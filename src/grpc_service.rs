use crate::db::UserRepository;
use crate::xauth_v1::auth_service_server::AuthService;
use crate::xauth_v1::{
    core_command::CommandType, AuthStepRequest, AuthStepResponse, CoreCommand, EndSessionRequest,
    EndSessionResponse, ForcePasswordChangeRequest, ForcePasswordChangeResponse,
    OAuthRevokeRequest, OAuthRevokeResponse, OAuthTokenRequest, OAuthTokenResponse,
    PlayerInfoRequest, PlayerInfoResponse, PluginEvent, SessionRequest, SessionResponse,
};
use sea_orm::DatabaseConnection;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::info;

pub type ClientSender = mpsc::Sender<Result<CoreCommand, Status>>;
pub type PendingScopeMap = Arc<RwLock<HashMap<String, oneshot::Sender<String>>>>;

enum StepResult {
    Skip,
    Ok,
    Fail(String),
}

pub struct XAuthCoreService {
    db: DatabaseConnection,
    settings: Arc<crate::config::Settings>,
    pub clients: Arc<RwLock<HashMap<String, ClientSender>>>,
    pub pending_scope_requests: PendingScopeMap,
}

impl XAuthCoreService {
    pub fn new(db: DatabaseConnection, settings: Arc<crate::config::Settings>) -> Self {
        Self {
            db,
            settings,
            clients: Arc::new(RwLock::new(HashMap::new())),
            pending_scope_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[tonic::async_trait]
impl AuthService for XAuthCoreService {
    type ConnectServerStream = ReceiverStream<Result<CoreCommand, Status>>;

    async fn connect_server(
        &self,
        request: Request<Streaming<PluginEvent>>,
    ) -> Result<Response<Self::ConnectServerStream>, Status> {
        let mut in_stream = request.into_inner();
        let (tx, rx) = mpsc::channel(100);

        let clients = self.clients.clone();
        let pending_requests = self.pending_scope_requests.clone();

        tokio::spawn(async move {
            let mut registered_server_id = None;
            while let Ok(Some(event)) = in_stream.message().await {
                if registered_server_id.is_none() {
                    registered_server_id = Some(event.server_id.clone());
                    clients
                        .write()
                        .await
                        .insert(event.server_id.clone(), tx.clone());
                    info!(
                        "Registered streaming channel for server: {}",
                        event.server_id
                    );
                }

                info!("Event from {}: {:?}", event.server_id, event.r#type);

                if event.r#type == 5 {
                    if let Ok(parsed_payload) =
                        serde_json::from_str::<serde_json::Value>(&event.payload)
                    {
                        if let Some(req_id) = parsed_payload["request_id"].as_str() {
                            if let Some(sender) = pending_requests.write().await.remove(req_id) {
                                let _ = sender.send(event.payload.clone());
                            }
                        }
                    }
                }
            }

            if let Some(id) = registered_server_id {
                clients.write().await.remove(&id);
                info!("Unregistered streaming channel for server: {}", id);
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn process_auth_step(
        &self,
        request: Request<AuthStepRequest>,
    ) -> Result<Response<AuthStepResponse>, Status> {
        let req = request.into_inner();
        let auth_flow = crate::services::auth_flow::AuthFlowService::new(
            UserRepository::new(self.db.clone()),
            self.settings.clone(),
        );

        let input = crate::services::auth_flow::AuthStepInput {
            username: req.username.clone(),
            step_type: req.step_type.clone(),
            input_data: req.input_data.clone(),
            flow_token: req.flow_token.clone(),
            ip_address: req.ip_address.clone(),
        };

        match auth_flow.process_step(input).await {
            Ok(result) => Ok(Response::new(AuthStepResponse {
                success: result.success,
                message: result.message,
                next_action: result.next_action,
                session_token: result.session_token,
                flow_token: result.flow_token,
            })),
            Err(crate::services::auth_flow::AuthFlowError::Unauthenticated(msg)) => {
                Err(Status::unauthenticated(msg))
            }
            Err(crate::services::auth_flow::AuthFlowError::PermissionDenied(msg)) => {
                Err(Status::permission_denied(msg))
            }
            Err(crate::services::auth_flow::AuthFlowError::Internal(msg)) => {
                Err(Status::internal(msg))
            }
            Err(crate::services::auth_flow::AuthFlowError::Fail(msg)) => {
                Err(Status::failed_precondition(msg))
            }
            Err(crate::services::auth_flow::AuthFlowError::TotpInit {
                otpauth_uri,
                flow_token,
            }) => Ok(Response::new(AuthStepResponse {
                success: true,
                message: otpauth_uri,
                next_action: "require_totp".into(),
                session_token: String::new(),
                flow_token,
            })),
        }
    }

    async fn validate_session(
        &self,
        request: Request<SessionRequest>,
    ) -> Result<Response<SessionResponse>, Status> {
        let req = request.into_inner();
        let sessions = crate::services::session::SessionService::new(
            UserRepository::new(self.db.clone()),
            self.settings.clone(),
        );

        let result = sessions.validate(&req.session_token).await;
        Ok(Response::new(SessionResponse {
            is_valid: result.is_valid,
            username: result.username,
            expires_at: result.expires_at,
        }))
    }

    async fn end_session(
        &self,
        request: Request<EndSessionRequest>,
    ) -> Result<Response<EndSessionResponse>, Status> {
        let req = request.into_inner();
        let sessions = crate::services::session::SessionService::new(
            UserRepository::new(self.db.clone()),
            self.settings.clone(),
        );

        sessions.end(&req.session_token).await;
        Ok(Response::new(EndSessionResponse { success: true }))
    }

    async fn generate_o_auth_token(
        &self,
        request: Request<OAuthTokenRequest>,
    ) -> Result<Response<OAuthTokenResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());

        if !repo
            .validate_oauth_client(&req.client_id, &req.client_secret)
            .await
            .unwrap_or(false)
        {
            return Ok(Response::new(OAuthTokenResponse {
                success: false,
                access_token: "".into(),
                refresh_token: "".into(),
                expires_in: 0,
                error: "invalid_client".into(),
            }));
        }

        if let Ok(claims) = crate::jwt::validate_jwt(&req.code, &self.settings.jwt.secret) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&claims.sub) {
                let u = data["u"].as_str().unwrap_or_default();
                let c = data["c"].as_str().unwrap_or_default();
                let r = data["r"].as_str().unwrap_or_default();

                if c == req.client_id && r == req.redirect_uri {
                    if let Ok(Some(user)) = repo.get_user_by_name(u).await {
                        let access_token = crate::jwt::generate_jwt(
                            u,
                            &self.settings.jwt.secret,
                            self.settings.jwt.access_token_ttl,
                        )
                        .unwrap_or_default();
                        let refresh_token = crate::jwt::generate_jwt(
                            u,
                            &self.settings.jwt.secret,
                            self.settings.jwt.refresh_token_ttl,
                        )
                        .unwrap_or_default();
                        let scopes = "openid profile";

                        repo.create_oauth_token(
                            &req.client_id,
                            user.id,
                            &access_token,
                            Some(&refresh_token),
                            self.settings.jwt.access_token_ttl as i64,
                            scopes,
                        )
                        .await
                        .ok();

                        return Ok(Response::new(OAuthTokenResponse {
                            success: true,
                            access_token,
                            refresh_token,
                            expires_in: self.settings.jwt.access_token_ttl as i32,
                            error: "".into(),
                        }));
                    }
                }
            }
        }

        Ok(Response::new(OAuthTokenResponse {
            success: false,
            access_token: "".into(),
            refresh_token: "".into(),
            expires_in: 0,
            error: "invalid_grant".into(),
        }))
    }

    async fn revoke_o_auth_token(
        &self,
        request: Request<OAuthRevokeRequest>,
    ) -> Result<Response<OAuthRevokeResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());

        repo.delete_oauth_token(&req.token).await.ok();

        if let Ok(claims) = crate::jwt::validate_jwt(&req.token, &self.settings.jwt.secret) {
            repo.blacklist_token(&claims.jti, claims.exp as i64)
                .await
                .ok();
        }

        Ok(Response::new(OAuthRevokeResponse { success: true }))
    }

    async fn get_player_info(
        &self,
        request: Request<PlayerInfoRequest>,
    ) -> Result<Response<PlayerInfoResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());

        match repo.get_user_by_name(&req.target_username).await {
            Ok(Some(user)) => {
                let has_2fa = repo.is_2fa_enabled(user.id).await.unwrap_or(false);

                Ok(Response::new(PlayerInfoResponse {
                    exists: true,
                    username: user.username.clone(),
                    is_banned: user.is_banned,
                    has_2fa,
                    last_ip: user.last_ip.unwrap_or_default(),
                    last_login: user.last_login.unwrap_or(0),
                    failed_attempts: user.failed_attempts,
                }))
            }
            Ok(None) => Ok(Response::new(PlayerInfoResponse {
                exists: false,
                username: req.target_username,
                is_banned: false,
                has_2fa: false,
                last_ip: "".into(),
                last_login: 0,
                failed_attempts: 0,
            })),
            Err(_) => Err(Status::internal("Database error")),
        }
    }

    async fn force_password_change(
        &self,
        request: Request<ForcePasswordChangeRequest>,
    ) -> Result<Response<ForcePasswordChangeResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());

        match repo.get_user_by_name(&req.target_username).await {
            Ok(Some(user)) => {
                repo.set_must_change_password(user.id, true).await.ok();

                if req.immediate_kick {
                    let cmd = CoreCommand {
                        r#type: CommandType::KickPlayer as i32,
                        target_username: req.target_username.clone(),
                        payload: "You must change your password. Please re-login.".into(),
                    };

                    let clients_guard = self.clients.read().await;
                    for tx in clients_guard.values() {
                        let _ = tx.send(Ok(cmd.clone())).await;
                    }
                }
                Ok(Response::new(ForcePasswordChangeResponse { success: true }))
            }
            Ok(None) => Ok(Response::new(ForcePasswordChangeResponse {
                success: false,
            })),
            Err(_) => Err(Status::internal("Database error")),
        }
    }
}
