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
use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use super::streaming::{connect_server, ClientSender, PendingScopeMap};

pub struct XAuthCoreService {
    db: DatabaseConnection,
    settings: Arc<crate::config::Settings>,
    rsa_key: Arc<rsa::RsaPrivateKey>,
    pub clients: Arc<RwLock<HashMap<String, ClientSender>>>,
    pub pending_scope_requests: PendingScopeMap,
    pub rate_limiter: crate::services::rate_limit::RateLimiter,
}

impl XAuthCoreService {
    pub fn new(
        db: DatabaseConnection,
        settings: Arc<crate::config::Settings>,
        rsa_key: Arc<rsa::RsaPrivateKey>,
    ) -> Self {
        let rate_limiter =
            crate::services::rate_limit::RateLimiter::new(settings.rate_limit.clone());
        Self {
            db,
            settings,
            rsa_key,
            clients: Arc::new(RwLock::new(HashMap::new())),
            pending_scope_requests: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter,
        }
    }

    fn oauth_service(&self) -> crate::services::oauth::OAuthService {
        crate::services::oauth::OAuthService::new(
            UserRepository::new(self.db.clone()),
            self.settings.clone(),
            self.rsa_key.clone(),
        )
    }
}

#[tonic::async_trait]
impl AuthService for XAuthCoreService {
    type ConnectServerStream = ReceiverStream<Result<CoreCommand, Status>>;

    async fn connect_server(
        &self,
        request: Request<Streaming<PluginEvent>>,
    ) -> Result<Response<Self::ConnectServerStream>, Status> {
        connect_server(
            self.clients.clone(),
            self.pending_scope_requests.clone(),
            request,
        )
        .await
    }

    async fn process_auth_step(
        &self,
        request: Request<AuthStepRequest>,
    ) -> Result<Response<AuthStepResponse>, Status> {
        let req = request.into_inner();

        let ip = req.ip_address.clone();
        if let Err(e) = self
            .rate_limiter
            .check(&crate::services::rate_limit::RateLimitType::Ip(ip))
            .await
        {
            return Err(Status::resource_exhausted(e));
        }

        if let Err(e) = self
            .rate_limiter
            .check(&crate::services::rate_limit::RateLimitType::Username(
                req.username.clone(),
            ))
            .await
        {
            return Err(Status::resource_exhausted(e));
        }

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
                action_payload: result.action_payload,
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
                action_payload: String::new(),
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
        let oauth = self.oauth_service();

        let token_req = crate::services::oauth::TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: req.client_id.clone(),
            client_secret: req.client_secret.clone(),
            code: Some(req.code.clone()),
            redirect_uri: Some(req.redirect_uri.clone()),
            code_verifier: None,
            refresh_token: None,
        };

        if !oauth
            .validate_client(&req.client_id, &req.client_secret)
            .await
        {
            return Ok(Response::new(OAuthTokenResponse {
                success: false,
                access_token: "".into(),
                refresh_token: "".into(),
                expires_in: 0,
                error: "invalid_client".into(),
            }));
        }

        match oauth.exchange_authorization_code(&token_req).await {
            Ok(issued) => Ok(Response::new(OAuthTokenResponse {
                success: true,
                access_token: issued.access_token,
                refresh_token: issued.refresh_token,
                expires_in: issued.expires_in as i32,
                error: "".into(),
            })),
            Err(e) => Ok(Response::new(OAuthTokenResponse {
                success: false,
                access_token: "".into(),
                refresh_token: "".into(),
                expires_in: 0,
                error: e.code().into(),
            })),
        }
    }

    async fn revoke_o_auth_token(
        &self,
        request: Request<OAuthRevokeRequest>,
    ) -> Result<Response<OAuthRevokeResponse>, Status> {
        let req = request.into_inner();
        self.oauth_service().revoke(&req.token).await;
        Ok(Response::new(OAuthRevokeResponse { success: true }))
    }

    async fn get_player_info(
        &self,
        request: Request<PlayerInfoRequest>,
    ) -> Result<Response<PlayerInfoResponse>, Status> {
        let req = request.into_inner();
        let svc =
            crate::services::user_info::UserInfoService::new(UserRepository::new(self.db.clone()));

        match svc.get_player_info(&req.target_username).await {
            Ok(info) => Ok(Response::new(PlayerInfoResponse {
                exists: info.exists,
                username: info.username,
                is_banned: info.is_banned,
                has_2fa: info.has_2fa,
                last_ip: info.last_ip,
                last_login: info.last_login,
                failed_attempts: info.failed_attempts,
            })),
            Err(e) => Err(Status::internal(e)),
        }
    }

    async fn force_password_change(
        &self,
        request: Request<ForcePasswordChangeRequest>,
    ) -> Result<Response<ForcePasswordChangeResponse>, Status> {
        let req = request.into_inner();
        let svc =
            crate::services::user_info::UserInfoService::new(UserRepository::new(self.db.clone()));

        match svc.force_password_change(&req.target_username).await {
            Ok(true) => {
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
            Ok(false) => Ok(Response::new(ForcePasswordChangeResponse {
                success: false,
            })),
            Err(e) => Err(Status::internal(e)),
        }
    }
}
