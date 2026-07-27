use crate::xauth_v1::auth_service_server::AuthService;
use crate::xauth_v1::{
    AuthStepRequest, AuthStepResponse, CoreCommand, EndSessionRequest,
    EndSessionResponse, ForcePasswordChangeRequest, ForcePasswordChangeResponse,
    OAuthRevokeRequest, OAuthRevokeResponse, OAuthTokenRequest, OAuthTokenResponse,
    PlayerInfoRequest, PlayerInfoResponse, PluginEvent, SessionRequest, SessionResponse,
    auth_step_response::NextAction, core_command::CommandType,
};
use crate::db::UserRepository;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use sea_orm::DatabaseConnection;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::info;

type ClientSender = mpsc::Sender<Result<CoreCommand, Status>>;

pub struct XAuthCoreService {
    db: DatabaseConnection,
    clients: Arc<RwLock<HashMap<String, ClientSender>>>,
}

impl XAuthCoreService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            clients: Arc::new(RwLock::new(HashMap::new())),
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

        tokio::spawn(async move {
            let mut registered_server_id = None;
            while let Ok(Some(event)) = in_stream.message().await {
                if registered_server_id.is_none() {
                    registered_server_id = Some(event.server_id.clone());
                    clients.write().await.insert(event.server_id.clone(), tx.clone());
                    info!("Registered streaming channel for server: {}", event.server_id);
                }
                info!("Event from {}: {:?}", event.server_id, event.r#type);
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
        let repo = UserRepository::new(self.db.clone());

        match req.r#type {
            0 => {
                let user = match repo.get_user_by_name(&req.username).await {
                    Ok(Some(u)) => u,
                    Ok(None) => {
                        return Ok(Response::new(AuthStepResponse {
                            success: false,
                            message: "User not found.".into(),
                            next_action: NextAction::RequireRegister as i32,
                            session_token: "".into(),
                        }));
                    },
                    Err(_) => return Err(Status::internal("Database error")),
                };

                let hash_to_verify = &user.password_hash;

                if crate::hash::verify_password(&req.input_data, hash_to_verify) {
                    let has_2fa = repo.is_2fa_enabled(user.id).await.unwrap_or(false);
                    
                    if has_2fa {
                        Ok(Response::new(AuthStepResponse {
                            success: true,
                            message: "Enter 2FA code from Telegram (/confirm <code>).".into(),
                            next_action: NextAction::Require2fa as i32,
                            session_token: "".into(),
                        }))
                    } else {
                        let token = crate::jwt::generate_jwt(&user.username, "super_secret_key_change_me", 3600 * 24).unwrap_or_else(|_| "".into());
                        repo.create_session(user.id, &token, &req.ip_address, 3600 * 24).await.ok();
                        repo.update_last_login(user.id, &req.ip_address).await.ok();
                        
                        Ok(Response::new(AuthStepResponse {
                            success: true,
                            message: "Successfully authenticated!".into(),
                            next_action: NextAction::Authenticated as i32,
                            session_token: token,
                        }))
                    }
                } else {
                    repo.increment_failed_attempts(user.id).await.ok();
                    Ok(Response::new(AuthStepResponse {
                        success: false,
                        message: "Invalid password!".into(),
                        next_action: NextAction::RequirePassword as i32,
                        session_token: "".into(),
                    }))
                }
            },
            1 => {
                let hash = crate::hash::hash_password(&req.input_data)
                    .map_err(|_| Status::internal("Hash failed"))?;
                
                repo.create_user(&req.username, &hash).await
                    .map_err(|_| Status::already_exists("User exists"))?;

                let token = crate::jwt::generate_jwt(&req.username, "super_secret_key_change_me", 3600 * 24).unwrap_or_else(|_| "".into());
                if let Ok(Some(u)) = repo.get_user_by_name(&req.username).await {
                    repo.create_session(u.id, &token, &req.ip_address, 3600 * 24).await.ok();
                }

                Ok(Response::new(AuthStepResponse {
                    success: true,
                    message: "Registration successful! You are authenticated.".into(),
                    next_action: NextAction::Authenticated as i32,
                    session_token: token,
                }))
            },
            _ => Err(Status::unimplemented("This step is not supported yet")),
        }
    }

    async fn validate_session(&self, request: Request<SessionRequest>) -> Result<Response<SessionResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());
        
        let mut is_valid = false;
        let mut username = String::new();
        let mut expires_at = 0;

        if let Ok(Some(session)) = repo.get_session(&req.session_token).await {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            if session.expires_at > now {
                if let Ok(claims) = crate::jwt::validate_jwt(&req.session_token, "super_secret_key_change_me") {
                    is_valid = true;
                    username = claims.sub;
                    expires_at = session.expires_at;
                }
            }
        }
        
        Ok(Response::new(SessionResponse {
            is_valid,
            username,
            expires_at,
        }))
    }
    
    async fn end_session(&self, request: Request<EndSessionRequest>) -> Result<Response<EndSessionResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());
        
        repo.delete_session(&req.session_token).await.ok();
        
        Ok(Response::new(EndSessionResponse {
            success: true,
        }))
    }

    async fn generate_o_auth_token(&self, request: Request<OAuthTokenRequest>) -> Result<Response<OAuthTokenResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());
        
        let is_valid = repo.validate_oauth_client(&req.client_id, &req.client_secret).await.unwrap_or(false);
        
        if is_valid {
            let access_token = crate::jwt::generate_jwt("oauth_user", "super_secret_key_change_me", 3600).unwrap_or_else(|_| "".into());
            let refresh_token = crate::jwt::generate_jwt("oauth_user", "super_secret_key_change_me", 3600 * 24 * 7).unwrap_or_else(|_| "".into());

            Ok(Response::new(OAuthTokenResponse {
                success: true,
                access_token,
                refresh_token,
                expires_in: 3600,
                error: "".into(),
            }))
        } else {
            Ok(Response::new(OAuthTokenResponse {
                success: false,
                access_token: "".into(),
                refresh_token: "".into(),
                expires_in: 0,
                error: "invalid_client".into(),
            }))
        }
    }

    async fn revoke_o_auth_token(&self, request: Request<OAuthRevokeRequest>) -> Result<Response<OAuthRevokeResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());
        
        if let Ok(claims) = crate::jwt::validate_jwt(&req.token, "super_secret_key_change_me") {
            repo.blacklist_token(&claims.jti, claims.exp as i64).await.ok();
        }
        
        Ok(Response::new(OAuthRevokeResponse {
            success: true,
        }))
    }

    async fn get_player_info(&self, request: Request<PlayerInfoRequest>) -> Result<Response<PlayerInfoResponse>, Status> {
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
            Ok(None) => {
                Ok(Response::new(PlayerInfoResponse {
                    exists: false,
                    username: req.target_username,
                    is_banned: false,
                    has_2fa: false,
                    last_ip: "".into(),
                    last_login: 0,
                    failed_attempts: 0,
                }))
            }
            Err(_) => Err(Status::internal("Database error")),
        }
    }

    async fn force_password_change(&self, request: Request<ForcePasswordChangeRequest>) -> Result<Response<ForcePasswordChangeResponse>, Status> {
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
                Ok(Response::new(ForcePasswordChangeResponse {
                    success: true,
                }))
            }
            Ok(None) => {
                Ok(Response::new(ForcePasswordChangeResponse {
                    success: false,
                }))
            }
            Err(_) => Err(Status::internal("Database error")),
        }
    }
}
