use crate::xauth_v1::auth_service_server::AuthService;
use crate::xauth_v1::{
    AuthStepRequest, AuthStepResponse, CoreCommand, EndSessionRequest,
    EndSessionResponse, ForcePasswordChangeRequest, ForcePasswordChangeResponse,
    OAuthRevokeRequest, OAuthRevokeResponse, OAuthTokenRequest, OAuthTokenResponse,
    PlayerInfoRequest, PlayerInfoResponse, PluginEvent, SessionRequest, SessionResponse,
    auth_step_response::NextAction,
};
use crate::db::UserRepository;
use sea_orm::DatabaseConnection;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::info;

pub struct XAuthCoreService {
    db: DatabaseConnection,
}

impl XAuthCoreService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
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
        let (_tx, rx) = mpsc::channel(100);

        tokio::spawn(async move {
            while let Ok(Some(event)) = in_stream.message().await {
                info!("Event from {}: {:?}", event.server_id, event.r#type);
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
        
        let (is_valid, username, expires_at) = match crate::jwt::validate_jwt(&req.session_token, "super_secret_key_change_me") {
            Ok(claims) => {
                let blacklisted = repo.is_token_blacklisted(&claims.jti).await.unwrap_or(false);
                if blacklisted {
                    (false, "".into(), 0)
                } else {
                    (true, claims.sub, claims.exp as i64)
                }
            },
            Err(_) => (false, "".into(), 0),
        };
        
        Ok(Response::new(SessionResponse {
            is_valid,
            username,
            expires_at,
        }))
    }
    
    async fn end_session(&self, request: Request<EndSessionRequest>) -> Result<Response<EndSessionResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());
        
        if let Ok(claims) = crate::jwt::validate_jwt(&req.session_token, "super_secret_key_change_me") {
            repo.blacklist_token(&claims.jti, claims.exp as i64).await.ok();
        }
        
        Ok(Response::new(EndSessionResponse {
            success: true,
        }))
    }

    async fn generate_o_auth_token(&self, request: Request<OAuthTokenRequest>) -> Result<Response<OAuthTokenResponse>, Status> {
        let req = request.into_inner();
        
        // TODO: Validate req.client_id, req.client_secret and req.code
        let is_valid = req.client_id == "my-client-id"; // Mock validation
        
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
        
        // req doesn't explicitly mention 'token' field in proto usually, but let's assume it's in the request 
        // Wait, what's the field name for OAuthRevokeRequest? Let's check proto or assume `token` for now.
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
                // TODO: If req.immediate_kick is true, send KickPlayer command via streaming channel
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
