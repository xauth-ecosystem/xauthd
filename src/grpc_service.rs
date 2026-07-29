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
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::info;

type ClientSender = mpsc::Sender<Result<CoreCommand, Status>>;

enum StepResult {
    Skip,
    Ok,
    Fail(String),
}

pub struct XAuthCoreService {
    db: DatabaseConnection,
    settings: Arc<crate::config::Settings>,
    clients: Arc<RwLock<HashMap<String, ClientSender>>>,
}

impl XAuthCoreService {
    pub fn new(db: DatabaseConnection, settings: Arc<crate::config::Settings>) -> Self {
        Self {
            db,
            settings,
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

        let mut step_index = 0;
        let chain_name;

        if req.step_type == "init" {
            let user_exists = repo
                .get_user_by_name(&req.username)
                .await
                .unwrap_or(None)
                .is_some();
            chain_name = if user_exists {
                "login".to_string()
            } else {
                "register".to_string()
            };
        } else {
            if req.flow_token.is_empty() {
                return Err(Status::unauthenticated("Missing flow_token"));
            }
            let claims =
                match crate::jwt::validate_flow_token(&req.flow_token, &self.settings.jwt.secret) {
                    Ok(c) => c,
                    Err(_) => return Err(Status::unauthenticated("Invalid or expired flow_token")),
                };
            if claims.sub != req.username {
                return Err(Status::unauthenticated("Token username mismatch"));
            }
            step_index = claims.step_index;
            chain_name = claims.chain;
        }

        let chain = if chain_name == "login" {
            &self.settings.auth_flow.login_chain
        } else {
            &self.settings.auth_flow.register_chain
        };

        if step_index >= chain.len() {
            return Err(Status::internal("Auth flow exceeded"));
        }

        let current_step = &chain[step_index];

        if req.step_type == "init" && current_step.as_str() != "totp" {
            let new_flow_token = crate::jwt::generate_flow_token(
                &req.username,
                &chain_name,
                step_index,
                &self.settings.jwt.secret,
                600,
            )
            .map_err(|_| Status::internal("Token failed"))?;
            return Ok(Response::new(AuthStepResponse {
                success: true,
                message: String::new(),
                next_action: format!("require_{}", current_step),
                session_token: "".into(),
                flow_token: new_flow_token,
            }));
        }

        let result = match current_step.as_str() {
            "password" => {
                let mut user = match repo.get_user_by_name(&req.username).await {
                    Ok(Some(u)) => u,
                    _ => return Err(Status::unauthenticated("User not found")),
                };

                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                if let Some(last_failed) = user.last_failed_attempt {
                    if now - last_failed > self.settings.security.failed_attempts_reset_interval {
                        repo.reset_failed_attempts(user.id).await.ok();
                        user.failed_attempts = 0;
                    }
                }

                if user.failed_attempts >= self.settings.security.max_failed_attempts {
                    return Err(Status::permission_denied(
                        "Too many failed attempts. Account locked.",
                    ));
                }

                if crate::hash::verify_password(&req.input_data, &user.password_hash) {
                    repo.reset_failed_attempts(user.id).await.ok();
                    StepResult::Ok
                } else {
                    repo.increment_failed_attempts(user.id).await.ok();
                    StepResult::Fail("Invalid password!".into())
                }
            }
            "register" => {
                let hash =
                    crate::hash::hash_password(&req.input_data, &self.settings.password_hashing)
                        .map_err(|_| Status::internal("Hash failed"))?;
                if repo.create_user(&req.username, &hash).await.is_ok() {
                    StepResult::Ok
                } else {
                    StepResult::Fail("User already exists!".into())
                }
            }
            "totp" => {
                let user = repo.get_user_by_name(&req.username).await.unwrap_or(None);
                let has_2fa = if let Some(u) = &user {
                    repo.is_2fa_enabled(u.id).await.unwrap_or(false)
                } else {
                    false
                };

                if !has_2fa && !self.settings.totp.required {
                    StepResult::Skip
                } else if req.step_type == "init" {
                    let u = user
                        .as_ref()
                        .ok_or_else(|| Status::internal("User not found"))?;
                    let secret = totp_rs::Secret::generate_secret();
                    let totp = totp_rs::TOTP::new(
                        totp_rs::Algorithm::SHA1,
                        6,
                        1,
                        30,
                        secret
                            .to_bytes()
                            .map_err(|_| Status::internal("Secret error"))?,
                    )
                    .map_err(|_| Status::internal("TOTP generation failed"))?;
                    let otpauth_uri = format!(
                        "otpauth://totp/{}:{}?secret={}&issuer={}",
                        "xauthd",
                        req.username,
                        totp.get_secret_base32(),
                        "xauthd"
                    );
                    let new_flow_token = crate::jwt::generate_flow_token(
                        &req.username,
                        &chain_name,
                        step_index,
                        &self.settings.jwt.secret,
                        600,
                    )
                    .map_err(|_| Status::internal("Token failed"))?;
                    repo.set_totp_secret(u.id, &totp.get_secret_base32())
                        .await
                        .map_err(|_| Status::internal("Failed to save TOTP secret"))?;
                    return Ok(Response::new(AuthStepResponse {
                        success: true,
                        message: otpauth_uri,
                        next_action: "require_totp".into(),
                        session_token: "".into(),
                        flow_token: new_flow_token,
                    }));
                } else if req.step_type == "totp" {
                    let user = user
                        .as_ref()
                        .ok_or_else(|| Status::internal("User not found"))?;
                    let secret_b32 = user
                        .totp_secret
                        .as_ref()
                        .ok_or_else(|| Status::internal("2FA not configured"))?;
                    let secret = totp_rs::Secret::Encoded(secret_b32.clone());
                    let totp = totp_rs::TOTP::new(
                        totp_rs::Algorithm::SHA1,
                        6,
                        1,
                        30,
                        secret
                            .to_bytes()
                            .map_err(|_| Status::internal("Invalid TOTP secret"))?,
                    )
                    .map_err(|_| Status::internal("TOTP init failed"))?;
                    if totp
                        .check_current(&req.input_data)
                        .map_err(|_| Status::internal("TOTP verification error"))?
                    {
                        StepResult::Ok
                    } else {
                        StepResult::Fail("Invalid TOTP code".into())
                    }
                } else {
                    StepResult::Fail("Expected totp step".into())
                }
            }
            custom_step => {
                let complete_signal = format!("{}_complete", custom_step);
                if req.step_type == complete_signal {
                    StepResult::Ok
                } else {
                    StepResult::Fail(format!("Expected {}", complete_signal))
                }
            }
        };

        let (success, step_completed) = match &result {
            StepResult::Skip | StepResult::Ok => (true, true),
            StepResult::Fail(_) => (false, false),
        };

        if step_completed {
            step_index += 1;
        }

        while step_index < chain.len() {
            let eval_step = &chain[step_index];
            if eval_step == "totp" {
                let user = repo.get_user_by_name(&req.username).await.unwrap_or(None);
                let has_2fa = if let Some(u) = &user {
                    repo.is_2fa_enabled(u.id).await.unwrap_or(false)
                } else {
                    false
                };
                if !has_2fa && !self.settings.totp.required {
                    step_index += 1;
                    continue;
                }
            }
            break;
        }

        if step_index >= chain.len() {
            let user = repo.get_user_by_name(&req.username).await.unwrap_or(None);
            if let Some(u) = user {
                let token = crate::jwt::generate_jwt(
                    &u.username,
                    &self.settings.jwt.secret,
                    self.settings.jwt.session_ttl,
                )
                .unwrap_or_default();
                repo.create_session(
                    u.id,
                    &token,
                    &req.ip_address,
                    self.settings.jwt.session_ttl as i64,
                )
                .await
                .ok();
                repo.update_last_login(u.id, &req.ip_address).await.ok();

                return Ok(Response::new(AuthStepResponse {
                    success: true,
                    message: "Successfully authenticated!".into(),
                    next_action: "authenticated".into(),
                    session_token: token,
                    flow_token: "".into(),
                }));
            } else {
                return Err(Status::internal("User not found at end of flow"));
            }
        }

        let message = match result {
            StepResult::Fail(msg) => msg,
            _ => String::new(),
        };

        let next_step = &chain[step_index];
        let new_flow_token = crate::jwt::generate_flow_token(
            &req.username,
            &chain_name,
            step_index,
            &self.settings.jwt.secret,
            600,
        )
        .unwrap_or_default();

        Ok(Response::new(AuthStepResponse {
            success,
            message,
            next_action: format!("require_{}", next_step),
            session_token: "".into(),
            flow_token: new_flow_token,
        }))
    }

    async fn validate_session(
        &self,
        request: Request<SessionRequest>,
    ) -> Result<Response<SessionResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());

        let mut is_valid = false;
        let mut username = String::new();
        let mut expires_at = 0;

        if let Ok(Some(session)) = repo.get_session(&req.session_token).await {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            if session.expires_at > now {
                if let Ok(claims) =
                    crate::jwt::validate_jwt(&req.session_token, &self.settings.jwt.secret)
                {
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

    async fn end_session(
        &self,
        request: Request<EndSessionRequest>,
    ) -> Result<Response<EndSessionResponse>, Status> {
        let req = request.into_inner();
        let repo = UserRepository::new(self.db.clone());

        repo.delete_session(&req.session_token).await.ok();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AuthFlowSettings, DatabaseSettings, JwtSettings, NetworkSettings, PasswordHashingSettings,
        SecuritySettings, Settings, TotpSettings, WebSettings,
    };
    use crate::db::Entity as UserEntity;
    use sea_orm::{ActiveModelTrait, ConnectionTrait, Database, Schema, Set};

    async fn setup_test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        let builder = db.get_database_backend();
        let schema = Schema::new(builder);

        let stmt = schema.create_table_from_entity(UserEntity);
        db.execute(&stmt).await.unwrap();

        db
    }

    fn get_test_settings() -> Arc<Settings> {
        Arc::new(Settings {
            database: DatabaseSettings { url: "".into() },
            network: NetworkSettings {
                grpc_address: "".into(),
                web_address: "".into(),
            },
            password_hashing: PasswordHashingSettings {
                algorithm: "BCRYPT".into(),
                options: None,
            },
            jwt: JwtSettings {
                secret: "secret".into(),
                rsa_private_key_path: "".into(),
                session_ttl: 3600,
                auth_code_ttl: 3600,
                access_token_ttl: 3600,
                refresh_token_ttl: 3600,
            },
            security: SecuritySettings {
                max_failed_attempts: 5,
                failed_attempts_reset_interval: 3600,
            },
            auth_flow: AuthFlowSettings {
                register_chain: vec!["password".into(), "totp".into()],
                login_chain: vec!["password".into(), "totp".into()],
                max_attempts_per_step: 3,
            },
            web: WebSettings {
                templates_dir: "./templates".into(),
                public_dir: None,
            },
            totp: TotpSettings { required: false },
        })
    }

    #[tokio::test]
    async fn test_process_auth_step_init_register() {
        let db = setup_test_db().await;
        let settings = get_test_settings();
        let service = XAuthCoreService::new(db, settings);

        let req = Request::new(AuthStepRequest {
            username: "new_player".into(),
            step_type: "init".into(),
            input_data: "".into(),
            ip_address: "127.0.0.1".into(),
            flow_token: "".into(),
            server_id: "test_server".into(),
        });

        let resp = service.process_auth_step(req).await.unwrap().into_inner();

        assert!(resp.success);
        assert_eq!(resp.next_action, "require_password");
        assert!(!resp.flow_token.is_empty());
        assert!(resp.session_token.is_empty());
    }

    #[tokio::test]
    async fn test_process_auth_step_init_login() {
        let db = setup_test_db().await;

        let new_user = crate::db::ActiveModel {
            username: Set("existing_player".into()),
            password_hash: Set("hash".into()),
            failed_attempts: Set(0),
            is_banned: Set(false),
            must_change_password: Set(false),
            ..Default::default()
        };
        new_user.insert(&db).await.unwrap();

        let settings = get_test_settings();
        let service = XAuthCoreService::new(db, settings);

        let req = Request::new(AuthStepRequest {
            username: "existing_player".into(),
            step_type: "init".into(),
            input_data: "".into(),
            ip_address: "127.0.0.1".into(),
            flow_token: "".into(),
            server_id: "test_server".into(),
        });

        let resp = service.process_auth_step(req).await.unwrap().into_inner();

        assert!(resp.success);
        assert_eq!(resp.next_action, "require_password");
        assert!(!resp.flow_token.is_empty());
    }

    #[tokio::test]
    async fn test_get_player_info_not_found() {
        let db = setup_test_db().await;
        let settings = get_test_settings();
        let service = XAuthCoreService::new(db, settings);

        let req = Request::new(PlayerInfoRequest {
            target_username: "unknown".into(),
            requestor_id: "admin".into(),
        });

        let resp = service.get_player_info(req).await.unwrap().into_inner();
        assert!(!resp.exists);
        assert_eq!(resp.username, "unknown");
    }

    #[tokio::test]
    async fn test_get_player_info_exists() {
        let db = setup_test_db().await;

        let new_user = crate::db::ActiveModel {
            username: Set("known_user".into()),
            password_hash: Set("hash".into()),
            failed_attempts: Set(0),
            is_banned: Set(true),
            must_change_password: Set(false),
            ..Default::default()
        };
        new_user.insert(&db).await.unwrap();

        let settings = get_test_settings();
        let service = XAuthCoreService::new(db, settings);

        let req = Request::new(PlayerInfoRequest {
            target_username: "known_user".into(),
            requestor_id: "admin".into(),
        });

        let resp = service.get_player_info(req).await.unwrap().into_inner();
        assert!(resp.exists);
        assert_eq!(resp.username, "known_user");
        assert!(resp.is_banned);
    }
}
