use crate::config::Settings;
use crate::db::UserRepository;
use std::sync::Arc;

pub enum StepOutcome {
    Ok,
    Skip,
    Fail(String),
}

pub struct AuthStepInput {
    pub username: String,
    pub step_type: String,
    pub input_data: String,
    pub flow_token: String,
    pub ip_address: String,
}

pub struct AuthStepResult {
    pub success: bool,
    pub message: String,
    pub next_action: String,
    pub session_token: String,
    pub flow_token: String,
    pub action_payload: String,
}

pub struct AuthFlowService {
    repo: UserRepository,
    settings: Arc<Settings>,
}

impl AuthFlowService {
    pub fn new(repo: UserRepository, settings: Arc<Settings>) -> Self {
        Self { repo, settings }
    }

    pub fn repo(&self) -> &UserRepository {
        &self.repo
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub async fn process_step(&self, req: AuthStepInput) -> Result<AuthStepResult, AuthFlowError> {
        let mut step_index = 0;
        let chain_name;

        if req.step_type == "init" {
            let user_exists = self
                .repo
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
                return Err(AuthFlowError::Unauthenticated("Missing flow_token".into()));
            }
            let claims = crate::services::jwt::validate_flow_token(
                &req.flow_token,
                &self.settings.jwt.secret,
            )
            .map_err(|_| AuthFlowError::Unauthenticated("Invalid or expired flow_token".into()))?;
            if claims.sub != req.username {
                return Err(AuthFlowError::Unauthenticated(
                    "Token username mismatch".into(),
                ));
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
            return Err(AuthFlowError::Internal("Auth flow exceeded".into()));
        }

        let current_step = &chain[step_index];

        if req.step_type == "init" && current_step.as_str() != "totp" {
            let new_flow_token = crate::services::jwt::generate_flow_token(
                &req.username,
                &chain_name,
                step_index,
                &self.settings.jwt.secret,
                600,
            )
            .map_err(|_| AuthFlowError::Internal("Token failed".into()))?;
            return Ok(AuthStepResult {
                success: true,
                message: String::new(),
                next_action: format!("require_{}", current_step),
                session_token: String::new(),
                flow_token: new_flow_token,
                action_payload: String::new(),
            });
        }

        let result = match current_step.as_str() {
            "password" => self.handle_password(&req, step_index).await,
            "register" => self.handle_register(&req).await,
            "totp" => self.handle_totp(&req, &chain_name, step_index).await,
            _ => {
                if req.step_type == format!("{}_complete", current_step) {
                    Ok(StepOutcome::Ok)
                } else {
                    Err(AuthFlowError::Fail(format!(
                        "Expected {}_complete",
                        current_step
                    )))
                }
            }
        }?;

        let (success, step_completed) = match &result {
            StepOutcome::Skip | StepOutcome::Ok => (true, true),
            StepOutcome::Fail(_) => (false, false),
        };

        if step_completed {
            step_index += 1;
        }

        while step_index < chain.len() {
            let eval_step = &chain[step_index];
            if eval_step == "totp" {
                let user = self
                    .repo
                    .get_user_by_name(&req.username)
                    .await
                    .unwrap_or(None);
                let has_2fa = if let Some(u) = &user {
                    self.repo.is_2fa_enabled(u.id).await.unwrap_or(false)
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
            let user = self
                .repo
                .get_user_by_name(&req.username)
                .await
                .unwrap_or(None);
            if let Some(u) = user {
                let token = crate::services::jwt::generate_jwt(
                    &u.username,
                    &self.settings.jwt.secret,
                    self.settings.jwt.session_ttl,
                )
                .map_err(|_| AuthFlowError::Internal("Failed to generate session token".into()))?;
                self.repo
                    .create_session(
                        u.id,
                        &token,
                        &req.ip_address,
                        self.settings.jwt.session_ttl as i64,
                    )
                    .await
                    .ok();
                self.repo
                    .update_last_login(u.id, &req.ip_address)
                    .await
                    .ok();

                return Ok(AuthStepResult {
                    success: true,
                    message: "Successfully authenticated!".into(),
                    next_action: "authenticated".into(),
                    session_token: token,
                    flow_token: String::new(),
                    action_payload: String::new(),
                });
            } else {
                return Err(AuthFlowError::Internal(
                    "User not found at end of flow".into(),
                ));
            }
        }

        let message = match result {
            StepOutcome::Fail(msg) => msg,
            _ => String::new(),
        };

        let next_step = &chain[step_index];
        let new_flow_token = crate::services::jwt::generate_flow_token(
            &req.username,
            &chain_name,
            step_index,
            &self.settings.jwt.secret,
            600,
        )
        .map_err(|_| AuthFlowError::Internal("Failed to generate flow token".into()))?;

        Ok(AuthStepResult {
            success,
            message,
            next_action: format!("require_{}", next_step),
            session_token: String::new(),
            flow_token: new_flow_token,
            action_payload: String::new(),
        })
    }

    async fn handle_password(
        &self,
        req: &AuthStepInput,
        _step_index: usize,
    ) -> Result<StepOutcome, AuthFlowError> {
        let mut user = self
            .repo
            .get_user_by_name(&req.username)
            .await
            .map_err(|_| AuthFlowError::Unauthenticated("User not found".into()))?
            .ok_or_else(|| AuthFlowError::Unauthenticated("User not found".into()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        if let Some(last_failed) = user.last_failed_attempt {
            if now - last_failed > self.settings.security.failed_attempts_reset_interval {
                self.repo.reset_failed_attempts(user.id).await.ok();
                user.failed_attempts = 0;
            }
        }

        if user.failed_attempts >= self.settings.security.max_failed_attempts {
            return Err(AuthFlowError::PermissionDenied(
                "Too many failed attempts. Account locked.".into(),
            ));
        }

        if crate::services::hash::verify_password(&req.input_data, &user.password_hash) {
            self.repo.reset_failed_attempts(user.id).await.ok();
            Ok(StepOutcome::Ok)
        } else {
            self.repo.increment_failed_attempts(user.id).await.ok();
            Ok(StepOutcome::Fail("Invalid password!".into()))
        }
    }

    async fn handle_register(&self, req: &AuthStepInput) -> Result<StepOutcome, AuthFlowError> {
        let hash =
            crate::services::hash::hash_password(&req.input_data, &self.settings.password_hashing)
                .map_err(|_| AuthFlowError::Internal("Hash failed".into()))?;
        if self.repo.create_user(&req.username, &hash).await.is_ok() {
            Ok(StepOutcome::Ok)
        } else {
            Ok(StepOutcome::Fail("User already exists!".into()))
        }
    }

    async fn handle_totp(
        &self,
        req: &AuthStepInput,
        chain_name: &str,
        step_index: usize,
    ) -> Result<StepOutcome, AuthFlowError> {
        let user = self
            .repo
            .get_user_by_name(&req.username)
            .await
            .unwrap_or(None);
        let has_2fa = if let Some(u) = &user {
            self.repo.is_2fa_enabled(u.id).await.unwrap_or(false)
        } else {
            false
        };

        if !has_2fa && !self.settings.totp.required {
            return Ok(StepOutcome::Skip);
        }

        if req.step_type == "init" {
            let u = user
                .as_ref()
                .ok_or_else(|| AuthFlowError::Internal("User not found".into()))?;
            let secret = totp_rs::Secret::generate_secret();
            let totp = totp_rs::TOTP::new(
                totp_rs::Algorithm::SHA1,
                6,
                1,
                30,
                secret
                    .to_bytes()
                    .map_err(|_| AuthFlowError::Internal("Secret error".into()))?,
            )
            .map_err(|_| AuthFlowError::Internal("TOTP generation failed".into()))?;
            let otpauth_uri = format!(
                "otpauth://totp/{}:{}?secret={}&issuer={}",
                "xauthd",
                req.username,
                totp.get_secret_base32(),
                "xauthd"
            );
            let new_flow_token = crate::services::jwt::generate_flow_token(
                &req.username,
                chain_name,
                step_index,
                &self.settings.jwt.secret,
                600,
            )
            .map_err(|_| AuthFlowError::Internal("Token failed".into()))?;
            self.repo
                .set_totp_secret(u.id, &totp.get_secret_base32())
                .await
                .map_err(|_| AuthFlowError::Internal("Failed to save TOTP secret".into()))?;
            return Err(AuthFlowError::TotpInit {
                otpauth_uri,
                flow_token: new_flow_token,
            });
        }

        if req.step_type == "totp" {
            let user = user
                .as_ref()
                .ok_or_else(|| AuthFlowError::Internal("User not found".into()))?;
            let secret_b32 = user
                .totp_secret
                .as_ref()
                .ok_or_else(|| AuthFlowError::Internal("2FA not configured".into()))?;
            let secret = totp_rs::Secret::try_from_base32(secret_b32.clone())
                .map_err(|_| AuthFlowError::Internal("Invalid TOTP secret".into()))?;
            let totp = totp_rs::TOTP::new(
                totp_rs::Algorithm::SHA1,
                6,
                1,
                30,
                secret
                    .to_bytes()
                    .map_err(|_| AuthFlowError::Internal("Invalid TOTP secret".into()))?,
            )
            .map_err(|_| AuthFlowError::Internal("TOTP init failed".into()))?;
            if totp.check_current(&req.input_data).is_some() {
                Ok(StepOutcome::Ok)
            } else {
                Ok(StepOutcome::Fail("Invalid TOTP code".into()))
            }
        } else {
            Ok(StepOutcome::Fail("Expected totp step".into()))
        }
    }
}

#[derive(Debug)]
pub enum AuthFlowError {
    Unauthenticated(String),
    PermissionDenied(String),
    Internal(String),
    Fail(String),
    TotpInit {
        otpauth_uri: String,
        flow_token: String,
    },
}
