use crate::db::UserRepository;
use crate::config::Settings;
use std::sync::Arc;

pub struct SessionService {
    repo: UserRepository,
    settings: Arc<Settings>,
}

pub struct SessionValidation {
    pub is_valid: bool,
    pub username: String,
    pub expires_at: i64,
}

impl SessionService {
    pub fn new(repo: UserRepository, settings: Arc<Settings>) -> Self {
        Self { repo, settings }
    }

    pub async fn validate(&self, token: &str) -> SessionValidation {
        let mut is_valid = false;
        let mut username = String::new();
        let mut expires_at = 0;

        if let Ok(Some(session)) = self.repo.get_session(token).await {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            if session.expires_at > now {
                if let Ok(claims) =
                    crate::services::jwt::validate_jwt(token, &self.settings.jwt.secret)
                {
                    is_valid = true;
                    username = claims.sub;
                    expires_at = session.expires_at;
                }
            }
        }

        SessionValidation {
            is_valid,
            username,
            expires_at,
        }
    }

    pub async fn end(&self, token: &str) {
        self.repo.delete_session(token).await.ok();
    }
}
