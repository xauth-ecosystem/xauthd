use crate::db::UserRepository;

pub struct UserInfoService {
    repo: UserRepository,
}

pub struct PlayerInfo {
    pub exists: bool,
    pub username: String,
    pub is_banned: bool,
    pub has_2fa: bool,
    pub last_ip: String,
    pub last_login: i64,
    pub failed_attempts: i32,
}

impl UserInfoService {
    pub fn new(repo: UserRepository) -> Self {
        Self { repo }
    }

    pub async fn get_player_info(&self, target_username: &str) -> Result<PlayerInfo, String> {
        match self.repo.get_user_by_name(target_username).await {
            Ok(Some(user)) => {
                let has_2fa = self.repo.is_2fa_enabled(user.id).await.unwrap_or(false);
                Ok(PlayerInfo {
                    exists: true,
                    username: user.username.clone(),
                    is_banned: user.is_banned,
                    has_2fa,
                    last_ip: user.last_ip.unwrap_or_default(),
                    last_login: user.last_login.unwrap_or(0),
                    failed_attempts: user.failed_attempts,
                })
            }
            Ok(None) => Ok(PlayerInfo {
                exists: false,
                username: target_username.to_owned(),
                is_banned: false,
                has_2fa: false,
                last_ip: String::new(),
                last_login: 0,
                failed_attempts: 0,
            }),
            Err(_) => Err("Database error".into()),
        }
    }

    pub async fn force_password_change(&self, target_username: &str) -> Result<bool, String> {
        match self.repo.get_user_by_name(target_username).await {
            Ok(Some(user)) => {
                self.repo.set_must_change_password(user.id, true).await.ok();
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(_) => Err("Database error".into()),
        }
    }
}
