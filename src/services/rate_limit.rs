use crate::config::RateLimitSettings;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct RateLimiter {
    settings: RateLimitSettings,
    ip_attempts: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    username_attempts: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
}

#[derive(Debug, Clone)]
pub enum RateLimitType {
    Ip(String),
    Username(String),
}

impl RateLimiter {
    pub fn new(settings: RateLimitSettings) -> Self {
        Self {
            settings,
            ip_attempts: Arc::new(RwLock::new(HashMap::new())),
            username_attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn check(&self, limit_type: &RateLimitType) -> Result<(), &'static str> {
        if !self.settings.enabled {
            return Ok(());
        }

        let now = Instant::now();
        let window = Duration::from_secs(self.settings.window_seconds);

        match limit_type {
            RateLimitType::Ip(ip) => {
                let mut map = self.ip_attempts.write().await;
                let (count, last_reset) = map.entry(ip.clone()).or_insert((0, now));

                if now.duration_since(*last_reset) > window {
                    *count = 1;
                    *last_reset = now;
                    Ok(())
                } else if *count >= self.settings.max_attempts_per_ip {
                    Err("Too many requests from this IP")
                } else {
                    *count += 1;
                    Ok(())
                }
            }
            RateLimitType::Username(username) => {
                let mut map = self.username_attempts.write().await;
                let (count, last_reset) = map.entry(username.clone()).or_insert((0, now));

                if now.duration_since(*last_reset) > window {
                    *count = 1;
                    *last_reset = now;
                    Ok(())
                } else if *count >= self.settings.max_attempts_per_username {
                    Err("Too many requests for this username")
                } else {
                    *count += 1;
                    Ok(())
                }
            }
        }
    }
}
