use crate::transport::grpc::{ClientSender, PendingScopeMap};
use sea_orm::DatabaseConnection;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AppStateInner {
    pub db: DatabaseConnection,
    pub settings: Arc<crate::config::Settings>,
    pub rsa_key: rsa::RsaPrivateKey,
    pub templates_dir: String,
    pub grpc_clients: Arc<RwLock<HashMap<String, ClientSender>>>,
    pub pending_scope_requests: PendingScopeMap,
    pub rate_limiter: crate::services::rate_limit::RateLimiter,
}

pub type AppState = Arc<AppStateInner>;
