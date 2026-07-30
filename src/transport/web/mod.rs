pub mod dto;
pub mod handlers;
pub mod state;
pub mod templates;

use crate::transport::grpc::{ClientSender, PendingScopeMap};
use axum::{
    routing::{get, post},
    Router,
};
use sea_orm::DatabaseConnection;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use handlers::{
    authorize::authorize_get,
    consent::{consent_get, consent_post},
    discovery::{discovery_get, jwks_get},
    introspect::introspect_post,
    login::login_post,
    revoke::revoke_post,
    token::token_post,
    userinfo::user_get,
};
use state::AppStateInner;

pub fn router(
    db: DatabaseConnection,
    settings: Arc<crate::config::Settings>,
    grpc_clients: Arc<RwLock<HashMap<String, ClientSender>>>,
    pending_scope_requests: PendingScopeMap,
) -> Router {
    let templates_dir = &settings.web.templates_dir;
    let templates_path = std::path::Path::new(templates_dir);
    if !templates_path.exists() || !templates_path.is_dir() {
        panic!(
            "FATAL: templates directory '{}' not found. Check web.templates_dir in xauthd.toml.",
            templates_dir
        );
    }

    let rsa_key = crate::services::jwt::get_or_create_rsa_key(&settings.jwt.rsa_private_key_path);
    let state = Arc::new(AppStateInner {
        db,
        templates_dir: settings.web.templates_dir.clone(),
        settings,
        rsa_key,
        grpc_clients,
        pending_scope_requests,
    });

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery_get))
        .route("/jwks", get(jwks_get))
        .route("/user", get(user_get).post(user_get))
        .route("/introspect", post(introspect_post))
        .route("/revoke", post(revoke_post))
        .route("/authorize", get(authorize_get))
        .route("/login", post(login_post))
        .route("/consent", get(consent_get).post(consent_post))
        .route("/token", post(token_post));

    let app = if let Some(public_dir) = &state.settings.web.public_dir {
        let public_path = std::path::Path::new(public_dir);
        if public_path.exists() && public_path.is_dir() {
            tracing::info!("Serving static files from '{}' under /static/", public_dir);
            app.nest_service("/static", tower_http::services::ServeDir::new(public_dir))
        } else {
            tracing::warn!(
                "public_dir '{}' not found, static file serving disabled",
                public_dir
            );
            app
        }
    } else {
        app
    };

    app.with_state(state)
}
