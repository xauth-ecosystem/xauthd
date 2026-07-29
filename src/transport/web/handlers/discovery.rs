use axum::{extract::State, response::IntoResponse, Json};
use crate::transport::web::state::AppState;

pub async fn jwks_get(State(state): State<AppState>) -> impl IntoResponse {
    Json(crate::jwt::get_jwks(&state.rsa_key))
}

pub async fn discovery_get() -> impl IntoResponse {
    let base_url = "http://localhost:8080";
    Json(serde_json::json!({
        "issuer": base_url,
        "authorization_endpoint": format!("{}/authorize", base_url),
        "token_endpoint": format!("{}/token", base_url),
        "jwks_uri": format!("{}/jwks", base_url),
        "scopes_supported": ["openid", "profile"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }))
}
