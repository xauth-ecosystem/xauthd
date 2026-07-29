use axum::{
    extract::{Form, State},
    response::IntoResponse,
};
use crate::db::UserRepository;
use crate::transport::web::{dto::RevokeRequest, state::AppState};

pub async fn revoke_post(
    State(state): State<AppState>,
    Form(req): Form<RevokeRequest>,
) -> impl IntoResponse {
    let repo = UserRepository::new(state.db.clone());
    let is_valid = repo
        .validate_oauth_client(&req.client_id, &req.client_secret)
        .await
        .unwrap_or(false);
    if !is_valid {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({"error": "invalid_client"})),
        )
            .into_response();
    }

    repo.delete_oauth_token(&req.token).await.ok();

    if let Ok(claims) = crate::jwt::validate_jwt(&req.token, &state.settings.jwt.secret) {
        repo.blacklist_token(&claims.jti, claims.exp as i64)
            .await
            .ok();
    }

    axum::http::StatusCode::OK.into_response()
}
