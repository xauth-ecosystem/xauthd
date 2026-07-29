use axum::{
    extract::{Form, State},
    response::IntoResponse,
    Json,
};
use crate::db::UserRepository;
use super::{dto::IntrospectRequest, state::AppState};

pub async fn introspect_post(
    State(state): State<AppState>,
    Form(req): Form<IntrospectRequest>,
) -> impl IntoResponse {
    let repo = UserRepository::new(state.db.clone());
    let is_valid = repo
        .validate_oauth_client(&req.client_id, &req.client_secret)
        .await
        .unwrap_or(false);
    if !is_valid {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_client"})),
        )
            .into_response();
    }

    if let Ok(claims) = crate::jwt::validate_jwt(&req.token, &state.settings.jwt.secret) {
        if !repo
            .is_token_blacklisted(&claims.jti)
            .await
            .unwrap_or(false)
        {
            let oauth_token = repo.get_oauth_token(&req.token).await.ok().flatten();
            let scope = oauth_token
                .as_ref()
                .map(|t| t.scopes.clone())
                .unwrap_or_default();
            let client_id = oauth_token
                .as_ref()
                .map(|t| t.client_id.clone())
                .unwrap_or_default();
            return (
                axum::http::StatusCode::OK,
                Json(serde_json::json!({
                    "active": true,
                    "sub": claims.sub,
                    "username": claims.sub,
                    "exp": claims.exp,
                    "iat": claims.iat,
                    "scope": scope,
                    "client_id": client_id
                })),
            )
                .into_response();
        }
    }

    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({"active": false})),
    )
        .into_response()
}
