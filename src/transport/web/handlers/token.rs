use axum::{
    extract::{Form, State},
    response::IntoResponse,
    Json,
};
use crate::db::UserRepository;
use crate::services::oauth::{OAuthService, TokenRequest as OAuthTokenRequest};
use super::{dto::{TokenRequest, TokenResponse}, state::AppState};

pub async fn token_post(
    State(state): State<AppState>,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    let oauth = OAuthService::new(
        UserRepository::new(state.db.clone()),
        state.settings.clone(),
        std::sync::Arc::new(state.rsa_key.clone()),
    );

    if !oauth.validate_client(&req.client_id, &req.client_secret).await {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid_client"})),
        )
            .into_response();
    }

    let oauth_req = OAuthTokenRequest {
        grant_type: req.grant_type.clone(),
        client_id: req.client_id.clone(),
        client_secret: req.client_secret.clone(),
        code: req.code.clone(),
        redirect_uri: req.redirect_uri.clone(),
        code_verifier: req.code_verifier.clone(),
        refresh_token: req.refresh_token.clone(),
    };

    let result = if req.grant_type == "authorization_code" {
        oauth.exchange_authorization_code(&oauth_req).await
    } else if req.grant_type == "refresh_token" {
        oauth.exchange_refresh_token(&oauth_req).await
    } else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unsupported_grant_type"})),
        )
            .into_response();
    };

    match result {
        Ok(issued) => Json(TokenResponse {
            access_token: issued.access_token,
            token_type: "Bearer".to_string(),
            expires_in: issued.expires_in,
            refresh_token: issued.refresh_token,
            id_token: issued.id_token,
        })
        .into_response(),
        Err(e) => {
            let status = match &e {
                crate::services::oauth::TokenError::InvalidClient => {
                    axum::http::StatusCode::UNAUTHORIZED
                }
                _ => axum::http::StatusCode::BAD_REQUEST,
            };
            (
                status,
                Json(serde_json::json!({
                    "error": e.code(),
                    "error_description": e.description()
                })),
            )
                .into_response()
        }
    }
}
