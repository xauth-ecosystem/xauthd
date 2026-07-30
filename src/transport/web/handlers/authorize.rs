use crate::db::UserRepository;
use crate::transport::web::{dto::LoginQuery, state::AppState, templates::render_template};
use axum::{
    extract::{Query, State},
    response::IntoResponse,
};

pub async fn authorize_get(
    State(state): State<AppState>,
    Query(q): Query<LoginQuery>,
) -> impl IntoResponse {
    let repo = UserRepository::new(state.db.clone());

    let scope = match &q.scope {
        Some(s) if !s.is_empty() => s.clone() as String,
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                "Missing scope parameter",
            )
                .into_response();
        }
    };

    let code_challenge_method = q.code_challenge_method.as_deref().unwrap_or("");
    if !matches!(code_challenge_method, "S256" | "plain" | "") {
        if let Some(redirect_uri) = &q.redirect_uri {
            let sep: char = if redirect_uri.contains('?') { '&' } else { '?' };
            let url = format!(
                "{}{}error=invalid_request&state={}",
                redirect_uri,
                sep,
                q.state.clone().unwrap_or_default()
            );
            return axum::response::Redirect::to(&url).into_response();
        }
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "Unsupported code_challenge_method",
        )
            .into_response();
    }

    let requested_scopes: Vec<&str> = scope.split_whitespace().collect();
    if requested_scopes.contains(&"openid") && q.nonce.is_none() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            "nonce parameter is required for OpenID Connect requests",
        )
            .into_response();
    }

    if let Some(client_id) = &q.client_id {
        if let Ok(Some(client)) = repo.get_oauth_client(client_id).await {
            let allowed = client
                .allowed_scopes
                .as_deref()
                .unwrap_or("")
                .split_whitespace()
                .chain(std::iter::once("openid"))
                .collect::<Vec<_>>();
            for req_scope in &requested_scopes {
                if !allowed.contains(req_scope) {
                    if let Some(redirect_uri) = &q.redirect_uri {
                        let sep: char = if redirect_uri.contains('?') { '&' } else { '?' };
                        let url = format!(
                            "{}{}error=invalid_scope&state={}",
                            redirect_uri,
                            sep,
                            q.state.clone().unwrap_or_default()
                        );
                        return axum::response::Redirect::to(&url).into_response();
                    }
                    return (axum::http::StatusCode::BAD_REQUEST, "Invalid scope").into_response();
                }
            }
        }
    }

    let ctx = minijinja::context! {
        error => q.error,
        client_id => q.client_id.unwrap_or_default(),
        redirect_uri => q.redirect_uri.unwrap_or_default(),
        scope => scope,
        state => q.state.unwrap_or_default(),
        code_challenge => q.code_challenge.unwrap_or_default(),
        code_challenge_method => q.code_challenge_method.unwrap_or_default(),
        nonce => q.nonce.unwrap_or_default(),
    };

    match render_template(&state.templates_dir, "login.html", ctx) {
        Ok(html) => html.into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}
