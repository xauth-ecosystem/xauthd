use crate::db::UserRepository;
use crate::transport::web::{
    dto::{ConsentForm, LoginQuery},
    state::AppState,
    templates::{get_username_from_cookie, render_template},
};
use axum::{
    extract::{Form, Query, State},
    response::IntoResponse,
};

pub async fn consent_get(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
    Query(q): Query<LoginQuery>,
) -> impl IntoResponse {
    let username = get_username_from_cookie(&headers, &state);
    let repo = UserRepository::new(state.db.clone());
    let mut allowed_scopes = "profile".to_string();

    if let Some(client_id) = &q.client_id {
        if let Ok(Some(client)) = repo.get_oauth_client(client_id).await {
            if let Some(scopes) = client.allowed_scopes {
                allowed_scopes = scopes;
            }
        }
    }

    let ctx = minijinja::context! {
        client_id => q.client_id.unwrap_or_default(),
        redirect_uri => q.redirect_uri.unwrap_or_default(),
        state => q.state.unwrap_or_default(),
        username => username,
        scopes_list => allowed_scopes,
        code_challenge => q.code_challenge.unwrap_or_default(),
        code_challenge_method => q.code_challenge_method.unwrap_or_default(),
        nonce => q.nonce.unwrap_or_default(),
    };

    match render_template(&state.templates_dir, "consent.html", ctx) {
        Ok(html) => html.into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

pub async fn consent_post(
    headers: axum::http::HeaderMap,
    State(state): State<AppState>,
    Form(f): Form<ConsentForm>,
) -> impl IntoResponse {
    if f.action == "approve" {
        let username = get_username_from_cookie(&headers, &state);
        let subject = serde_json::to_string(&serde_json::json!({
            "u": username,
            "c": f.client_id,
            "r": f.redirect_uri,
            "s": f.scope,
            "cc": f.code_challenge,
            "ccm": f.code_challenge_method,
            "n": f.nonce
        }))
        .unwrap_or_default();
        let code = crate::services::jwt::generate_jwt(
            &subject,
            &state.settings.jwt.secret,
            state.settings.jwt.auth_code_ttl,
        )
        .unwrap_or_else(|_| "fallback_code".into());
        let url = format!("{}?code={}&state={}", f.redirect_uri, code, f.state);
        axum::response::Redirect::to(&url).into_response()
    } else {
        let url = format!("{}?error=access_denied&state={}", f.redirect_uri, f.state);
        axum::response::Redirect::to(&url).into_response()
    }
}
