use crate::db::UserRepository;
use crate::services::rate_limit::RateLimitType;
use crate::transport::web::{
    dto::{LoginForm, LoginResponse},
    state::AppState,
};
use axum::{
    extract::{ConnectInfo, Form, State},
    response::{IntoResponse, Redirect},
    Json,
};
use std::net::SocketAddr;

pub async fn login_post(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Form(f): Form<LoginForm>,
) -> impl IntoResponse {
    let repo = UserRepository::new(state.db.clone());
    let mut headers = axum::http::HeaderMap::new();

    // Check IP rate limit
    let ip = addr.ip().to_string();
    if let Err(e) = state.rate_limiter.check(&RateLimitType::Ip(ip)).await {
        return Redirect::to(&format!("/login?error={}", urlencoding::encode(e))).into_response();
    }

    // Check Username rate limit
    if let Err(e) = state
        .rate_limiter
        .check(&RateLimitType::Username(f.username.clone()))
        .await
    {
        return Redirect::to(&format!("/login?error={}", urlencoding::encode(e))).into_response();
    }

    match repo.get_user_by_name(&f.username).await {
        Ok(Some(mut user)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            if let Some(last_failed) = user.last_failed_attempt {
                if now - last_failed > state.settings.security.failed_attempts_reset_interval {
                    repo.reset_failed_attempts(user.id).await.ok();
                    user.failed_attempts = 0;
                }
            }

            if user.failed_attempts >= state.settings.security.max_failed_attempts {
                return (
                    headers,
                    Json(LoginResponse {
                        redirect_url: None,
                        error: Some("Too many failed attempts. Account locked.".to_string()),
                    }),
                )
                    .into_response();
            }

            if crate::services::hash::verify_password(&f.password, &user.password_hash) {
                repo.reset_failed_attempts(user.id).await.ok();
                if let Ok(session_token) = crate::services::jwt::generate_jwt(
                    &user.username,
                    &state.settings.jwt.secret,
                    state.settings.jwt.session_ttl,
                ) {
                    if let Ok(cookie_val) = format!(
                        "session_token={}; HttpOnly; Path=/; SameSite=Lax",
                        session_token
                    )
                    .parse()
                    {
                        headers.insert(axum::http::header::SET_COOKIE, cookie_val);
                    }
                }
                let mut url = format!("/consent?client_id={}", f.client_id.unwrap_or_default());
                if let Some(redirect_uri) = f.redirect_uri {
                    url.push_str(&format!("&redirect_uri={}", redirect_uri));
                }
                if let Some(s) = f.scope {
                    url.push_str(&format!("&scope={}", s));
                }
                if let Some(s) = f.state {
                    url.push_str(&format!("&state={}", s));
                }
                if let Some(cc) = f.code_challenge {
                    url.push_str(&format!("&code_challenge={}", cc));
                }
                if let Some(ccm) = f.code_challenge_method {
                    url.push_str(&format!("&code_challenge_method={}", ccm));
                }
                if let Some(n) = f.nonce {
                    url.push_str(&format!("&nonce={}", n));
                }
                (
                    headers,
                    Json(LoginResponse {
                        redirect_url: Some(url),
                        error: None,
                    }),
                )
                    .into_response()
            } else {
                repo.increment_failed_attempts(user.id).await.ok();
                (
                    headers,
                    Json(LoginResponse {
                        redirect_url: None,
                        error: Some("Invalid username or password".to_string()),
                    }),
                )
                    .into_response()
            }
        }
        _ => (
            headers,
            Json(LoginResponse {
                redirect_url: None,
                error: Some("Invalid username or password".to_string()),
            }),
        )
            .into_response(),
    }
}
