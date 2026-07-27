use askama::Template;
use axum::{
    extract::{Query, Form, State},
    response::{Html, IntoResponse, sse::{Event, Sse}},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use sea_orm::DatabaseConnection;
use uuid::Uuid;
use crate::db::UserRepository;
use tokio_stream::wrappers::ReceiverStream;
use tokio::sync::mpsc;
use std::convert::Infallible;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
    client_id: String,
    redirect_uri: String,
    state: String,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate {
    client_id: String,
    redirect_uri: String,
    state: String,
    username: String,
    scopes_list: String,
}

#[derive(Deserialize)]
struct LoginQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
struct ConsentForm {
    action: String,
    client_id: String,
    redirect_uri: String,
    state: String,
}

#[derive(Serialize)]
struct LoginResponse {
    request_id: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct LoginEventData {
    redirect_url: Option<String>,
}

#[derive(Deserialize)]
struct SseQuery {
    request_id: String,
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: String,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: usize,
    refresh_token: String,
    id_token: String,
}

struct AppStateInner {
    db: DatabaseConnection,
    login_channels: RwLock<HashMap<String, mpsc::Receiver<String>>>,
}

type AppState = Arc<AppStateInner>;

async fn authorize_get(Query(q): Query<LoginQuery>) -> impl IntoResponse {
    let template = LoginTemplate {
        error: q.error,
        client_id: q.client_id.unwrap_or_default(),
        redirect_uri: q.redirect_uri.unwrap_or_default(),
        state: q.state.unwrap_or_default(),
    };
    Html(template.render().unwrap())
}

async fn login_post(State(state): State<AppState>, Form(f): Form<LoginForm>) -> impl IntoResponse {
    let repo = UserRepository::new(state.db.clone());
    let (tx, rx) = mpsc::channel(1);
    
    let request_id = Uuid::new_v4().to_string();
    state.login_channels.write().await.insert(request_id.clone(), rx);
    
    let mut headers = axum::http::HeaderMap::new();
    
    let result_data = match repo.get_user_by_name(&f.username).await {
        Ok(Some(user)) => {
            if crate::hash::verify_password(&f.password, &user.password_hash) {
                if let Ok(session_token) = crate::jwt::generate_jwt(&user.username, "super_secret_key_change_me", 3600) {
                    if let Ok(cookie_val) = format!("session_token={}; HttpOnly; Path=/; SameSite=Lax", session_token).parse() {
                        headers.insert(axum::http::header::SET_COOKIE, cookie_val);
                    }
                }
                let mut url = format!("/consent?client_id={}", f.client_id.unwrap_or_default());
                if let Some(redirect_uri) = f.redirect_uri {
                    url.push_str(&format!("&redirect_uri={}", redirect_uri));
                }
                if let Some(s) = f.state {
                    url.push_str(&format!("&state={}", s));
                }
                serde_json::to_string(&LoginEventData { redirect_url: Some(url) }).unwrap()
            } else {
                serde_json::to_string(&LoginEventData { redirect_url: None }).unwrap()
            }
        },
        _ => serde_json::to_string(&LoginEventData { redirect_url: None }).unwrap(),
    };
    
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let _ = tx.send(result_data).await;
    });
    
    (headers, Json(LoginResponse {
        request_id: Some(request_id),
        error: None,
    }))
}

fn get_username_from_cookie(headers: &axum::http::HeaderMap) -> String {
    if let Some(cookie_val) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_val.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if part.starts_with("session_token=") {
                    let token = &part["session_token=".len()..];
                    if let Ok(claims) = crate::jwt::validate_jwt(token, "super_secret_key_change_me") {
                        return claims.sub;
                    }
                }
            }
        }
    }
    "Guest".to_string()
}

async fn login_events_get(State(state): State<AppState>, Query(q): Query<SseQuery>) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx_opt = state.login_channels.write().await.remove(&q.request_id);
    let (tx, rx) = mpsc::channel(1);
    
    if let Some(mut backend_rx) = rx_opt {
        tokio::spawn(async move {
            if let Some(data) = backend_rx.recv().await {
                let _ = tx.send(Ok(Event::default().event("login_result").data(data))).await;
            }
        });
    }
    
    Sse::new(ReceiverStream::new(rx)).keep_alive(axum::response::sse::KeepAlive::new())
}

async fn consent_get(headers: axum::http::HeaderMap, Query(q): Query<LoginQuery>) -> impl IntoResponse {
    let username = get_username_from_cookie(&headers);
    let template = ConsentTemplate {
        client_id: q.client_id.unwrap_or_default(),
        redirect_uri: q.redirect_uri.unwrap_or_default(),
        state: q.state.unwrap_or_default(),
        username,
        scopes_list: "profile".to_string(),
    };
    Html(template.render().unwrap())
}

async fn consent_post(headers: axum::http::HeaderMap, Form(f): Form<ConsentForm>) -> impl IntoResponse {
    if f.action == "approve" {
        let username = get_username_from_cookie(&headers);
        let subject = serde_json::to_string(&serde_json::json!({
            "u": username,
            "c": f.client_id,
            "r": f.redirect_uri
        })).unwrap_or_default();
        let code = crate::jwt::generate_jwt(&subject, "super_secret_key_change_me", 600).unwrap_or_else(|_| "fallback_code".into());
        let url = format!("{}?code={}&state={}", f.redirect_uri, code, f.state);
        axum::response::Redirect::to(&url).into_response()
    } else {
        let url = format!("{}?error=access_denied&state={}", f.redirect_uri, f.state);
        axum::response::Redirect::to(&url).into_response()
    }
}

async fn token_post(State(state): State<AppState>, Form(req): Form<TokenRequest>) -> impl IntoResponse {
    let repo = UserRepository::new(state.db.clone());
    let is_valid = repo.validate_oauth_client(&req.client_id, &req.client_secret).await.unwrap_or(false);
    
    if !is_valid {
        return (axum::http::StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "invalid_client"}))).into_response();
    }
    
    if req.grant_type != "authorization_code" {
        return (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "unsupported_grant_type"}))).into_response();
    }
    
    let code = req.code.unwrap_or_default();
    if let Ok(claims) = crate::jwt::validate_jwt(&code, "super_secret_key_change_me") {
        if let Ok(data) = serde_json::from_str::<serde_json::Value>(&claims.sub) {
            let u = data["u"].as_str().unwrap_or_default();
            let c = data["c"].as_str().unwrap_or_default();
            let r = data["r"].as_str().unwrap_or_default();
            
            let req_redirect_uri = req.redirect_uri.unwrap_or_default();
            if c == req.client_id && r == req_redirect_uri {
                let access_token = crate::jwt::generate_jwt(u, "super_secret_key_change_me", 3600).unwrap();
                let refresh_token = crate::jwt::generate_jwt(u, "super_secret_key_change_me", 3600 * 24 * 7).unwrap();
                let id_token = crate::jwt::generate_jwt(u, "super_secret_key_change_me", 3600).unwrap();
                
                return Json(TokenResponse {
                    access_token,
                    token_type: "Bearer".to_string(),
                    expires_in: 3600,
                    refresh_token,
                    id_token,
                }).into_response();
            }
        }
    }
    
    (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_grant"}))).into_response()
}

pub fn router(db: DatabaseConnection) -> Router {
    let state = Arc::new(AppStateInner {
        db,
        login_channels: RwLock::new(HashMap::new()),
    });

    Router::new()
        .route("/authorize", get(authorize_get))
        .route("/login", post(login_post))
        .route("/login-events", get(login_events_get))
        .route("/consent", get(consent_get).post(consent_post))
        .route("/token", post(token_post))
        .with_state(state)
}
