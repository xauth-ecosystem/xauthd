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

struct AppStateInner {
    db: DatabaseConnection,
    login_channels: RwLock<HashMap<String, mpsc::Receiver<String>>>,
}

type AppState = Arc<AppStateInner>;

async fn login_get(Query(q): Query<LoginQuery>) -> impl IntoResponse {
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
    
    tokio::spawn(async move {
        let result = match repo.get_user_by_name(&f.username).await {
            Ok(Some(user)) => {
                if crate::hash::verify_password(&f.password, &user.password_hash) {
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
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let _ = tx.send(result).await;
    });
    
    Json(LoginResponse {
        request_id: Some(request_id),
        error: None,
    })
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

async fn consent_get(Query(q): Query<LoginQuery>) -> impl IntoResponse {
    let template = ConsentTemplate {
        client_id: q.client_id.unwrap_or_default(),
        redirect_uri: q.redirect_uri.unwrap_or_default(),
        state: q.state.unwrap_or_default(),
        username: "Player".to_string(), // Mock
        scopes_list: "profile".to_string(),
    };
    Html(template.render().unwrap())
}

async fn consent_post(Form(f): Form<ConsentForm>) -> impl IntoResponse {
    if f.action == "approve" {
        let code = "dummy_auth_code_123";
        let url = format!("{}?code={}&state={}", f.redirect_uri, code, f.state);
        axum::response::Redirect::to(&url).into_response()
    } else {
        let url = format!("{}?error=access_denied&state={}", f.redirect_uri, f.state);
        axum::response::Redirect::to(&url).into_response()
    }
}

pub fn router(db: DatabaseConnection) -> Router {
    let state = Arc::new(AppStateInner {
        db,
        login_channels: RwLock::new(HashMap::new()),
    });

    Router::new()
        .route("/login", get(login_get).post(login_post))
        .route("/login-events", get(login_events_get))
        .route("/consent", get(consent_get).post(consent_post))
        .with_state(state)
}
