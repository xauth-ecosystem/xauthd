use askama::Template;
use axum::{
    extract::{Query, Form},
    response::{Html, IntoResponse},
    routing::{get, post},
    Router,
};
use serde::Deserialize;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    error: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
}

#[derive(Template)]
#[template(path = "consent.html")]
struct ConsentTemplate {
    client_id: String,
    redirect_uri: String,
    state: String,
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
    password: String, // Mock for now
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

async fn login_get(Query(q): Query<LoginQuery>) -> impl IntoResponse {
    let template = LoginTemplate {
        error: q.error,
        client_id: q.client_id,
        redirect_uri: q.redirect_uri,
        state: q.state,
    };
    Html(template.render().unwrap())
}

async fn login_post(Form(f): Form<LoginForm>) -> impl IntoResponse {
    // Basic stub for testing
    if f.username == "test" && f.password == "test" {
        // Success
        if let Some(client_id) = f.client_id {
            // Need consent
            let url = format!("/consent?client_id={}&redirect_uri={}&state={}", 
                client_id, 
                f.redirect_uri.unwrap_or_default(), 
                f.state.unwrap_or_default()
            );
            return axum::response::Redirect::to(&url).into_response();
        } else {
            return Html("Авторизація успішна! Ви можете закрити цю сторінку.".to_string()).into_response();
        }
    } else {
        // Fail
        let url = format!("/login?error=Invalid_Login&client_id={}&redirect_uri={}&state={}", 
            f.client_id.unwrap_or_default(), 
            f.redirect_uri.unwrap_or_default(), 
            f.state.unwrap_or_default()
        );
        return axum::response::Redirect::to(&url).into_response();
    }
}

async fn consent_get(Query(q): Query<LoginQuery>) -> impl IntoResponse {
    let template = ConsentTemplate {
        client_id: q.client_id.unwrap_or_default(),
        redirect_uri: q.redirect_uri.unwrap_or_default(),
        state: q.state.unwrap_or_default(),
    };
    Html(template.render().unwrap())
}

async fn consent_post(Form(f): Form<ConsentForm>) -> impl IntoResponse {
    if f.action == "approve" {
        // Redirect back with auth code
        let code = "dummy_auth_code_123";
        let url = format!("{}?code={}&state={}", f.redirect_uri, code, f.state);
        axum::response::Redirect::to(&url).into_response()
    } else {
        let url = format!("{}?error=access_denied&state={}", f.redirect_uri, f.state);
        axum::response::Redirect::to(&url).into_response()
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/login", get(login_get).post(login_post))
        .route("/consent", get(consent_get).post(consent_post))
}
