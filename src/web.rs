use crate::db::UserRepository;
use axum::{
    extract::{Form, Query, State},
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

fn render_template(
    templates_dir: &str,
    name: &str,
    ctx: minijinja::Value,
) -> Result<Html<String>, String> {
    let mut env = minijinja::Environment::new();
    env.set_loader(minijinja::path_loader(templates_dir));
    let tmpl = env.get_template(name).map_err(|e| e.to_string())?;
    let rendered = tmpl.render(ctx).map_err(|e| e.to_string())?;
    Ok(Html(rendered))
}

#[derive(Deserialize)]
struct LoginQuery {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    error: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

#[derive(Deserialize)]
struct ConsentForm {
    action: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

#[derive(Serialize)]
struct LoginResponse {
    redirect_url: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: String,
    client_secret: String,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct IntrospectRequest {
    token: String,
    client_id: String,
    client_secret: String,
}

#[derive(Deserialize)]
struct RevokeRequest {
    token: String,
    client_id: String,
    client_secret: String,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: usize,
    refresh_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

struct AppStateInner {
    db: DatabaseConnection,
    settings: Arc<crate::config::Settings>,
    rsa_key: rsa::RsaPrivateKey,
    templates_dir: String,
}

type AppState = Arc<AppStateInner>;

async fn authorize_get(
    State(state): State<AppState>,
    Query(q): Query<LoginQuery>,
) -> impl IntoResponse {
    let repo = UserRepository::new(state.db.clone());

    let scope = match &q.scope {
        Some(s) if !s.is_empty() => s.clone(),
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
            let sep = if redirect_uri.contains('?') { '&' } else { '?' };
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
                        let sep = if redirect_uri.contains('?') { '&' } else { '?' };
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

async fn login_post(State(state): State<AppState>, Form(f): Form<LoginForm>) -> impl IntoResponse {
    let repo = UserRepository::new(state.db.clone());
    let mut headers = axum::http::HeaderMap::new();

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

            if crate::hash::verify_password(&f.password, &user.password_hash) {
                repo.reset_failed_attempts(user.id).await.ok();
                if let Ok(session_token) = crate::jwt::generate_jwt(
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

fn get_username_from_cookie(headers: &axum::http::HeaderMap, state: &AppState) -> String {
    if let Some(cookie_val) = headers.get(axum::http::header::COOKIE) {
        if let Ok(cookie_str) = cookie_val.to_str() {
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(token) = part.strip_prefix("session_token=") {
                    if let Ok(claims) = crate::jwt::validate_jwt(token, &state.settings.jwt.secret)
                    {
                        return claims.sub;
                    }
                }
            }
        }
    }
    "Guest".to_string()
}

async fn consent_get(
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

async fn consent_post(
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
        let code = crate::jwt::generate_jwt(
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

async fn token_post(
    State(state): State<AppState>,
    Form(req): Form<TokenRequest>,
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

    if req.grant_type == "authorization_code" {
        let code = req.code.unwrap_or_default();
        if let Ok(claims) = crate::jwt::validate_jwt(&code, &state.settings.jwt.secret) {
            if let Ok(data) = serde_json::from_str::<serde_json::Value>(&claims.sub) {
                let u = data["u"].as_str().unwrap_or_default();
                let c = data["c"].as_str().unwrap_or_default();
                let r = data["r"].as_str().unwrap_or_default();

                let cc = data["cc"].as_str().unwrap_or_default();
                let ccm = data["ccm"].as_str().unwrap_or_default();
                let req_redirect_uri = req.redirect_uri.unwrap_or_default();

                if c == req.client_id && r == req_redirect_uri {
                    if !cc.is_empty() {
                        let code_verifier = req.code_verifier.unwrap_or_default();
                        if code_verifier.is_empty() {
                            return (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_request", "error_description": "code_verifier required"}))).into_response();
                        }

                        let is_valid = if ccm == "S256" {
                            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
                            use sha2::{Digest, Sha256};
                            let mut hasher = Sha256::new();
                            hasher.update(code_verifier.as_bytes());
                            let hash = hasher.finalize();
                            let expected = URL_SAFE_NO_PAD.encode(hash);
                            expected == cc
                        } else if ccm == "plain" || ccm == "plain_text" || ccm.is_empty() {
                            code_verifier == cc
                        } else {
                            false
                        };

                        if !is_valid {
                            return (axum::http::StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid_grant", "error_description": "Invalid code_verifier"}))).into_response();
                        }
                    }

                    if let Ok(Some(user)) = repo.get_user_by_name(u).await {
                        let access_token = crate::jwt::generate_jwt(
                            u,
                            &state.settings.jwt.secret,
                            state.settings.jwt.access_token_ttl,
                        )
                        .unwrap();
                        let refresh_token = crate::jwt::generate_jwt(
                            u,
                            &state.settings.jwt.secret,
                            state.settings.jwt.refresh_token_ttl,
                        )
                        .unwrap();

                        let scopes = data["s"].as_str().unwrap_or("");
                        let id_token = if scopes.split_whitespace().any(|s| s == "openid") {
                            let n = data["n"].as_str().unwrap_or_default();
                            let nonce_opt = if n.is_empty() {
                                None
                            } else {
                                Some(n.to_string())
                            };
                            Some(
                                crate::jwt::generate_rs256_jwt(
                                    u,
                                    &state.rsa_key,
                                    state.settings.jwt.access_token_ttl,
                                    nonce_opt,
                                )
                                .unwrap(),
                            )
                        } else {
                            None
                        };

                        repo.create_oauth_token(
                            &req.client_id,
                            user.id,
                            &access_token,
                            Some(&refresh_token),
                            state.settings.jwt.access_token_ttl as i64,
                            scopes,
                        )
                        .await
                        .ok();

                        return Json(TokenResponse {
                            access_token,
                            token_type: "Bearer".to_string(),
                            expires_in: state.settings.jwt.access_token_ttl,
                            refresh_token,
                            id_token,
                        })
                        .into_response();
                    }
                }
            }
        }

        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid_grant"})),
        )
            .into_response()
    } else if req.grant_type == "refresh_token" {
        let refresh_token = match req.refresh_token {
            Some(t) => t,
            None => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_request", "error_description": "Missing refresh_token parameter"})),
                )
                    .into_response();
            }
        };

        let claims = match crate::jwt::validate_jwt(&refresh_token, &state.settings.jwt.secret) {
            Ok(c) => c,
            Err(_) => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant", "error_description": "Invalid or expired refresh token"})),
                )
                    .into_response();
            }
        };

        if repo
            .is_token_blacklisted(&claims.jti)
            .await
            .unwrap_or(false)
        {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_grant", "error_description": "Refresh token has been revoked"})),
            )
                .into_response();
        }

        let existing_token = match repo.get_oauth_token(&refresh_token).await {
            Ok(Some(t)) => t,
            _ => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant", "error_description": "Refresh token not found"})),
                )
                    .into_response();
            }
        };

        if existing_token.client_id != req.client_id {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid_grant", "error_description": "Refresh token was issued to another client"})),
            )
                .into_response();
        }

        let username = claims.sub.clone();
        let new_access_token = crate::jwt::generate_jwt(
            &username,
            &state.settings.jwt.secret,
            state.settings.jwt.access_token_ttl,
        )
        .unwrap();
        let new_refresh_token = crate::jwt::generate_jwt(
            &username,
            &state.settings.jwt.secret,
            state.settings.jwt.refresh_token_ttl,
        )
        .unwrap();

        let user = match repo.get_user_by_name(&username).await {
            Ok(Some(u)) => u,
            _ => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid_grant", "error_description": "User not found"})),
                )
                    .into_response();
            }
        };

        repo.delete_oauth_token(&refresh_token).await.ok();
        repo.create_oauth_token(
            &req.client_id,
            user.id,
            &new_access_token,
            Some(&new_refresh_token),
            state.settings.jwt.access_token_ttl as i64,
            &existing_token.scopes,
        )
        .await
        .ok();

        let id_token = if existing_token
            .scopes
            .split_whitespace()
            .any(|s| s == "openid")
        {
            Some(
                crate::jwt::generate_rs256_jwt(
                    &username,
                    &state.rsa_key,
                    state.settings.jwt.access_token_ttl,
                    None,
                )
                .unwrap(),
            )
        } else {
            None
        };

        Json(TokenResponse {
            access_token: new_access_token,
            token_type: "Bearer".to_string(),
            expires_in: state.settings.jwt.access_token_ttl,
            refresh_token: new_refresh_token,
            id_token,
        })
        .into_response()
    } else {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "unsupported_grant_type"})),
        )
            .into_response()
    }
}

async fn user_get(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let repo = UserRepository::new(state.db.clone());
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if let Ok(claims) = crate::jwt::validate_jwt(token, &state.settings.jwt.secret) {
                    if !repo
                        .is_token_blacklisted(&claims.jti)
                        .await
                        .unwrap_or(false)
                    {
                        return (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({
                                "sub": claims.sub.clone(),
                                "preferred_username": claims.sub.clone(),
                                "name": claims.sub
                            })),
                        )
                            .into_response();
                    }
                }
            }
        }
    }
    (
        axum::http::StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "invalid_token"})),
    )
        .into_response()
}

async fn introspect_post(
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
            let scope = repo
                .get_oauth_token(&req.token)
                .await
                .ok()
                .flatten()
                .map(|t| t.scopes)
                .unwrap_or_default();
            let client_id = repo
                .get_oauth_token(&req.token)
                .await
                .ok()
                .flatten()
                .map(|t| t.client_id)
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

async fn revoke_post(
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
            Json(serde_json::json!({"error": "invalid_client"})),
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

async fn jwks_get(State(state): State<AppState>) -> impl IntoResponse {
    Json(crate::jwt::get_jwks(&state.rsa_key))
}

async fn discovery_get() -> impl IntoResponse {
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

pub fn router(db: DatabaseConnection, settings: Arc<crate::config::Settings>) -> Router {
    // Check if templates directory exists
    let templates_dir = &settings.web.templates_dir;
    let templates_path = std::path::Path::new(templates_dir);
    if !templates_path.exists() || !templates_path.is_dir() {
        panic!(
            "FATAL: templates directory '{}' not found. Check web.templates_dir in xauthd.toml.",
            templates_dir
        );
    }

    let rsa_key = crate::jwt::get_or_create_rsa_key(&settings.jwt.rsa_private_key_path);
    let state = Arc::new(AppStateInner {
        db,
        templates_dir: settings.web.templates_dir.clone(),
        settings,
        rsa_key,
    });

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery_get))
        .route("/jwks", get(jwks_get))
        .route("/user", get(user_get).post(user_get))
        .route("/introspect", post(introspect_post))
        .route("/revoke", post(revoke_post))
        .route("/authorize", get(authorize_get))
        .route("/login", post(login_post))
        .route("/consent", get(consent_get).post(consent_post))
        .route("/token", post(token_post));

    // Serve static files from public_dir under /static/ if configured
    let app = if let Some(public_dir) = &state.settings.web.public_dir {
        let public_path = std::path::Path::new(public_dir);
        if public_path.exists() && public_path.is_dir() {
            tracing::info!("Serving static files from '{}' under /static/", public_dir);
            app.nest_service("/static", tower_http::services::ServeDir::new(public_dir))
        } else {
            tracing::warn!(
                "public_dir '{}' not found, static file serving disabled",
                public_dir
            );
            app
        }
    } else {
        app
    };

    app.with_state(state)
}
