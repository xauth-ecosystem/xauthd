mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use common::{get_test_settings, setup_test_db};
use sea_orm::DatabaseConnection;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::util::ServiceExt;
use xauth_core::db::UserRepository;
use xauth_core::transport::web::router;

fn build_auth_code(
    settings: &xauth_core::config::Settings,
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
    code_challenge: &str,
    code_challenge_method: &str,
    nonce: &str,
) -> String {
    let subject = serde_json::to_string(&serde_json::json!({
        "u": "test_user",
        "c": client_id,
        "r": redirect_uri,
        "s": scope,
        "cc": code_challenge,
        "ccm": code_challenge_method,
        "n": nonce
    }))
    .unwrap();
    xauth_core::services::jwt::generate_jwt(&subject, &settings.jwt.secret, settings.jwt.auth_code_ttl)
        .unwrap()
}

fn build_test_router(
    db: DatabaseConnection,
    settings: Arc<xauth_core::config::Settings>,
) -> axum::Router {
    let grpc_clients = Arc::new(RwLock::new(HashMap::new()));
    let pending_scopes = Arc::new(RwLock::new(HashMap::new()));
    router(db, settings, grpc_clients, pending_scopes)
}

#[tokio::test]
async fn test_discovery_get() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("GET")
        .uri("/.well-known/openid-configuration")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["issuer"], "http://localhost:8080");
    assert_eq!(json["token_endpoint"], "http://localhost:8080/token");
}

#[tokio::test]
async fn test_jwks_get() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("GET")
        .uri("/jwks")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["keys"].is_array());
    assert_eq!(json["keys"][0]["kty"], "RSA");
}

#[tokio::test]
async fn test_token_post_authorization_code_success() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());

    repo.create_user("test_user", "hash").await.unwrap();
    repo.create_oauth_client("my_client", "secret", "http://localhost/callback")
        .await
        .unwrap();

    let verifier = "test_verifier_123456789012345678901234567890123456789012345678";
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

    let auth_code = build_auth_code(
        &settings,
        "my_client",
        "http://localhost/callback",
        "openid profile",
        &challenge,
        "S256",
        "test_nonce",
    );

    let app = build_test_router(db, settings.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=authorization_code&code={}&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&client_id=my_client&client_secret=secret&code_verifier={}",
            auth_code, verifier
        )))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert!(!json["access_token"].as_str().unwrap().is_empty());
    assert!(!json["refresh_token"].as_str().unwrap().is_empty());
    assert!(!json["id_token"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_token_post_authorization_code_invalid_client() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());
    repo.create_user("test_user", "hash").await.unwrap();

    let auth_code = build_auth_code(
        &settings,
        "my_client",
        "http://localhost/callback",
        "openid profile",
        "",
        "",
        "",
    );

    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=authorization_code&code={}&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&client_id=bad_client&client_secret=bad",
            auth_code
        )))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn test_token_post_authorization_code_invalid_code() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());
    repo.create_user("test_user", "hash").await.unwrap();
    repo.create_oauth_client("my_client", "secret", "http://localhost/callback")
        .await
        .unwrap();

    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=authorization_code&code=not_a_valid_jwt&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback&client_id=my_client&client_secret=secret",
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn test_token_post_refresh_token_success() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());
    repo.create_user("test_user", "hash").await.unwrap();
    repo.create_oauth_client("my_client", "secret", "http://localhost/callback")
        .await
        .unwrap();

    let refresh_token = xauth_core::services::jwt::generate_jwt(
        "test_user",
        &settings.jwt.secret,
        settings.jwt.refresh_token_ttl,
    )
    .unwrap();
    let access_token = xauth_core::services::jwt::generate_jwt(
        "test_user",
        &settings.jwt.secret,
        settings.jwt.access_token_ttl,
    )
    .unwrap();
    let user = repo.get_user_by_name("test_user").await.unwrap().unwrap();
    repo.create_oauth_token(
        "my_client",
        user.id,
        &access_token,
        Some(&refresh_token),
        settings.jwt.access_token_ttl as i64,
        "openid profile",
    )
    .await
    .unwrap();

    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "grant_type=refresh_token&refresh_token={}&client_id=my_client&client_secret=secret",
            refresh_token
        )))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["token_type"], "Bearer");
    assert!(!json["access_token"].as_str().unwrap().is_empty());
    assert!(!json["refresh_token"].as_str().unwrap().is_empty());
    assert_ne!(json["refresh_token"].as_str().unwrap(), refresh_token);
}

#[tokio::test]
async fn test_token_post_refresh_token_invalid_client() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=refresh_token&refresh_token=any_token&client_id=bad_client&client_secret=bad",
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn test_token_post_refresh_token_invalid_grant() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());
    repo.create_oauth_client("my_client", "secret", "http://localhost/callback")
        .await
        .unwrap();

    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=refresh_token&refresh_token=not_a_valid_jwt&client_id=my_client&client_secret=secret",
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_grant");
}

#[tokio::test]
async fn test_token_post_unsupported_grant_type() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());
    repo.create_oauth_client("my_client", "secret", "http://localhost/callback")
        .await
        .unwrap();

    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=password&username=user&password=pass&client_id=my_client&client_secret=secret",
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn test_introspect_post_active() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());
    repo.create_user("test_user", "hash").await.unwrap();
    repo.create_oauth_client("my_client", "secret", "http://localhost/callback")
        .await
        .unwrap();

    let token = xauth_core::services::jwt::generate_jwt(
        "test_user",
        &settings.jwt.secret,
        settings.jwt.access_token_ttl,
    )
    .unwrap();
    let user = repo.get_user_by_name("test_user").await.unwrap().unwrap();
    repo.create_oauth_token(
        "my_client",
        user.id,
        &token,
        None,
        settings.jwt.access_token_ttl as i64,
        "openid profile",
    )
    .await
    .unwrap();

    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&client_id=my_client&client_secret=secret",
            token
        )))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active"], true);
    assert_eq!(json["sub"], "test_user");
    assert_eq!(json["username"], "test_user");
    assert_eq!(json["scope"], "openid profile");
    assert_eq!(json["client_id"], "my_client");
}

#[tokio::test]
async fn test_introspect_post_inactive() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());
    repo.create_oauth_client("my_client", "secret", "http://localhost/callback")
        .await
        .unwrap();

    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "token=not_a_valid_jwt&client_id=my_client&client_secret=secret",
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["active"], false);
}

#[tokio::test]
async fn test_introspect_post_invalid_client() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("POST")
        .uri("/introspect")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "token=any_token&client_id=bad_client&client_secret=bad",
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn test_revoke_post_success() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());
    repo.create_user("test_user", "hash").await.unwrap();
    repo.create_oauth_client("my_client", "secret", "http://localhost/callback")
        .await
        .unwrap();
    let user = repo.get_user_by_name("test_user").await.unwrap().unwrap();

    let token = xauth_core::services::jwt::generate_jwt(
        "test_user",
        &settings.jwt.secret,
        settings.jwt.access_token_ttl,
    )
    .unwrap();
    repo.create_oauth_token(
        "my_client",
        user.id,
        &token,
        None,
        settings.jwt.access_token_ttl as i64,
        "openid profile",
    )
    .await
    .unwrap();

    let app = build_test_router(db.clone(), settings.clone());
    let req = Request::builder()
        .method("POST")
        .uri("/revoke")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "token={}&client_id=my_client&client_secret=secret",
            token
        )))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let repo2 = UserRepository::new(db);
    let claims = xauth_core::services::jwt::validate_jwt(&token, &settings.jwt.secret).unwrap();
    assert!(repo2.is_token_blacklisted(&claims.jti).await.unwrap());
}

#[tokio::test]
async fn test_revoke_post_invalid_client() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("POST")
        .uri("/revoke")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(
            "token=any_token&client_id=bad_client&client_secret=bad",
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_client");
}

#[tokio::test]
async fn test_user_get_success() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let token = xauth_core::services::jwt::generate_jwt(
        "test_user",
        &settings.jwt.secret,
        settings.jwt.access_token_ttl,
    )
    .unwrap();

    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("GET")
        .uri("/user")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["sub"], "test_user");
    assert_eq!(json["preferred_username"], "test_user");
    assert_eq!(json["name"], "test_user");
}

#[tokio::test]
async fn test_user_get_missing_token() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let app = build_test_router(db, settings);
    let req = Request::builder()
        .method("GET")
        .uri("/user")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = to_bytes(resp.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "invalid_token");
}
