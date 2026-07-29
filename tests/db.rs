mod common;

use common::setup_test_db;
use xauth_core::db::UserRepository;

#[tokio::test]
async fn test_token_blacklist() {
    let db = setup_test_db().await;
    let repo = UserRepository::new(db);

    assert!(!repo.is_token_blacklisted("jti_123").await.unwrap());

    repo.blacklist_token("jti_123", 9999999999).await.unwrap();

    assert!(repo.is_token_blacklisted("jti_123").await.unwrap());
}

#[tokio::test]
async fn test_set_totp_secret() {
    let db = setup_test_db().await;
    let repo = UserRepository::new(db);

    repo.create_user("totp_user", "hash").await.unwrap();
    let user = repo.get_user_by_name("totp_user").await.unwrap().unwrap();

    assert!(!repo.is_2fa_enabled(user.id).await.unwrap());

    repo.set_totp_secret(user.id, "JBSWY3DPEHPK3PXP")
        .await
        .unwrap();

    let user = repo.get_user_by_name("totp_user").await.unwrap().unwrap();
    assert!(repo.is_2fa_enabled(user.id).await.unwrap());
    assert_eq!(user.totp_secret.unwrap(), "JBSWY3DPEHPK3PXP");
}

#[tokio::test]
async fn test_validate_oauth_client() {
    let db = setup_test_db().await;
    let repo = UserRepository::new(db);

    repo.create_oauth_client("client_123", "secret_456", "http://localhost/callback")
        .await
        .unwrap();

    let is_valid = repo
        .validate_oauth_client("client_123", "secret_456")
        .await
        .unwrap();
    assert!(is_valid, "Valid credentials should return true");

    let is_invalid = repo
        .validate_oauth_client("client_123", "wrong_secret")
        .await
        .unwrap();
    assert!(!is_invalid, "Invalid credentials should return false");

    let is_non_existent = repo
        .validate_oauth_client("non_existent", "secret_456")
        .await
        .unwrap();
    assert!(!is_non_existent, "Non-existent client should return false");
}

#[tokio::test]
async fn test_create_and_get_oauth_client() {
    let db = setup_test_db().await;
    let repo = UserRepository::new(db);

    // Test creating client
    let result = repo
        .create_oauth_client("client_123", "secret_456", "http://localhost/callback")
        .await;
    assert!(result.is_ok(), "Failed to create OAuth client");

    // Test fetching client
    let client = repo.get_oauth_client("client_123").await.unwrap();
    assert!(client.is_some(), "Client not found");

    let client = client.unwrap();
    assert_eq!(client.client_id, "client_123");
    assert_eq!(client.client_secret, "secret_456");
    assert_eq!(client.redirect_uris, "http://localhost/callback");
}

#[tokio::test]
async fn test_user_lifecycle() {
    let db = setup_test_db().await;
    let repo = UserRepository::new(db);

    // Create
    repo.create_user("test_user", "hash123").await.unwrap();

    // Get
    let user = repo.get_user_by_name("test_user").await.unwrap().unwrap();
    assert_eq!(user.username, "test_user");
    assert_eq!(user.password_hash, "hash123");
    assert_eq!(user.failed_attempts, 0);

    // Update login
    repo.update_last_login(user.id, "192.168.1.1")
        .await
        .unwrap();
    let user = repo.get_user_by_name("test_user").await.unwrap().unwrap();
    assert_eq!(user.last_ip.unwrap(), "192.168.1.1");
    assert!(user.last_login.is_some());

    // Failed attempts
    repo.increment_failed_attempts(user.id).await.unwrap();
    repo.increment_failed_attempts(user.id).await.unwrap();
    let user = repo.get_user_by_name("test_user").await.unwrap().unwrap();
    assert_eq!(user.failed_attempts, 2);

    repo.reset_failed_attempts(user.id).await.unwrap();
    let user = repo.get_user_by_name("test_user").await.unwrap().unwrap();
    assert_eq!(user.failed_attempts, 0);

    // Update password and ban
    repo.update_password(user.id, "new_hash").await.unwrap();
    repo.set_must_change_password(user.id, true).await.unwrap();
    repo.set_banned(user.id, true).await.unwrap();

    let user = repo.get_user_by_name("test_user").await.unwrap().unwrap();
    assert_eq!(user.password_hash, "new_hash");
    assert!(user.must_change_password);
    assert!(user.is_banned);
}

#[tokio::test]
async fn test_session_management() {
    let db = setup_test_db().await;
    let repo = UserRepository::new(db);

    repo.create_user("session_user", "hash").await.unwrap();
    let user = repo
        .get_user_by_name("session_user")
        .await
        .unwrap()
        .unwrap();

    repo.create_session(user.id, "token123", "127.0.0.1", 3600)
        .await
        .unwrap();

    let session = repo.get_session("token123").await.unwrap().unwrap();
    assert_eq!(session.session_token, "token123");
    assert_eq!(session.ip_address, "127.0.0.1");

    repo.delete_session("token123").await.unwrap();
    assert!(repo.get_session("token123").await.unwrap().is_none());
}

#[tokio::test]
async fn test_oauth_token_management() {
    let db = setup_test_db().await;
    let repo = UserRepository::new(db);

    repo.create_user("oauth_user", "hash").await.unwrap();
    let user = repo.get_user_by_name("oauth_user").await.unwrap().unwrap();

    repo.create_oauth_client("client1", "secret", "url")
        .await
        .unwrap();

    repo.create_oauth_token(
        "client1",
        user.id,
        "access_1",
        Some("refresh_1"),
        3600,
        "profile",
    )
    .await
    .unwrap();

    let token_model = repo.get_oauth_token("access_1").await.unwrap().unwrap();
    assert_eq!(token_model.access_token, "access_1");

    let token_model_by_refresh = repo.get_oauth_token("refresh_1").await.unwrap().unwrap();
    assert_eq!(token_model_by_refresh.access_token, "access_1");

    repo.delete_oauth_token("access_1").await.unwrap();
    assert!(repo.get_oauth_token("access_1").await.unwrap().is_none());
}
