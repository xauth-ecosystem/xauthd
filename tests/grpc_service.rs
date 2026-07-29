mod common;

use common::{get_test_settings, setup_test_db};
use sea_orm::{ActiveModelTrait, Set};
use std::sync::Arc;
use tonic::Request;
use xauth_core::config::{AuthFlowSettings, Settings};
use xauth_core::db::UserRepository;
use xauth_core::grpc_service::XAuthCoreService;
use xauth_core::xauth_v1::auth_service_server::AuthService;
use xauth_core::xauth_v1::{
    AuthStepRequest, EndSessionRequest, ForcePasswordChangeRequest, OAuthRevokeRequest,
    OAuthTokenRequest, PlayerInfoRequest, SessionRequest,
};

#[tokio::test]
async fn test_process_auth_step_init_register() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let service = XAuthCoreService::new(db, settings);

    let req = Request::new(AuthStepRequest {
        username: "new_player".into(),
        step_type: "init".into(),
        input_data: "".into(),
        ip_address: "127.0.0.1".into(),
        flow_token: "".into(),
        server_id: "test_server".into(),
    });

    let resp = service.process_auth_step(req).await.unwrap().into_inner();

    assert!(resp.success);
    assert_eq!(resp.next_action, "require_password");
    assert!(!resp.flow_token.is_empty());
    assert!(resp.session_token.is_empty());
}

#[tokio::test]
async fn test_process_auth_step_init_login() {
    let db = setup_test_db().await;

    let repo = UserRepository::new(db.clone());
    repo.create_user("existing_player", "hash").await.unwrap();

    let settings = get_test_settings();
    let service = XAuthCoreService::new(db, settings);

    let req = Request::new(AuthStepRequest {
        username: "existing_player".into(),
        step_type: "init".into(),
        input_data: "".into(),
        ip_address: "127.0.0.1".into(),
        flow_token: "".into(),
        server_id: "test_server".into(),
    });

    let resp = service.process_auth_step(req).await.unwrap().into_inner();

    assert!(resp.success);
    assert_eq!(resp.next_action, "require_password");
    assert!(!resp.flow_token.is_empty());
}

#[tokio::test]
async fn test_process_auth_step_password_correct() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let password_hash =
        xauth_core::hash::hash_password("correct_password", &settings.password_hashing).unwrap();

    let repo = UserRepository::new(db.clone());
    repo.create_user("player1", &password_hash).await.unwrap();

    let service = XAuthCoreService::new(db, settings.clone());

    let flow_token =
        xauth_core::jwt::generate_flow_token("player1", "login", 0, &settings.jwt.secret, 600)
            .unwrap();

    let req = Request::new(AuthStepRequest {
        username: "player1".into(),
        step_type: "password".into(),
        input_data: "correct_password".into(),
        ip_address: "127.0.0.1".into(),
        flow_token,
        server_id: "test_server".into(),
    });

    let resp = service.process_auth_step(req).await.unwrap().into_inner();
    assert!(resp.success);
    assert_eq!(resp.message, "Successfully authenticated!");
    assert_eq!(resp.next_action, "authenticated");
    assert!(!resp.session_token.is_empty());
    assert!(resp.flow_token.is_empty());
}

#[tokio::test]
async fn test_process_auth_step_password_incorrect() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let password_hash =
        xauth_core::hash::hash_password("correct_password", &settings.password_hashing).unwrap();

    let repo = UserRepository::new(db.clone());
    repo.create_user("player2", &password_hash).await.unwrap();

    let service = XAuthCoreService::new(db, settings.clone());

    let flow_token =
        xauth_core::jwt::generate_flow_token("player2", "login", 0, &settings.jwt.secret, 600)
            .unwrap();

    let req = Request::new(AuthStepRequest {
        username: "player2".into(),
        step_type: "password".into(),
        input_data: "wrong_password".into(),
        ip_address: "127.0.0.1".into(),
        flow_token,
        server_id: "test_server".into(),
    });

    let resp = service.process_auth_step(req).await.unwrap().into_inner();
    assert!(!resp.success);
    assert_eq!(resp.message, "Invalid password!");
    assert!(!resp.flow_token.is_empty());
}

#[tokio::test]
async fn test_process_auth_step_password_locked_account() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let password_hash =
        xauth_core::hash::hash_password("correct_password", &settings.password_hashing).unwrap();

    let new_user = xauth_core::db::ActiveModel {
        username: Set("locked_player".into()),
        password_hash: Set(password_hash),
        failed_attempts: Set(5),
        is_banned: Set(false),
        must_change_password: Set(false),
        ..Default::default()
    };
    new_user.insert(&db).await.unwrap();

    let service = XAuthCoreService::new(db, settings.clone());

    let flow_token = xauth_core::jwt::generate_flow_token(
        "locked_player",
        "login",
        0,
        &settings.jwt.secret,
        600,
    )
    .unwrap();

    let req = Request::new(AuthStepRequest {
        username: "locked_player".into(),
        step_type: "password".into(),
        input_data: "correct_password".into(),
        ip_address: "127.0.0.1".into(),
        flow_token,
        server_id: "test_server".into(),
    });

    let err = service.process_auth_step(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    assert!(err.message().contains("locked"));
}

#[tokio::test]
async fn test_process_auth_step_register_success() {
    let db = setup_test_db().await;
    let settings = Arc::new(Settings {
        auth_flow: AuthFlowSettings {
            register_chain: vec!["register".into()],
            ..get_test_settings().auth_flow.clone()
        },
        ..get_test_settings().as_ref().clone()
    });
    let service = XAuthCoreService::new(db, settings.clone());

    let flow_token = xauth_core::jwt::generate_flow_token(
        "new_player",
        "register",
        0,
        &settings.jwt.secret,
        600,
    )
    .unwrap();

    let req = Request::new(AuthStepRequest {
        username: "new_player".into(),
        step_type: "register".into(),
        input_data: "my_password".into(),
        ip_address: "127.0.0.1".into(),
        flow_token,
        server_id: "test_server".into(),
    });

    let resp = service.process_auth_step(req).await.unwrap().into_inner();
    assert!(resp.success);
    assert_eq!(resp.message, "Successfully authenticated!");
    assert_eq!(resp.next_action, "authenticated");
    assert!(!resp.session_token.is_empty());
    assert!(resp.flow_token.is_empty());
}

#[tokio::test]
async fn test_process_auth_step_register_user_exists() {
    let db = setup_test_db().await;

    let repo = UserRepository::new(db.clone());
    repo.create_user("existing_player", "hash").await.unwrap();

    let settings = Arc::new(Settings {
        auth_flow: AuthFlowSettings {
            register_chain: vec!["register".into()],
            ..get_test_settings().auth_flow.clone()
        },
        ..get_test_settings().as_ref().clone()
    });
    let service = XAuthCoreService::new(db, settings.clone());

    let flow_token = xauth_core::jwt::generate_flow_token(
        "existing_player",
        "register",
        0,
        &settings.jwt.secret,
        600,
    )
    .unwrap();

    let req = Request::new(AuthStepRequest {
        username: "existing_player".into(),
        step_type: "register".into(),
        input_data: "my_password".into(),
        ip_address: "127.0.0.1".into(),
        flow_token,
        server_id: "test_server".into(),
    });

    let resp = service.process_auth_step(req).await.unwrap().into_inner();
    assert!(!resp.success);
    assert_eq!(resp.message, "User already exists!");
}

#[tokio::test]
async fn test_process_auth_step_totp_skip() {
    let db = setup_test_db().await;
    let settings = Arc::new(Settings {
        auth_flow: AuthFlowSettings {
            login_chain: vec!["password".into(), "totp".into()],
            ..get_test_settings().auth_flow.clone()
        },
        ..get_test_settings().as_ref().clone()
    });

    let repo = UserRepository::new(db.clone());
    repo.create_user("player_no_2fa", "hash").await.unwrap();

    let service = XAuthCoreService::new(db, settings.clone());

    let flow_token = xauth_core::jwt::generate_flow_token(
        "player_no_2fa",
        "login",
        1,
        &settings.jwt.secret,
        600,
    )
    .unwrap();

    let req = Request::new(AuthStepRequest {
        username: "player_no_2fa".into(),
        step_type: "totp".into(),
        input_data: "".into(),
        ip_address: "127.0.0.1".into(),
        flow_token,
        server_id: "test_server".into(),
    });

    let resp = service.process_auth_step(req).await.unwrap().into_inner();
    assert!(resp.success);
    assert_eq!(resp.message, "Successfully authenticated!");
    assert_eq!(resp.next_action, "authenticated");
    assert!(!resp.session_token.is_empty());
    assert!(resp.flow_token.is_empty());
}

#[tokio::test]
async fn test_process_auth_step_custom_step() {
    let db = setup_test_db().await;
    let settings = Arc::new(Settings {
        auth_flow: AuthFlowSettings {
            login_chain: vec!["captcha".into(), "password".into()],
            ..get_test_settings().auth_flow.clone()
        },
        ..get_test_settings().as_ref().clone()
    });
    let service = XAuthCoreService::new(db, settings.clone());

    let flow_token =
        xauth_core::jwt::generate_flow_token("player1", "login", 0, &settings.jwt.secret, 600)
            .unwrap();

    let req = Request::new(AuthStepRequest {
        username: "player1".into(),
        step_type: "captcha_complete".into(),
        input_data: "".into(),
        ip_address: "127.0.0.1".into(),
        flow_token,
        server_id: "test_server".into(),
    });

    let resp = service.process_auth_step(req).await.unwrap().into_inner();
    assert!(resp.success);
    assert!(!resp.flow_token.is_empty());
}

#[tokio::test]
async fn test_validate_session() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());

    repo.create_user("session_user", "hash").await.unwrap();
    let user = repo
        .get_user_by_name("session_user")
        .await
        .unwrap()
        .unwrap();

    let token = xauth_core::jwt::generate_jwt(
        "session_user",
        &settings.jwt.secret,
        settings.jwt.session_ttl,
    )
    .unwrap();

    repo.create_session(
        user.id,
        &token,
        "127.0.0.1",
        settings.jwt.session_ttl as i64,
    )
    .await
    .unwrap();

    let service = XAuthCoreService::new(db, settings);

    let req = Request::new(SessionRequest {
        session_token: token,
        ip_address: "127.0.0.1".into(),
    });

    let resp = service.validate_session(req).await.unwrap().into_inner();
    assert!(resp.is_valid);
    assert_eq!(resp.username, "session_user");
    assert!(resp.expires_at > 0);
}

#[tokio::test]
async fn test_end_session() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());

    repo.create_user("session_user2", "hash").await.unwrap();
    let user = repo
        .get_user_by_name("session_user2")
        .await
        .unwrap()
        .unwrap();

    let token = xauth_core::jwt::generate_jwt(
        "session_user2",
        &settings.jwt.secret,
        settings.jwt.session_ttl,
    )
    .unwrap();

    repo.create_session(
        user.id,
        &token,
        "127.0.0.1",
        settings.jwt.session_ttl as i64,
    )
    .await
    .unwrap();

    let service = XAuthCoreService::new(db, settings);

    let req = Request::new(EndSessionRequest {
        username: "session_user2".into(),
        session_token: token.clone(),
    });

    let resp = service.end_session(req).await.unwrap().into_inner();
    assert!(resp.success);

    let req = Request::new(SessionRequest {
        session_token: token,
        ip_address: "127.0.0.1".into(),
    });

    let resp = service.validate_session(req).await.unwrap().into_inner();
    assert!(!resp.is_valid);
}

#[tokio::test]
async fn test_generate_o_auth_token() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());

    repo.create_oauth_client("my_client", "my_secret", "http://localhost/callback")
        .await
        .unwrap();
    repo.create_user("oauth_user2", "hash").await.unwrap();

    let sub = serde_json::to_string(&serde_json::json!({
        "u": "oauth_user2",
        "c": "my_client",
        "r": "http://localhost/callback"
    }))
    .unwrap();

    let code =
        xauth_core::jwt::generate_jwt(&sub, &settings.jwt.secret, settings.jwt.auth_code_ttl)
            .unwrap();

    let service = XAuthCoreService::new(db, settings.clone());

    let req = Request::new(OAuthTokenRequest {
        client_id: "my_client".into(),
        client_secret: "my_secret".into(),
        code,
        redirect_uri: "http://localhost/callback".into(),
    });

    let resp = service
        .generate_o_auth_token(req)
        .await
        .unwrap()
        .into_inner();
    assert!(resp.success);
    assert!(!resp.access_token.is_empty());
    assert!(!resp.refresh_token.is_empty());
    assert!(resp.expires_in > 0);
}

#[tokio::test]
async fn test_generate_o_auth_token_invalid_client() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let service = XAuthCoreService::new(db, settings);

    let req = Request::new(OAuthTokenRequest {
        client_id: "bad_client".into(),
        client_secret: "bad_secret".into(),
        code: "some_code".into(),
        redirect_uri: "http://localhost/callback".into(),
    });

    let resp = service
        .generate_o_auth_token(req)
        .await
        .unwrap()
        .into_inner();
    assert!(!resp.success);
    assert_eq!(resp.error, "invalid_client");
}

#[tokio::test]
async fn test_generate_o_auth_token_invalid_code() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());

    repo.create_oauth_client("my_client2", "my_secret2", "http://localhost/callback")
        .await
        .unwrap();

    let service = XAuthCoreService::new(db, settings);

    let req = Request::new(OAuthTokenRequest {
        client_id: "my_client2".into(),
        client_secret: "my_secret2".into(),
        code: "not_a_valid_jwt".into(),
        redirect_uri: "http://localhost/callback".into(),
    });

    let resp = service
        .generate_o_auth_token(req)
        .await
        .unwrap()
        .into_inner();
    assert!(!resp.success);
    assert_eq!(resp.error, "invalid_grant");
}

#[tokio::test]
async fn test_revoke_o_auth_token() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let repo = UserRepository::new(db.clone());

    repo.create_oauth_client("client1", "secret1", "http://localhost")
        .await
        .unwrap();
    repo.create_user("oauth_user", "hash").await.unwrap();

    let token = xauth_core::jwt::generate_jwt(
        "oauth_user",
        &settings.jwt.secret,
        settings.jwt.access_token_ttl,
    )
    .unwrap();

    repo.create_oauth_token(
        "client1",
        repo.get_user_by_name("oauth_user")
            .await
            .unwrap()
            .unwrap()
            .id,
        &token,
        None,
        settings.jwt.access_token_ttl as i64,
        "openid",
    )
    .await
    .unwrap();

    let service = XAuthCoreService::new(db.clone(), settings.clone());

    let req = Request::new(OAuthRevokeRequest {
        token: token.clone(),
        client_id: "client1".into(),
    });

    let resp = service.revoke_o_auth_token(req).await.unwrap().into_inner();
    assert!(resp.success);

    let claims = xauth_core::jwt::validate_jwt(&token, &settings.jwt.secret).unwrap();
    assert!(
        repo.is_token_blacklisted(&claims.jti).await.unwrap(),
        "Token should be blacklisted after revocation"
    );
}

#[tokio::test]
async fn test_get_player_info_not_found() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let service = XAuthCoreService::new(db, settings);

    let req = Request::new(PlayerInfoRequest {
        target_username: "unknown".into(),
        requestor_id: "admin".into(),
    });

    let resp = service.get_player_info(req).await.unwrap().into_inner();
    assert!(!resp.exists);
    assert_eq!(resp.username, "unknown");
}

#[tokio::test]
async fn test_get_player_info_exists() {
    let db = setup_test_db().await;

    let repo = UserRepository::new(db.clone());
    repo.create_user("known_user", "hash").await.unwrap();
    let user = repo.get_user_by_name("known_user").await.unwrap().unwrap();
    repo.set_banned(user.id, true).await.unwrap();

    let settings = get_test_settings();
    let service = XAuthCoreService::new(db, settings);

    let req = Request::new(PlayerInfoRequest {
        target_username: "known_user".into(),
        requestor_id: "admin".into(),
    });

    let resp = service.get_player_info(req).await.unwrap().into_inner();
    assert!(resp.exists);
    assert_eq!(resp.username, "known_user");
    assert!(resp.is_banned);
}

#[tokio::test]
async fn test_force_password_change() {
    let db = setup_test_db().await;

    let repo = UserRepository::new(db.clone());
    repo.create_user("force_pw_player", "hash").await.unwrap();

    let settings = get_test_settings();
    let service = XAuthCoreService::new(db.clone(), settings.clone());

    let req = Request::new(ForcePasswordChangeRequest {
        target_username: "force_pw_player".into(),
        immediate_kick: false,
    });

    let resp = service
        .force_password_change(req)
        .await
        .unwrap()
        .into_inner();
    assert!(resp.success);

    let user = repo
        .get_user_by_name("force_pw_player")
        .await
        .unwrap()
        .unwrap();
    assert!(user.must_change_password);
}

#[tokio::test]
async fn test_force_password_change_user_not_found() {
    let db = setup_test_db().await;
    let settings = get_test_settings();
    let service = XAuthCoreService::new(db, settings);

    let req = Request::new(ForcePasswordChangeRequest {
        target_username: "nonexistent".into(),
        immediate_kick: false,
    });

    let resp = service
        .force_password_change(req)
        .await
        .unwrap()
        .into_inner();
    assert!(!resp.success);
}
