#![allow(dead_code)]

use sea_orm::{ConnectionTrait, Database, DatabaseConnection, Schema};
use std::sync::Arc;
use xauth_core::config::{
    AuthFlowSettings, DatabaseSettings, JwtSettings, NetworkSettings, PasswordHashingSettings,
    SecuritySettings, Settings, TotpSettings, WebSettings,
};

pub async fn setup_test_db() -> DatabaseConnection {
    let path = format!("/tmp/xauthd_test_{}.sqlite", uuid::Uuid::new_v4());
    let db_uri = format!("sqlite://{}?mode=rwc", path);
    let db = Database::connect(&db_uri).await.unwrap();
    let builder = db.get_database_backend();
    let schema = Schema::new(builder);
    use xauth_core::db::Entity as UserEntity;

    let stmts = vec![
        schema.create_table_from_entity(UserEntity),
        schema.create_table_from_entity(xauth_core::db::sessions::Entity),
        schema.create_table_from_entity(xauth_core::db::token_blacklist::Entity),
        schema.create_table_from_entity(xauth_core::db::oauth_clients::Entity),
        schema.create_table_from_entity(xauth_core::db::oauth_tokens::Entity),
    ];

    for stmt in stmts {
        db.execute(&stmt).await.unwrap();
    }

    db
}

pub fn get_test_settings() -> Arc<Settings> {
    Arc::new(Settings {
        database: DatabaseSettings { url: "".into() },
        network: NetworkSettings {
            grpc_address: "".into(),
            web_address: "".into(),
        },
        password_hashing: PasswordHashingSettings {
            algorithm: "BCRYPT".into(),
            options: None,
        },
        jwt: JwtSettings {
            secret: "test_secret".into(),
            rsa_private_key_path: format!(
                "/tmp/xauthd_test_rsa_{}_{}.pem",
                std::process::id(),
                uuid::Uuid::new_v4()
            ),
            session_ttl: 3600,
            auth_code_ttl: 3600,
            access_token_ttl: 3600,
            refresh_token_ttl: 3600,
        },
        security: SecuritySettings {
            max_failed_attempts: 5,
            failed_attempts_reset_interval: 3600,
        },
        auth_flow: AuthFlowSettings {
            register_chain: vec!["password".into()],
            login_chain: vec!["password".into()],
            max_attempts_per_step: 3,
        },
        web: WebSettings {
            templates_dir: "templates".into(),
            public_dir: None,
        },
        totp: TotpSettings { required: false },
    })
}
