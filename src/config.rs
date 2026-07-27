use config::{Config, ConfigError, File};
use serde::Deserialize;
use std::path::Path;

const DEFAULT_CONFIG: &str = include_str!("../xauthd.example.toml");

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseSettings {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkSettings {
    pub grpc_address: String,
    pub web_address: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BcryptSettings {
    pub cost: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Argon2idSettings {
    pub memory_cost: u32,
    pub time_cost: u32,
    pub threads: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PasswordHashingOptions {
    #[serde(rename = "BCRYPT")]
    pub bcrypt: Option<BcryptSettings>,
    #[serde(rename = "ARGON2ID")]
    pub argon2id: Option<Argon2idSettings>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PasswordHashingSettings {
    pub algorithm: String,
    pub options: Option<PasswordHashingOptions>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtSettings {
    pub secret: String,
    pub rsa_private_key_path: String,
    pub session_ttl: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub database: DatabaseSettings,
    pub network: NetworkSettings,
    pub password_hashing: PasswordHashingSettings,
    pub jwt: JwtSettings,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        if !Path::new("xauthd.toml").exists() {
            tracing::info!("xauthd.toml not found, generating default configuration...");
            if let Err(e) = std::fs::write("xauthd.toml", DEFAULT_CONFIG) {
                tracing::warn!("Failed to create default xauthd.toml: {}", e);
            }
        }

        let s = Config::builder()
            .add_source(File::with_name("xauthd").required(true))
            .build()?;

        s.try_deserialize()
    }
}
