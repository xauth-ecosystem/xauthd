use config::{Config, ConfigError, File};
use serde::Deserialize;
use std::path::Path;

const DEFAULT_CONFIG: &str = include_str!("../xauthd.example.toml");

#[derive(Debug, Deserialize)]
pub struct DatabaseSettings {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct NetworkSettings {
    pub grpc_address: String,
    pub web_address: String,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub database: DatabaseSettings,
    pub network: NetworkSettings,
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
