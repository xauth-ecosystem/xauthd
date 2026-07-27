use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize)]
pub struct DatabaseSettings {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub database: DatabaseSettings,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        let s = Config::builder()
            // Start off by merging in the "default" configuration file
            .add_source(File::with_name("xauthd").required(false))
            // Add in the current environment file
            // Default to 'development' env
            // Note that this file is _optional_
            .add_source(File::with_name(&format!("xauthd.{}", run_mode)).required(false))
            // Add in settings from the environment (with a prefix of XAUTHD)
            // Eg.. `XAUTHD_DATABASE__URL=...` would set `database.url`
            .add_source(Environment::with_prefix("XAUTHD").separator("__"))
            // We also want to support the legacy DATABASE_URL env var directly for convenience
            .build()?;

        // If DATABASE_URL is set in the environment directly, we can override the loaded config manually
        // or just let the app parse it. Since we want to parse it all into `Settings`, we can do a trick:
        let mut settings: Settings = s.try_deserialize()?;
        
        if let Ok(db_url) = env::var("DATABASE_URL") {
            settings.database.url = db_url;
        }

        Ok(settings)
    }
}
