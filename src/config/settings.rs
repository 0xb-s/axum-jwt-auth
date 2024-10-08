// src/config/settings.rs

use config;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub jwt: JwtSettings,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtSettings {
    // Maps to JWT_SECRET environment variable
    #[serde(rename = "JWT_SECRET")]
    pub secret: String,
    // Maps to JWT_ISSUER environment variable
    #[serde(rename = "JWT_ISSUER")]
    pub issuer: String,
    // Maps to JWT_EXPIRATION_SECONDS environment variable
    #[serde(rename = "JWT_EXPIRATION_SECONDS")]
    pub expiration_seconds: usize,
    // Maps to JWT_ALGORITHM environment variable
    #[serde(rename = "JWT_ALGORITHM")]
    pub algorithm: JwtAlgorithm,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum JwtAlgorithm {
    HS256,
    RS256,
}

impl Settings {
    pub fn new() -> Result<Self, config::ConfigError> {
        let mut cfg = config::Config::default();

        cfg.merge(
            config::Environment::with_prefix("APP")
                .separator("_")
                .try_parsing(true),
        )?;

        cfg.try_deserialize()
    }
}
