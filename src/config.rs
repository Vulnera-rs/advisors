use anyhow::Result;
use dotenvy::dotenv;
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub ghsa_token: String,
    pub nvd_api_key: Option<String>,
    pub redis_url: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenv().ok();

        let ghsa_token =
            env::var("VULNERA__APIS__GHSA__TOKEN").expect("VULNERA__APIS__GHSA__TOKEN must be set");

        let nvd_api_key = env::var("VULNERA__APIS__NVD__API_KEY").ok();

        let redis_url =
            env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        Ok(Self {
            ghsa_token,
            nvd_api_key,
            redis_url,
        })
    }
}
