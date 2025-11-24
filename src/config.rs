//! Configuration types for the vulnera-advisors crate.
//!
//! This module provides configuration structures for all components including
//! sources, storage, and rate limiting.

use crate::error::{AdvisoryError, Result};
use dotenvy::dotenv;
use serde::Deserialize;
use std::env;

/// Main configuration for VulnerabilityManager.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// GitHub Personal Access Token for GHSA API.
    pub ghsa_token: Option<String>,
    /// NVD API key (optional, but recommended for higher rate limits).
    pub nvd_api_key: Option<String>,
    /// Redis/DragonflyDB connection URL.
    pub redis_url: String,
    /// OSS Index configuration (optional).
    #[serde(default)]
    pub ossindex: Option<OssIndexConfig>,
    /// NVD source configuration.
    #[serde(default)]
    pub nvd: NvdConfig,
    /// Store configuration.
    #[serde(default)]
    pub store: StoreConfig,
}

/// Configuration for the NVD source.
#[derive(Debug, Clone, Deserialize)]
pub struct NvdConfig {
    /// Maximum number of requests per time window.
    /// Default: 50 with API key, 5 without.
    pub requests_per_window: Option<u32>,
    /// Time window in seconds for rate limiting.
    /// Default: 30 seconds.
    pub window_seconds: Option<u64>,
    /// Maximum results to fetch per sync (None = unlimited).
    /// Set this to limit initial sync size.
    pub max_results: Option<u32>,
    /// Maximum days to look back for incremental sync.
    /// NVD API has a 120-day limit.
    pub max_days_range: Option<i64>,
}

impl Default for NvdConfig {
    fn default() -> Self {
        Self {
            requests_per_window: None, // Will use 50/5 based on API key
            window_seconds: Some(30),
            max_results: None,
            max_days_range: Some(120),
        }
    }
}

/// Configuration for OSS Index source.
#[derive(Debug, Clone, Deserialize)]
pub struct OssIndexConfig {
    /// OSS Index username (email) for authenticated requests.
    pub user: Option<String>,
    /// OSS Index API token.
    pub token: Option<String>,
    /// Maximum components per batch request (max: 128).
    #[serde(default = "default_ossindex_batch_size")]
    pub batch_size: usize,
}

fn default_ossindex_batch_size() -> usize {
    128
}

impl Default for OssIndexConfig {
    fn default() -> Self {
        Self {
            user: None,
            token: None,
            batch_size: 128,
        }
    }
}

/// Configuration for the advisory store.
#[derive(Debug, Clone, Deserialize)]
pub struct StoreConfig {
    /// TTL in seconds for advisory data (None = no expiration).
    pub ttl_seconds: Option<u64>,
    /// Compression level for zstd (1-22, default: 3).
    #[serde(default = "default_compression_level")]
    pub compression_level: i32,
    /// Prefix for all Redis keys.
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,
}

fn default_compression_level() -> i32 {
    3
}

fn default_key_prefix() -> String {
    "vuln".to_string()
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: None,
            compression_level: 3,
            key_prefix: "vuln".to_string(),
        }
    }
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// # Environment Variables
    ///
    /// - `VULNERA__APIS__GHSA__TOKEN` - GitHub token for GHSA (required for GHSA source)
    /// - `VULNERA__APIS__NVD__API_KEY` - NVD API key (optional)
    /// - `REDIS_URL` - Redis connection URL (default: `redis://127.0.0.1:6379`)
    /// - `OSSINDEX_USER` - OSS Index username (optional)
    /// - `OSSINDEX_TOKEN` - OSS Index token (optional)
    /// - `VULNERA__STORE__TTL_SECONDS` - Advisory TTL in seconds (optional)
    ///
    /// # Errors
    ///
    /// Returns `AdvisoryError::Config` if required variables are missing.
    pub fn from_env() -> Result<Self> {
        dotenv().ok();

        let ghsa_token = env::var("VULNERA__APIS__GHSA__TOKEN").ok();
        let nvd_api_key = env::var("VULNERA__APIS__NVD__API_KEY").ok();

        let redis_url =
            env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        let ossindex = {
            let user = env::var("OSSINDEX_USER").ok();
            let token = env::var("OSSINDEX_TOKEN").ok();
            if user.is_some() || token.is_some() {
                Some(OssIndexConfig {
                    user,
                    token,
                    batch_size: 128,
                })
            } else {
                None
            }
        };

        let ttl_seconds = env::var("VULNERA__STORE__TTL_SECONDS")
            .ok()
            .and_then(|s| s.parse().ok());

        let nvd = NvdConfig {
            requests_per_window: env::var("VULNERA__NVD__REQUESTS_PER_WINDOW")
                .ok()
                .and_then(|s| s.parse().ok()),
            window_seconds: env::var("VULNERA__NVD__WINDOW_SECONDS")
                .ok()
                .and_then(|s| s.parse().ok()),
            max_results: env::var("VULNERA__NVD__MAX_RESULTS")
                .ok()
                .and_then(|s| s.parse().ok()),
            max_days_range: Some(120),
        };

        let store = StoreConfig {
            ttl_seconds,
            compression_level: env::var("VULNERA__STORE__COMPRESSION_LEVEL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),
            key_prefix: env::var("VULNERA__STORE__KEY_PREFIX")
                .unwrap_or_else(|_| "vuln".to_string()),
        };

        Ok(Self {
            ghsa_token,
            nvd_api_key,
            redis_url,
            ossindex,
            nvd,
            store,
        })
    }

    /// Create a minimal configuration for testing.
    pub fn for_testing(redis_url: &str) -> Self {
        Self {
            ghsa_token: None,
            nvd_api_key: None,
            redis_url: redis_url.to_string(),
            ossindex: None,
            nvd: NvdConfig::default(),
            store: StoreConfig::default(),
        }
    }

    /// Validate that required configuration is present for specific sources.
    pub fn validate_for_ghsa(&self) -> Result<&str> {
        self.ghsa_token.as_deref().ok_or_else(|| {
            AdvisoryError::config("GHSA token is required (set VULNERA__APIS__GHSA__TOKEN)")
        })
    }
}
