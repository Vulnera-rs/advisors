//! Error types for the vulnera-advisors crate.
//!
//! This module provides a comprehensive error type [`AdvisoryError`] that covers
//! all failure modes in the library, enabling proper error handling.

use std::io;

/// The main error type for all operations in this crate.
#[derive(Debug, thiserror::Error)]
pub enum AdvisoryError {
    /// Redis/DragonflyDB connection or operation failed.
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    /// Failed to fetch data from an advisory source.
    #[error("Source '{source_name}' fetch failed: {message}")]
    SourceFetch {
        /// Name of the source that failed (e.g., "GHSA", "NVD", "OSV").
        source_name: String,
        /// Description of what went wrong.
        message: String,
    },

    /// Configuration error (missing or invalid values).
    #[error("Configuration error: {0}")]
    Config(String),

    /// JSON serialization/deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Compression or decompression failed.
    #[error("Compression error: {0}")]
    Compression(String),

    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// HTTP request via middleware failed.
    #[error("HTTP middleware error: {0}")]
    HttpMiddleware(#[from] reqwest_middleware::Error),

    /// Rate limit exceeded.
    #[error("Rate limit exceeded for source '{source_name}': {message}")]
    RateLimit {
        /// Name of the source that hit rate limits.
        source_name: String,
        /// Additional details about the rate limit.
        message: String,
    },

    /// I/O error (file operations, etc.).
    #[error("I/O error: {0}")]
    Io(io::Error),

    /// Version parsing failed.
    #[error("Invalid version '{version}': {message}")]
    VersionParse {
        /// The version string that failed to parse.
        version: String,
        /// Why parsing failed.
        message: String,
    },

    /// ZIP archive error.
    #[error("ZIP error: {0}")]
    Zip(#[from] zip::result::ZipError),

    /// Task join error (from spawned tasks).
    #[error("Task join error: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),

    /// GraphQL API error.
    #[error("GraphQL error: {0}")]
    GraphQL(String),
}

/// A specialized Result type for advisory operations.
pub type Result<T> = std::result::Result<T, AdvisoryError>;

impl AdvisoryError {
    /// Create a new source fetch error.
    pub fn source_fetch(source: impl Into<String>, message: impl Into<String>) -> Self {
        Self::SourceFetch {
            source_name: source.into(),
            message: message.into(),
        }
    }

    /// Create a new configuration error.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Create a new compression error.
    pub fn compression(message: impl Into<String>) -> Self {
        Self::Compression(message.into())
    }

    /// Create a new rate limit error.
    pub fn rate_limit(source: impl Into<String>, message: impl Into<String>) -> Self {
        Self::RateLimit {
            source_name: source.into(),
            message: message.into(),
        }
    }

    /// Create a new version parse error.
    pub fn version_parse(version: impl Into<String>, message: impl Into<String>) -> Self {
        Self::VersionParse {
            version: version.into(),
            message: message.into(),
        }
    }

    /// Create a new GraphQL error.
    pub fn graphql(message: impl Into<String>) -> Self {
        Self::GraphQL(message.into())
    }

    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Http(_) | Self::HttpMiddleware(_) | Self::RateLimit { .. } | Self::Redis(_)
        )
    }
}

// Convert from zstd errors
impl From<std::io::Error> for AdvisoryError {
    fn from(err: std::io::Error) -> Self {
        // Check if it's a compression-related error
        if err.to_string().contains("zstd") || err.to_string().contains("compress") {
            Self::Compression(err.to_string())
        } else {
            Self::Io(err)
        }
    }
}
