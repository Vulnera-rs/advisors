//! Vulnerability data sources.
//!
//! This module contains implementations for fetching advisories from various
//! vulnerability databases. Each source implements the [`AdvisorySource`] trait.
//!
//! # Available Sources
//!
//! - [`ghsa::GHSASource`] - GitHub Security Advisories (requires GitHub token)
//! - [`nvd::NVDSource`] - NIST National Vulnerability Database
//! - [`osv::OSVSource`] - Open Source Vulnerabilities (Google)
//! - [`kev::KevSource`] - CISA Known Exploited Vulnerabilities
//! - [`epss::EpssSource`] - FIRST Exploit Prediction Scoring System
//! - [`ossindex::OssIndexSource`] - Sonatype OSS Index

pub mod epss;
pub mod ghsa;
pub mod kev;
pub mod nvd;
pub mod ossindex;
pub mod osv;

use crate::error::Result;
use crate::models::Advisory;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Trait for vulnerability advisory data sources.
///
/// Implement this trait to add support for a new vulnerability database.
///
/// # Example
///
/// ```ignore
/// use vulnera_advisors::sources::AdvisorySource;
/// use vulnera_advisors::models::Advisory;
/// use async_trait::async_trait;
///
/// struct MySource;
///
/// #[async_trait]
/// impl AdvisorySource for MySource {
///     async fn fetch(&self, since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>> {
///         // Fetch advisories from your source
///         Ok(vec![])
///     }
///
///     fn name(&self) -> &str {
///         "MySource"
///     }
/// }
/// ```
#[async_trait]
pub trait AdvisorySource: Send + Sync {
    /// Fetch advisories, optionally since a given timestamp.
    ///
    /// If `since` is provided, implementations should attempt to return only
    /// advisories modified after that timestamp (incremental sync).
    /// If `since` is `None`, implementations should return all advisories (full sync).
    async fn fetch(&self, since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>>;

    /// Get the name of this source (used for logging and metadata).
    fn name(&self) -> &str;
}
