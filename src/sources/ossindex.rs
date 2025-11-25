//! OSS Index vulnerability source integration.
//!
//! [OSS Index](https://ossindex.sonatype.org/) provides free vulnerability data
//! for open source components. This module handles querying their REST API with
//! automatic batching (128 components per request), caching, and retry logic.
//!
//! # Authentication
//!
//! OSS Index requires authentication. Set `OSSINDEX_USER` and `OSSINDEX_TOKEN`
//! environment variables, or configure via `OssIndexConfig`.
//!
//! # Example
//!
//! ```rust,ignore
//! use vulnera_advisors::OssIndexSource;
//! use vulnera_advisors::Purl;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let source = OssIndexSource::new(None)?;
//!     
//!     let purls = vec![
//!         Purl::new("npm", "lodash").with_version("4.17.20").to_string(),
//!         Purl::new("pypi", "requests").with_version("2.25.0").to_string(),
//!     ];
//!     
//!     let advisories = source.query_advisories(&purls).await?;
//!     for advisory in advisories {
//!         if let Some(summary) = &advisory.summary {
//!             println!("{}: {}", advisory.id, summary);
//!         }
//!     }
//!     Ok(())
//! }
//! ```

use crate::config::OssIndexConfig;
use crate::error::AdvisoryError;
use crate::models::{
    Advisory, Affected, Event, Package, Range, RangeType, Reference, ReferenceType, Severity,
};
use crate::purl::Purl;
use anyhow::Result;
use reqwest::Client;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

/// Maximum components per batch request (OSS Index limit).
const MAX_BATCH_SIZE: usize = 128;

/// Default concurrent request limit.
const DEFAULT_CONCURRENCY: usize = 4;

/// Request timeout
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Connection timeout
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// OSS Index API base URL.
const API_BASE_URL: &str = "https://ossindex.sonatype.org/api/v3";

/// OSS Index component report request.
#[derive(Debug, Serialize)]
struct ComponentReportRequest {
    coordinates: Vec<String>,
}

/// OSS Index component report response.
#[derive(Debug, Deserialize)]
pub struct ComponentReport {
    pub coordinates: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub vulnerabilities: Vec<OssVulnerability>,
}

/// OSS Index vulnerability entry.
#[derive(Debug, Deserialize, Clone)]
pub struct OssVulnerability {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub title: String,
    pub description: String,
    #[serde(rename = "cvssScore")]
    pub cvss_score: Option<f64>,
    #[serde(rename = "cvssVector")]
    pub cvss_vector: Option<String>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub cve: Option<String>,
    pub reference: String,
    #[serde(rename = "versionRanges")]
    pub version_ranges: Option<Vec<String>>,
    #[serde(rename = "externalReferences")]
    pub external_references: Option<Vec<String>>,
}

/// OSS Index vulnerability source.
///
/// Provides batch querying of vulnerabilities for Package URLs (PURLs)
/// with automatic rate limiting and retry handling.
pub struct OssIndexSource {
    client: ClientWithMiddleware,
    config: OssIndexConfig,
    semaphore: Arc<Semaphore>,
}

impl OssIndexSource {
    /// Create a new OSS Index source with optional configuration.
    ///
    /// If `config` is `None`, configuration is loaded from environment variables.
    pub fn new(config: Option<OssIndexConfig>) -> Result<Self> {
        let config = config.unwrap_or_else(Self::config_from_env);

        let raw_client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .unwrap_or_default();
        
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
        let client = ClientBuilder::new(raw_client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Ok(Self {
            client,
            semaphore: Arc::new(Semaphore::new(DEFAULT_CONCURRENCY)),
            config,
        })
    }

    /// Load configuration from environment variables.
    fn config_from_env() -> OssIndexConfig {
        OssIndexConfig {
            user: env::var("OSSINDEX_USER").ok(),
            token: env::var("OSSINDEX_TOKEN").ok(),
            batch_size: 128,
        }
    }

    /// Create a new OSS Index source with custom concurrency limit.
    pub fn with_concurrency(config: Option<OssIndexConfig>, concurrency: usize) -> Result<Self> {
        let mut source = Self::new(config)?;
        source.semaphore = Arc::new(Semaphore::new(concurrency));
        Ok(source)
    }

    /// Query OSS Index for vulnerabilities affecting the given PURLs.
    ///
    /// This is the main public API for querying vulnerabilities. It handles:
    /// - Automatic batching (128 components per request)
    /// - Parallel requests with rate limiting
    /// - Conversion to canonical `Advisory` format
    ///
    /// # Arguments
    ///
    /// * `purls` - Package URLs to query (e.g., "pkg:npm/lodash@4.17.20")
    ///
    /// # Returns
    ///
    /// Vector of `Advisory` objects for all vulnerabilities found.
    pub async fn query_advisories(&self, purls: &[String]) -> Result<Vec<Advisory>> {
        let reports = self.query_batch(purls).await?;
        Ok(self.convert_reports_to_advisories(&reports))
    }

    /// Query OSS Index for component reports (raw API response).
    ///
    /// Use this if you need access to the full OSS Index response data.
    pub async fn query_components(&self, purls: &[String]) -> Result<Vec<ComponentReport>> {
        self.query_batch(purls).await
    }

    /// Query a batch of PURLs with automatic chunking and parallel execution.
    async fn query_batch(&self, purls: &[String]) -> Result<Vec<ComponentReport>> {
        if purls.is_empty() {
            return Ok(Vec::new());
        }

        let chunks: Vec<_> = purls.chunks(MAX_BATCH_SIZE).collect();
        let mut handles = Vec::with_capacity(chunks.len());

        for chunk in chunks {
            let chunk_vec: Vec<String> = chunk.to_vec();
            let client = self.client.clone();
            let config = self.config.clone();
            let semaphore = self.semaphore.clone();

            handles.push(tokio::spawn(async move {
                let _permit =
                    semaphore
                        .acquire()
                        .await
                        .map_err(|e| AdvisoryError::SourceFetch {
                            source_name: "ossindex".to_string(),
                            message: format!("Semaphore error: {}", e),
                        })?;

                Self::query_chunk(&client, &config, &chunk_vec).await
            }));
        }

        let mut all_reports = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(reports)) => all_reports.extend(reports),
                Ok(Err(e)) => {
                    warn!("OSS Index batch query failed: {}", e);
                    return Err(e);
                }
                Err(e) => {
                    warn!("OSS Index task panicked: {}", e);
                    return Err(AdvisoryError::SourceFetch {
                        source_name: "ossindex".to_string(),
                        message: format!("Task panicked: {}", e),
                    }
                    .into());
                }
            }
        }

        Ok(all_reports)
    }

    /// Query a single chunk of PURLs (up to 128).
    async fn query_chunk(
        client: &ClientWithMiddleware,
        config: &OssIndexConfig,
        purls: &[String],
    ) -> Result<Vec<ComponentReport>> {
        let url = format!("{}/component-report", API_BASE_URL);

        let request = ComponentReportRequest {
            coordinates: purls.to_vec(),
        };

        let mut req_builder = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");

        // Add authentication if configured
        if let (Some(user), Some(token)) = (&config.user, &config.token) {
            req_builder = req_builder.basic_auth(user, Some(token));
        }

        let response = req_builder
            .body(serde_json::to_string(&request)?)
            .send()
            .await
            .map_err(|e| AdvisoryError::SourceFetch {
                source_name: "ossindex".to_string(),
                message: format!("Request failed: {}", e),
            })?;

        let status = response.status();

        // Handle specific error codes
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(AdvisoryError::SourceFetch {
                source_name: "ossindex".to_string(),
                message: "Authentication required. Set OSSINDEX_USER and OSSINDEX_TOKEN environment variables.".to_string(),
            }.into());
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(AdvisoryError::SourceFetch {
                source_name: "ossindex".to_string(),
                message: "Rate limited by OSS Index. Please retry later.".to_string(),
            }
            .into());
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(AdvisoryError::SourceFetch {
                source_name: "ossindex".to_string(),
                message: format!("HTTP {}: {}", status, body),
            }
            .into());
        }

        let reports: Vec<ComponentReport> =
            response
                .json()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "ossindex".to_string(),
                    message: format!("Failed to parse response: {}", e),
                })?;

        debug!("OSS Index returned {} reports", reports.len());
        Ok(reports)
    }

    /// Convert OSS Index reports to canonical Advisory format.
    fn convert_reports_to_advisories(&self, reports: &[ComponentReport]) -> Vec<Advisory> {
        let mut advisories = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();

        for report in reports {
            for vuln in &report.vulnerabilities {
                // Generate a unique advisory ID
                let advisory_id = self.generate_advisory_id(vuln);

                // Deduplicate - same vulnerability may appear in multiple reports
                if seen_ids.contains(&advisory_id) {
                    // Update existing advisory with additional affected package
                    if let Some(advisory) = advisories
                        .iter_mut()
                        .find(|a: &&mut Advisory| a.id == advisory_id)
                    {
                        if let Some(affected) = self.extract_affected(&report.coordinates, vuln) {
                            advisory.affected.push(affected);
                        }
                    }
                    continue;
                }

                seen_ids.insert(advisory_id.clone());

                let advisory = self.convert_vulnerability(vuln, &report.coordinates);
                advisories.push(advisory);
            }
        }

        advisories
    }

    /// Generate a stable advisory ID from OSS Index vulnerability.
    fn generate_advisory_id(&self, vuln: &OssVulnerability) -> String {
        // Prefer CVE if available, otherwise use OSS Index ID
        if let Some(ref cve) = vuln.cve {
            if !cve.is_empty() {
                return cve.clone();
            }
        }

        // Check display_name for CVE pattern
        if let Some(ref name) = vuln.display_name {
            if name.starts_with("CVE-") {
                return name.clone();
            }
        }

        // Extract CVE from reference URL if present
        if let Some(cve) = Self::extract_cve_from_url(&vuln.reference) {
            return cve;
        }

        // Fall back to OSS Index ID (sonatype-YYYY-XXXX format)
        vuln.id.clone()
    }

    /// Extract CVE ID from an OSS Index reference URL.
    fn extract_cve_from_url(url: &str) -> Option<String> {
        // URLs like "https://ossindex.sonatype.org/vulnerability/CVE-2021-23337"
        let parts: Vec<&str> = url.split('/').collect();
        parts
            .last()
            .filter(|id| id.starts_with("CVE-"))
            .map(|s| s.to_string())
    }

    /// Convert a single OSS Index vulnerability to Advisory format.
    fn convert_vulnerability(&self, vuln: &OssVulnerability, coordinates: &str) -> Advisory {
        let mut affected = Vec::new();

        if let Some(aff) = self.extract_affected(coordinates, vuln) {
            affected.push(aff);
        }

        // Collect aliases
        let mut aliases = Vec::new();
        if let Some(ref cve) = vuln.cve {
            if !cve.is_empty() && !cve.starts_with("CVE-") {
                aliases.push(format!("CVE-{}", cve));
            } else if !cve.is_empty() {
                aliases.push(cve.clone());
            }
        }

        // Add OSS Index ID as alias if we're using CVE as primary
        let advisory_id = self.generate_advisory_id(vuln);
        if advisory_id.starts_with("CVE-") && !vuln.id.starts_with("CVE-") {
            aliases.push(vuln.id.clone());
        }

        // Collect references
        let mut references = vec![Reference {
            reference_type: ReferenceType::Advisory,
            url: vuln.reference.clone(),
        }];
        if let Some(ref ext_refs) = vuln.external_references {
            for url in ext_refs {
                references.push(Reference {
                    reference_type: ReferenceType::Web,
                    url: url.clone(),
                });
            }
        }

        // Build database_specific with CVSS and CWE info
        let mut db_specific = serde_json::Map::new();
        if let Some(score) = vuln.cvss_score {
            db_specific.insert("cvss_score".to_string(), serde_json::json!(score));
            db_specific.insert(
                "severity".to_string(),
                serde_json::json!(Self::cvss_to_severity(score)),
            );
        }
        if let Some(ref vector) = vuln.cvss_vector {
            db_specific.insert("cvss_vector".to_string(), serde_json::json!(vector));
        }
        if let Some(ref cwe) = vuln.cwe {
            db_specific.insert("cwe_ids".to_string(), serde_json::json!([cwe]));
        }
        db_specific.insert("source".to_string(), serde_json::json!("ossindex"));

        Advisory {
            id: advisory_id,
            summary: Some(vuln.title.clone()),
            details: Some(vuln.description.clone()),
            affected,
            references,
            published: None,
            modified: None,
            aliases: if aliases.is_empty() {
                None
            } else {
                Some(aliases)
            },
            database_specific: Some(serde_json::Value::Object(db_specific)),
            enrichment: None,
        }
    }

    /// Extract affected package information from PURL and vulnerability.
    fn extract_affected(&self, coordinates: &str, vuln: &OssVulnerability) -> Option<Affected> {
        let purl = Purl::parse(coordinates).ok()?;

        let ranges = vuln
            .version_ranges
            .as_ref()
            .map(|ranges| {
                ranges
                    .iter()
                    .filter_map(|r| Self::parse_version_range(r))
                    .collect()
            })
            .unwrap_or_default();

        Some(Affected {
            package: Package {
                ecosystem: purl.ecosystem(),
                name: purl.name.clone(),
                purl: Some(coordinates.to_string()),
            },
            ranges,
            versions: Vec::new(),
            ecosystem_specific: None,
            database_specific: None,
        })
    }

    /// Parse OSS Index version range to OSV Range format.
    ///
    /// OSS Index uses Maven-style version ranges:
    /// - `[1.0,2.0)` - >= 1.0 and < 2.0
    /// - `[1.0,2.0]` - >= 1.0 and <= 2.0 (inclusive end)
    /// - `(,1.0)` - < 1.0
    /// - `[1.0,)` - >= 1.0
    fn parse_version_range(range: &str) -> Option<Range> {
        let range = range.trim();
        if range.is_empty() {
            return None;
        }

        // Handle single version (exact match)
        if !range.contains(',') && !range.starts_with('[') && !range.starts_with('(') {
            return Some(Range {
                range_type: RangeType::Semver,
                events: vec![Event::LastAffected(range.to_string())],
                repo: None,
            });
        }

        // Parse Maven-style range
        let start_inclusive = range.starts_with('[');
        let end_inclusive = range.ends_with(']');

        // Remove brackets
        let inner = range
            .trim_start_matches(['[', '('])
            .trim_end_matches([']', ')']);

        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() != 2 {
            return None;
        }

        let start = parts[0].trim();
        let end = parts[1].trim();

        let mut events = Vec::new();

        // Handle start bound
        if !start.is_empty() {
            if start_inclusive {
                events.push(Event::Introduced(start.to_string()));
            } else {
                // Exclusive start - technically "after this version"
                // For practical purposes, we still use Introduced
                events.push(Event::Introduced(start.to_string()));
            }
        } else {
            // Open start means introduced at "0" (beginning)
            events.push(Event::Introduced("0".to_string()));
        }

        // Handle end bound
        if !end.is_empty() {
            if end_inclusive {
                // Inclusive end means this version IS affected
                // Use LastAffected
                events.push(Event::LastAffected(end.to_string()));
            } else {
                // Exclusive end - this version is the fix
                events.push(Event::Fixed(end.to_string()));
            }
        }

        Some(Range {
            range_type: RangeType::Semver,
            events,
            repo: None,
        })
    }

    /// Convert CVSS score to severity string.
    fn cvss_to_severity(score: f64) -> &'static str {
        match score {
            s if s >= 9.0 => "CRITICAL",
            s if s >= 7.0 => "HIGH",
            s if s >= 4.0 => "MEDIUM",
            s if s > 0.0 => "LOW",
            _ => "NONE",
        }
    }

    /// Convert CVSS score to Severity enum.
    pub fn score_to_severity(score: f64) -> Severity {
        Severity::from_cvss_score(score)
    }

    /// Get the source name.
    pub fn name(&self) -> &'static str {
        "ossindex"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_range_standard() {
        let range = OssIndexSource::parse_version_range("[1.0.0,2.0.0)");
        assert!(range.is_some());
        let range = range.unwrap();
        assert_eq!(range.range_type, RangeType::Semver);
        assert_eq!(range.events.len(), 2);
        assert!(matches!(&range.events[0], Event::Introduced(v) if v == "1.0.0"));
        assert!(matches!(&range.events[1], Event::Fixed(v) if v == "2.0.0"));
    }

    #[test]
    fn test_parse_version_range_inclusive_end() {
        let range = OssIndexSource::parse_version_range("[1.0.0,2.0.0]");
        assert!(range.is_some());
        let range = range.unwrap();
        assert_eq!(range.events.len(), 2);
        assert!(matches!(&range.events[0], Event::Introduced(v) if v == "1.0.0"));
        assert!(matches!(&range.events[1], Event::LastAffected(v) if v == "2.0.0"));
    }

    #[test]
    fn test_parse_version_range_open_start() {
        let range = OssIndexSource::parse_version_range("(,1.0.0)");
        assert!(range.is_some());
        let range = range.unwrap();
        assert_eq!(range.events.len(), 2);
        assert!(matches!(&range.events[0], Event::Introduced(v) if v == "0"));
        assert!(matches!(&range.events[1], Event::Fixed(v) if v == "1.0.0"));
    }

    #[test]
    fn test_parse_version_range_open_end() {
        let range = OssIndexSource::parse_version_range("[1.0.0,)");
        assert!(range.is_some());
        let range = range.unwrap();
        assert_eq!(range.events.len(), 1);
        assert!(matches!(&range.events[0], Event::Introduced(v) if v == "1.0.0"));
    }

    #[test]
    fn test_parse_version_range_exact() {
        let range = OssIndexSource::parse_version_range("1.0.0");
        assert!(range.is_some());
        let range = range.unwrap();
        assert_eq!(range.events.len(), 1);
        assert!(matches!(&range.events[0], Event::LastAffected(v) if v == "1.0.0"));
    }

    #[test]
    fn test_cvss_to_severity() {
        assert_eq!(OssIndexSource::cvss_to_severity(9.5), "CRITICAL");
        assert_eq!(OssIndexSource::cvss_to_severity(7.5), "HIGH");
        assert_eq!(OssIndexSource::cvss_to_severity(5.0), "MEDIUM");
        assert_eq!(OssIndexSource::cvss_to_severity(2.0), "LOW");
        assert_eq!(OssIndexSource::cvss_to_severity(0.0), "NONE");
    }

    #[test]
    fn test_extract_cve_from_url() {
        assert_eq!(
            OssIndexSource::extract_cve_from_url(
                "https://ossindex.sonatype.org/vulnerability/CVE-2021-23337"
            ),
            Some("CVE-2021-23337".to_string())
        );
        assert_eq!(
            OssIndexSource::extract_cve_from_url(
                "https://ossindex.sonatype.org/vulnerability/sonatype-2020-1234"
            ),
            None
        );
    }

    #[test]
    fn test_purl_integration() {
        let purl = Purl::new("npm", "lodash").with_version("4.17.20");
        assert_eq!(purl.to_string(), "pkg:npm/lodash@4.17.20");
        assert_eq!(purl.ecosystem(), "npm");
        assert_eq!(purl.name, "lodash");
        assert_eq!(purl.version, Some("4.17.20".to_string()));
    }

    #[test]
    fn test_score_to_severity() {
        assert_eq!(OssIndexSource::score_to_severity(9.5), Severity::Critical);
        assert_eq!(OssIndexSource::score_to_severity(7.5), Severity::High);
        assert_eq!(OssIndexSource::score_to_severity(5.0), Severity::Medium);
        assert_eq!(OssIndexSource::score_to_severity(2.0), Severity::Low);
        assert_eq!(OssIndexSource::score_to_severity(0.0), Severity::None);
    }
}
