//! Sonatype OSS Index source.
//!
//! This module queries the OSS Index API to find vulnerabilities for specific
//! package coordinates (PURLs).
//!
//! # Data Source
//!
//! - API: <https://ossindex.sonatype.org/api/v3/>
//! - Documentation: <https://ossindex.sonatype.org/doc/rest>
//! - Rate Limits: Unauthenticated requests are rate-limited; use credentials for higher limits

use crate::error::{AdvisoryError, Result};
use crate::models::{
    Advisory, Affected, Event, Package, Range, RangeType, Reference, ReferenceType,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::AdvisorySource;

/// Base URL for OSS Index API.
pub const OSSINDEX_API_URL: &str = "https://ossindex.sonatype.org/api/v3";

/// Maximum components per request (API limit).
pub const MAX_BATCH_SIZE: usize = 128;

/// OSS Index source configuration.
#[derive(Debug, Clone, Default)]
pub struct OssIndexConfig {
    /// Username (email) for authenticated requests.
    pub user: Option<String>,
    /// API token for authenticated requests.
    pub token: Option<String>,
    /// Batch size for component requests (max 128).
    pub batch_size: usize,
}

/// OSS Index vulnerability source.
///
/// Queries the Sonatype OSS Index for known vulnerabilities affecting
/// specific package coordinates.
pub struct OssIndexSource {
    client: reqwest::Client,
    config: OssIndexConfig,
}

impl OssIndexSource {
    /// Create a new OSS Index source with default configuration.
    pub fn new() -> Self {
        Self::with_config(OssIndexConfig {
            batch_size: MAX_BATCH_SIZE,
            ..Default::default()
        })
    }

    /// Create a new OSS Index source with authentication.
    pub fn with_auth(user: String, token: String) -> Self {
        Self::with_config(OssIndexConfig {
            user: Some(user),
            token: Some(token),
            batch_size: MAX_BATCH_SIZE,
        })
    }

    /// Create a new OSS Index source with custom configuration.
    pub fn with_config(config: OssIndexConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
        }
    }

    /// Query OSS Index for vulnerabilities affecting the given PURLs.
    ///
    /// # Arguments
    ///
    /// * `purls` - Package URLs to check (e.g., "pkg:npm/lodash@4.17.20")
    ///
    /// # Returns
    ///
    /// Component reports with vulnerability information.
    pub async fn query_components(&self, purls: &[&str]) -> Result<Vec<ComponentReport>> {
        if purls.is_empty() {
            return Ok(Vec::new());
        }

        let batch_size = self.config.batch_size.min(MAX_BATCH_SIZE);
        let mut all_reports = Vec::new();

        for chunk in purls.chunks(batch_size) {
            let reports = self.query_batch(chunk).await?;
            all_reports.extend(reports);
        }

        Ok(all_reports)
    }

    /// Query a single batch of components.
    async fn query_batch(&self, purls: &[&str]) -> Result<Vec<ComponentReport>> {
        let url = format!("{}/component-report", OSSINDEX_API_URL);

        let request_body = ComponentReportRequest {
            coordinates: purls.iter().map(|s| s.to_string()).collect(),
        };

        debug!("Querying OSS Index for {} components", purls.len());

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let mut request = self.client.post(&url).headers(headers).json(&request_body);

        // Add authentication if configured
        if let (Some(user), Some(token)) = (&self.config.user, &self.config.token) {
            request = request.basic_auth(user, Some(token));
        }

        let response = request.send().await?;

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(AdvisoryError::rate_limit(
                "OSSIndex",
                "Rate limit exceeded. Consider using authentication for higher limits.",
            ));
        }

        if !response.status().is_success() {
            return Err(AdvisoryError::source_fetch(
                "OSSIndex",
                format!("HTTP {}", response.status()),
            ));
        }

        let reports: Vec<ComponentReport> = response.json().await?;
        debug!("Received {} component reports", reports.len());

        Ok(reports)
    }

    /// Convert OSS Index vulnerabilities to canonical Advisory format.
    #[allow(dead_code)]
    fn convert_to_advisories(&self, reports: Vec<ComponentReport>) -> Vec<Advisory> {
        let mut advisories = Vec::new();

        for report in reports {
            for vuln in report.vulnerabilities {
                let advisory = self.convert_vulnerability(&report.coordinates, vuln);
                advisories.push(advisory);
            }
        }

        advisories
    }

    /// Convert a single OSS Index vulnerability to Advisory format.
    #[allow(dead_code)]
    fn convert_vulnerability(&self, purl: &str, vuln: OssVulnerability) -> Advisory {
        // Parse PURL to extract ecosystem and package name
        let (ecosystem, name) = parse_purl_components(purl);

        let affected = vec![Affected {
            package: Package {
                ecosystem: ecosystem.clone(),
                name: name.clone(),
                purl: Some(purl.to_string()),
            },
            ranges: vuln
                .version_ranges
                .as_ref()
                .map(|ranges| {
                    ranges
                        .iter()
                        .filter_map(|r| parse_version_range(r))
                        .collect()
                })
                .unwrap_or_default(),
            versions: vec![],
            ecosystem_specific: None,
            database_specific: Some(serde_json::json!({
                "ossindex_id": vuln.id,
                "cwe": vuln.cwe,
            })),
        }];

        let references = vec![Reference {
            reference_type: ReferenceType::Advisory,
            url: vuln.reference.clone(),
        }];

        // Extract CVE if present in the ID or reference
        let aliases = extract_cve_alias(&vuln.id, &vuln.reference, &vuln.title);

        Advisory {
            id: vuln.id,
            summary: Some(vuln.title),
            details: vuln.description,
            affected,
            references,
            published: None,
            modified: None,
            aliases,
            database_specific: Some(serde_json::json!({
                "source": "OSSIndex",
                "cvss_score": vuln.cvss_score,
                "cvss_vector": vuln.cvss_vector,
            })),
            enrichment: None,
        }
    }
}

impl Default for OssIndexSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AdvisorySource for OssIndexSource {
    async fn fetch(&self, _since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>> {
        // OSS Index doesn't support fetching all vulnerabilities.
        // It's designed for querying specific packages.
        // Return empty - this source is used for on-demand queries.
        warn!("OSSIndex doesn't support bulk fetch. Use query_components() instead.");
        Ok(Vec::new())
    }

    fn name(&self) -> &str {
        "OSSIndex"
    }
}

/// Request body for component report API.
#[derive(Debug, Serialize)]
struct ComponentReportRequest {
    coordinates: Vec<String>,
}

/// Response from the component report API.
#[derive(Debug, Clone, Deserialize)]
pub struct ComponentReport {
    /// Package URL coordinates.
    pub coordinates: String,
    /// Description of the component.
    pub description: Option<String>,
    /// Reference URL for the component.
    pub reference: Option<String>,
    /// List of vulnerabilities affecting this component.
    #[serde(default)]
    pub vulnerabilities: Vec<OssVulnerability>,
}

/// A vulnerability from OSS Index.
#[derive(Debug, Clone, Deserialize)]
pub struct OssVulnerability {
    /// OSS Index vulnerability ID.
    pub id: String,
    /// Display name/title.
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    /// Vulnerability title.
    pub title: String,
    /// Detailed description.
    pub description: Option<String>,
    /// CVSS score (0.0 - 10.0).
    #[serde(rename = "cvssScore")]
    pub cvss_score: Option<f64>,
    /// CVSS vector string.
    #[serde(rename = "cvssVector")]
    pub cvss_vector: Option<String>,
    /// CWE identifier.
    pub cwe: Option<String>,
    /// CVE identifier if known.
    pub cve: Option<String>,
    /// Reference URL.
    pub reference: String,
    /// Affected version ranges.
    #[serde(rename = "versionRanges")]
    pub version_ranges: Option<Vec<String>>,
    /// External references.
    #[serde(rename = "externalReferences")]
    pub external_references: Option<Vec<String>>,
}

/// Parse PURL to extract ecosystem and package name.
#[allow(dead_code)]
fn parse_purl_components(purl: &str) -> (String, String) {
    // Format: pkg:type/namespace/name@version?qualifiers#subpath
    // or pkg:type/name@version
    if let Some(rest) = purl.strip_prefix("pkg:") {
        let parts: Vec<&str> = rest.splitn(2, '/').collect();
        if parts.len() >= 2 {
            let ecosystem = parts[0].to_string();
            let name_part = parts[1];

            // Remove version if present
            let name = name_part.split('@').next().unwrap_or(name_part).to_string();

            return (ecosystem, name);
        }
    }

    ("unknown".to_string(), purl.to_string())
}

/// Parse OSS Index version range to our Range format.
#[allow(dead_code)]
fn parse_version_range(range_str: &str) -> Option<Range> {
    // OSS Index uses Maven-style version ranges like "[1.0,2.0)" or "(,1.5]"
    // This is a simplified parser
    let range_str = range_str.trim();

    if range_str.is_empty() {
        return None;
    }

    let mut events = Vec::new();

    // Parse range bounds
    let _is_lower_inclusive = range_str.starts_with('[');
    let _is_upper_inclusive = range_str.ends_with(']');

    let inner = range_str
        .trim_start_matches(['[', '('])
        .trim_end_matches([']', ')']);

    let parts: Vec<&str> = inner.split(',').collect();

    match parts.as_slice() {
        [lower, upper] => {
            let lower = lower.trim();
            let upper = upper.trim();

            if !lower.is_empty() {
                events.push(Event::Introduced(lower.to_string()));
            } else {
                events.push(Event::Introduced("0".to_string()));
            }

            if !upper.is_empty() {
                events.push(Event::Fixed(upper.to_string()));
            }
        }
        [single] => {
            let single = single.trim();
            if !single.is_empty() {
                events.push(Event::Introduced(single.to_string()));
            }
        }
        _ => return None,
    }

    if events.is_empty() {
        return None;
    }

    Some(Range {
        range_type: RangeType::Ecosystem,
        events,
        repo: None,
    })
}

/// Extract CVE alias from OSS Index data.
#[allow(dead_code)]
fn extract_cve_alias(id: &str, reference: &str, title: &str) -> Option<Vec<String>> {
    let mut aliases = Vec::new();

    // Check for CVE pattern in various fields
    let cve_pattern = regex_lite::Regex::new(r"CVE-\d{4}-\d+").ok()?;

    for text in [id, reference, title] {
        if let Some(m) = cve_pattern.find(text) {
            let cve = m.as_str().to_string();
            if !aliases.contains(&cve) {
                aliases.push(cve);
            }
        }
    }

    if aliases.is_empty() {
        None
    } else {
        Some(aliases)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_purl() {
        let (eco, name) = parse_purl_components("pkg:npm/lodash@4.17.20");
        assert_eq!(eco, "npm");
        assert_eq!(name, "lodash");

        let (eco, name) = parse_purl_components("pkg:maven/org.apache.struts/struts2-core@2.5.30");
        assert_eq!(eco, "maven");
        assert_eq!(name, "org.apache.struts/struts2-core");
    }

    #[test]
    fn test_parse_version_range() {
        let range = parse_version_range("[1.0,2.0)").unwrap();
        assert_eq!(range.events.len(), 2);

        let range = parse_version_range("(,1.5]").unwrap();
        assert_eq!(range.events.len(), 2);
    }
}
