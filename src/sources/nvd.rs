use super::AdvisorySource;
use crate::error::Result;
use crate::models::{Advisory, Reference, ReferenceType};
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use cpe::cpe::Cpe;
use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use once_cell::sync::Lazy;
use regex_lite::Regex;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use serde::{Deserialize, Deserializer};
use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Custom deserializer for NVD datetime format (e.g., "2024-01-15T10:30:00.000")
fn deserialize_nvd_datetime<'de, D>(deserializer: D) -> std::result::Result<DateTime<Utc>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;

    // O1
    if let Ok(naive) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S%.3f") {
        return Ok(naive.and_utc());
    }

    // O2
    if let Ok(naive) = NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(naive.and_utc());
    }

    // O3
    if let Ok(dt) = DateTime::parse_from_rfc3339(&s) {
        return Ok(dt.with_timezone(&Utc));
    }

    Err(serde::de::Error::custom(format!(
        "Failed to parse NVD datetime: {}",
        s
    )))
}

static GHSA_REGEX: Lazy<Result<Regex, regex_lite::Error>> =
    Lazy::new(|| Regex::new(r"(?i)(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})"));
static OSV_REGEX: Lazy<Result<Regex, regex_lite::Error>> =
    Lazy::new(|| Regex::new(r"(?i)osv\.dev/vulnerability/([^/?#]+)"));
static CVE_REGEX: Lazy<Result<Regex, regex_lite::Error>> =
    Lazy::new(|| Regex::new(r"(?i)(CVE-\d{4}-\d{4,})"));

pub struct NVDSource {
    api_key: Option<String>,
    client: ClientWithMiddleware,
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>,
    /// Maximum number of CVEs to fetch (None = unlimited)
    max_results: Option<u32>,
    /// Optional API URL (useful for tests / mocks)
    api_url: Option<String>,
}

impl NVDSource {
    pub fn new(api_key: Option<String>) -> Self {
        Self::with_max_results(api_key, None)
    }

    /// Create a new NVD source with a maximum result limit.
    ///
    /// Use `None` for unlimited results (will fetch all ~320k CVEs on full sync).
    /// Use `Some(n)` to limit to n results (useful for testing).
    pub fn with_max_results(api_key: Option<String>, max_results: Option<u32>) -> Self {
        // Build raw client with timeout
        let raw_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .connect_timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        // Retry policy: 3 retries with exponential backoff
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
        let client = ClientBuilder::new(raw_client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        // Rate limiter: 50 req / 30 sec (with key) or 5 req / 30 sec (without)
        let (requests, seconds) = if api_key.is_some() { (50, 30) } else { (5, 30) };

        let quota = Quota::with_period(std::time::Duration::from_secs(seconds))
            .unwrap()
            .allow_burst(NonZeroU32::new(requests).unwrap());

        let limiter = Arc::new(RateLimiter::direct(quota));

        Self {
            api_key,
            client,
            limiter,
            max_results,
            api_url: None,
        }
    }

    /// Override the API base URL (useful for mock servers in tests)
    pub fn with_api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = Some(api_url.into());
        self
    }
}

#[async_trait]
impl AdvisorySource for NVDSource {
    async fn fetch(&self, since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>> {
        let base_url = self
            .api_url
            .as_deref()
            .unwrap_or("https://services.nvd.nist.gov/rest/json/cves/2.0");
        let mut advisories = Vec::new();
        let mut start_index = 0;
        let results_per_page = 2000; // Max allowed by NVD

        loop {
            let mut url = format!(
                "{}?startIndex={}&resultsPerPage={}",
                base_url, start_index, results_per_page
            );

            if let Some(since) = since {
                // NVD has a 120-day maximum range restriction
                let now = Utc::now();
                let duration = now.signed_duration_since(since);
                let max_days = 120;

                // NVD requires ISO 8601 format: YYYY-MM-DDTHH:MM:SS.sss
                let format_nvd_date = |dt: DateTime<Utc>| -> String {
                    dt.format("%Y-%m-%dT%H:%M:%S%.3f").to_string()
                };

                if duration.num_days() > max_days {
                    // If range exceeds 120 days, we need to chunk
                    warn!(
                        "NVD sync: Last sync was {} days ago (max: {}). Only fetching last {} days.",
                        duration.num_days(),
                        max_days,
                        max_days
                    );
                    let start = now - chrono::Duration::days(max_days);
                    url.push_str(&format!(
                        "&lastModStartDate={}&lastModEndDate={}",
                        format_nvd_date(start),
                        format_nvd_date(now)
                    ));
                } else {
                    // Normal case: range is within limit
                    url.push_str(&format!(
                        "&lastModStartDate={}&lastModEndDate={}",
                        format_nvd_date(since),
                        format_nvd_date(now)
                    ));
                }
            }
            // Wait for rate limiter
            self.limiter.until_ready().await;

            debug!("Fetching NVD data from startIndex={}", start_index);

            let mut request = self.client.get(&url);
            if let Some(key) = &self.api_key {
                request = request.header("apiKey", key);
            }

            let response = request.send().await?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(crate::error::AdvisoryError::source_fetch(
                    "NVD",
                    format!(
                        "HTTP {}: {}",
                        status,
                        body.chars().take(200).collect::<String>()
                    ),
                ));
            }

            let nvd_response: NvdResponse = response.json().await?;
            let total_results = nvd_response.total_results;
            let count = nvd_response.vulnerabilities.len();

            for item in nvd_response.vulnerabilities {
                let cve = item.cve;

                let mut affected = Vec::new();

                // Parse configurations to find CPEs
                if let Some(configurations) = cve.configurations {
                    for config in configurations {
                        for node in config.nodes {
                            for cpe_match in node.cpe_match {
                                if cpe_match.vulnerable {
                                    if let Ok(cpe_uri) = cpe::uri::Uri::parse(&cpe_match.criteria) {
                                        let vendor = cpe_uri.vendor().to_string();
                                        let product = cpe_uri.product().to_string();
                                        let version = cpe_uri.version().to_string();

                                        // Very basic heuristic
                                        let ecosystem = if vendor == "apache" {
                                            "maven"
                                        } else if vendor == "npm" {
                                            "npm"
                                        } else {
                                            "generic"
                                        };

                                        let purl = packageurl::PackageUrl::new(ecosystem, &product)
                                            .ok()
                                            .map(|mut p| {
                                                if !version.is_empty() && version != "*" {
                                                    let _ = p.with_version(version.clone());
                                                }
                                                if ecosystem == "maven" {
                                                    let _ = p.with_namespace(vendor.clone());
                                                }
                                                p.to_string()
                                            });

                                        affected.push(crate::models::Affected {
                                            package: crate::models::Package {
                                                ecosystem: ecosystem.to_string(),
                                                name: product,
                                                purl,
                                            },
                                            ranges: vec![], // NVD ranges are complex, skipping for now
                                            versions: vec![version],
                                            ecosystem_specific: None,
                                            database_specific: Some(serde_json::json!({
                                                "cpe": cpe_match.criteria
                                            })),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                let references = cve
                    .references
                    .iter()
                    .map(|r| Reference {
                        reference_type: ReferenceType::Web,
                        url: r.url.clone(),
                    })
                    .collect();

                // Build alias set from references (e.g., GHSA / OSV IDs) and dedupe
                let mut alias_set: HashSet<String> = HashSet::new();
                for r in &cve.references {
                    // GHSA: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
                    if let Ok(ghsa_regex) = &*GHSA_REGEX {
                        if let Some(caps) = ghsa_regex.captures(&r.url) {
                            alias_set.insert(caps[1].to_uppercase());
                        }
                    }

                    // OSV: https://osv.dev/vulnerability/<id>
                    if let Ok(osv_regex) = &*OSV_REGEX {
                        if let Some(caps) = osv_regex.captures(&r.url) {
                            let osv_id = caps[1].to_string();
                            // If the OSV id looks like a CVE, don't add it here (CVE already present)
                            let is_cve = if let Ok(cve_regex) = &*CVE_REGEX {
                                cve_regex.captures(&osv_id).is_some()
                            } else {
                                false
                            };
                            if !is_cve {
                                alias_set.insert(osv_id);
                            }
                        }
                    }
                }

                let aliases_field = if alias_set.is_empty() {
                    None
                } else {
                    Some(alias_set.into_iter().collect())
                };

                advisories.push(Advisory {
                    id: cve.id,
                    summary: None,
                    details: cve.descriptions.first().map(|d| d.value.clone()),
                    affected,
                    references,
                    published: Some(cve.published),
                    modified: Some(cve.last_modified),
                    aliases: aliases_field,
                    database_specific: Some(serde_json::json!({
                        "source": "NVD",
                        "metrics": cve.metrics,
                    })),
                    enrichment: None,
                });
            }

            start_index += count as u32;
            if start_index >= total_results {
                break;
            }

            // Optional limit on results (useful for testing or incremental loading)
            if let Some(max) = self.max_results {
                if start_index >= max {
                    info!(
                        "Stopping NVD sync at configured limit (fetched {} of {} items)",
                        start_index, total_results
                    );
                    break;
                }
            }
        }

        Ok(advisories)
    }

    fn name(&self) -> &str {
        "NVD"
    }
}

// Minimal NVD Structs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NvdResponse {
    total_results: u32,
    vulnerabilities: Vec<NvdItem>,
}

#[derive(Deserialize)]
struct NvdItem {
    cve: Cve,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Cve {
    id: String,
    #[serde(deserialize_with = "deserialize_nvd_datetime")]
    published: DateTime<Utc>,
    #[serde(deserialize_with = "deserialize_nvd_datetime")]
    last_modified: DateTime<Utc>,
    descriptions: Vec<Description>,
    #[serde(default)]
    references: Vec<NvdReference>,
    #[serde(default)]
    metrics: serde_json::Value,
    #[serde(default)]
    configurations: Option<Vec<Configuration>>,
    // Ignored fields: cveTags, sourceIdentifier, vulnStatus, weaknesses
}

#[derive(Deserialize)]
struct Configuration {
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Node {
    cpe_match: Vec<CpeMatch>,
    // Ignored: negate, operator
}

#[derive(Deserialize)]
struct CpeMatch {
    vulnerable: bool,
    criteria: String,
}

#[derive(Deserialize)]
struct Description {
    value: String,
}

#[derive(Deserialize)]
struct NvdReference {
    url: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_nvd_parses_ghsa_and_osv_aliases() {
        let mock_server = MockServer::start().await;
        let source = NVDSource::with_max_results(None, Some(1)).with_api_url(mock_server.uri());

        let response_body = json!({
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-12345",
                        "published": "2024-06-30T12:00:00.000",
                        "lastModified": "2024-06-30T12:00:00.000",
                        "descriptions": [ { "value": "This is a description" } ],
                        "references": [
                            { "url": "https://github.com/advisories/GHSA-1111-2222-3333" },
                            { "url": "https://osv.dev/vulnerability/OSV-2024-1234" }
                        ],
                        "metrics": {},
                        "configurations": []
                    }
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        let advisories = source.fetch(None).await.unwrap();
        assert_eq!(advisories.len(), 1);
        let adv = &advisories[0];
        assert_eq!(adv.id, "CVE-2024-12345");
        let aliases = adv.aliases.as_ref().unwrap();
        assert!(
            aliases
                .iter()
                .any(|a| a.eq_ignore_ascii_case("GHSA-1111-2222-3333"))
        );
        assert!(aliases.iter().any(|a| a == "OSV-2024-1234"));
    }

    #[tokio::test]
    async fn test_nvd_no_aliases_none() {
        let mock_server = MockServer::start().await;
        let source = NVDSource::with_max_results(None, Some(1)).with_api_url(mock_server.uri());

        let response_body = json!({
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-22222",
                        "published": "2024-06-30T12:00:00.000",
                        "lastModified": "2024-06-30T12:00:00.000",
                        "descriptions": [ { "value": "No aliases here" } ],
                        "references": [],
                        "metrics": {},
                        "configurations": []
                    }
                }
            ]
        });

        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        let advisories = source.fetch(None).await.unwrap();
        assert_eq!(advisories.len(), 1);
        assert!(advisories[0].aliases.is_none());
    }
}
