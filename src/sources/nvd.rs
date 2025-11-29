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
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use serde::{Deserialize, Deserializer};
use std::num::NonZeroU32;
use std::sync::Arc;
use tracing::{info, warn};

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

pub struct NVDSource {
    api_key: Option<String>,
    client: ClientWithMiddleware,
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>,
    /// Maximum number of CVEs to fetch (None = unlimited)
    max_results: Option<u32>,
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
        }
    }
}

#[async_trait]
impl AdvisorySource for NVDSource {
    async fn fetch(&self, since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>> {
        let base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0";
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
                    // For first implementation, just use last 120 days and log warning
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

            info!("Fetching NVD data from startIndex={}", start_index);

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
                                                    p.with_version(version.clone());
                                                }
                                                if ecosystem == "maven" {
                                                    p.with_namespace(vendor.clone());
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

                advisories.push(Advisory {
                    id: cve.id,
                    summary: None,
                    details: cve.descriptions.first().map(|d| d.value.clone()),
                    affected,
                    references,
                    published: Some(cve.published),
                    modified: Some(cve.last_modified),
                    aliases: None,
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
