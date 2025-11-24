use super::AdvisorySource;
use crate::models::{Advisory, Reference, ReferenceType};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use cpe::cpe::Cpe;
use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use serde::Deserialize;
use std::num::NonZeroU32;
use std::sync::Arc;
use tracing::{info, warn};

pub struct NVDSource {
    api_key: Option<String>,
    client: ClientWithMiddleware,
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>,
}

impl NVDSource {
    pub fn new(api_key: Option<String>) -> Self {
        // Retry policy
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
        let client = ClientBuilder::new(reqwest::Client::new())
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
                        start.to_rfc3339(),
                        now.to_rfc3339()
                    ));
                } else {
                    // Normal case: range is within limit
                    url.push_str(&format!(
                        "&lastModStartDate={}&lastModEndDate={}",
                        since.to_rfc3339(),
                        now.to_rfc3339()
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
                warn!("Failed to fetch NVD data: {}", response.status());
                // If 403 or 404, maybe stop? For now, break to avoid infinite loop on error
                break;
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
                                        // Heuristic: Try to map CPE to PURL
                                        // This is imperfect. NVD doesn't tell us the package manager.
                                        // We'll make a best-effort guess or generic entry.

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
                });
            }

            start_index += count as u32;
            if start_index >= total_results {
                break;
            }

            // Safety break for scaffold to avoid downloading 200k+ CVEs
            if start_index > 2000 {
                info!(
                    "Stopping NVD sync early for scaffold safety (fetched {} items)",
                    start_index
                );
                break;
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
struct NvdResponse {
    #[serde(rename = "totalResults")]
    total_results: u32,
    vulnerabilities: Vec<NvdItem>,
}

#[derive(Deserialize)]
struct NvdItem {
    cve: Cve,
}

#[derive(Deserialize)]
struct Cve {
    id: String,
    published: DateTime<Utc>,
    #[serde(rename = "lastModified")]
    last_modified: DateTime<Utc>,
    descriptions: Vec<Description>,
    references: Vec<NvdReference>,
    #[serde(default)]
    metrics: serde_json::Value,
    #[serde(default)]
    configurations: Option<Vec<Configuration>>,
}

#[derive(Deserialize)]
struct Configuration {
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct Node {
    #[serde(rename = "cpeMatch")]
    cpe_match: Vec<CpeMatch>,
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
