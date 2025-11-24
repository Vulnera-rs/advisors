use super::AdvisorySource;
use crate::models::{Advisory, Reference, ReferenceType};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use tracing::{info, warn};

pub struct NVDSource {
    api_key: Option<String>,
}

impl NVDSource {
    pub fn new(api_key: Option<String>) -> Self {
        Self { api_key }
    }
}

#[async_trait]
impl AdvisorySource for NVDSource {
    async fn fetch(&self, _since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>> {
        // For now, we will just fetch a recent feed or use the API if key is present.
        // However, the prompt suggested downloading JSON dumps.
        // NVD API is rate limited.
        // Let's implement a basic fetch from the API for "modified" if 'since' is provided,
        // or just a dummy implementation that would normally fetch from NVD.

        // Real implementation would be complex. We will implement a basic structure.
        // We'll use the NVD API 2.0.

        let client = reqwest::Client::new();
        let mut url = "https://services.nvd.nist.gov/rest/json/cves/2.0".to_string();

        // If we had 'since', we would add pubStartDate/pubEndDate or lastModStartDate/lastModEndDate
        // But NVD requires strict formatting.

        // For this scaffold, we will fetch a small batch to prove it works.
        url.push_str("?resultsPerPage=10");

        info!("Fetching NVD data from {}", url);

        let mut request = client.get(&url);
        if let Some(key) = &self.api_key {
            request = request.header("apiKey", key);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            warn!("Failed to fetch NVD data: {}", response.status());
            return Ok(vec![]);
        }

        let nvd_response: NvdResponse = response.json().await?;
        let mut advisories = Vec::new();

        for item in nvd_response.vulnerabilities {
            let cve = item.cve;

            let affected = Vec::new();
            // CPE mapping is hard. We will just put a placeholder for now.
            // In a real system, we would parse configurations.

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
                summary: None, // NVD doesn't have a short summary usually, just description
                details: cve.descriptions.first().map(|d| d.value.clone()),
                affected,
                references,
                published: Some(cve.published),
                modified: Some(cve.last_modified),
                database_specific: Some(serde_json::json!({
                    "source": "NVD",
                    "metrics": cve.metrics,
                })),
            });
        }

        Ok(advisories)
    }
}

// Minimal NVD Structs
#[derive(Deserialize)]
struct NvdResponse {
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
}

#[derive(Deserialize)]
struct Description {
    value: String,
}

#[derive(Deserialize)]
struct NvdReference {
    url: String,
}
