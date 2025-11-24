use super::AdvisorySource;
use crate::models::Advisory;
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::io::Read;
use tracing::{info, warn};

pub struct OSVSource {
    ecosystems: Vec<String>,
}

impl OSVSource {
    pub fn new(ecosystems: Vec<String>) -> Self {
        Self { ecosystems }
    }
}

#[async_trait]
impl AdvisorySource for OSVSource {
    async fn fetch(&self, _since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>> {
        let mut advisories = Vec::new();
        let client = reqwest::Client::new();

        for ecosystem in &self.ecosystems {
            let url = format!(
                "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip",
                ecosystem
            );
            info!("Fetching OSV data for {} from {}", ecosystem, url);

            let response = client.get(&url).send().await?;
            if !response.status().is_success() {
                warn!(
                    "Failed to fetch OSV data for {}: {}",
                    ecosystem,
                    response.status()
                );
                continue;
            }

            let bytes = response.bytes().await?;
            let reader = std::io::Cursor::new(bytes);
            let mut zip = zip::ZipArchive::new(reader)?;

            for i in 0..zip.len() {
                let mut file = zip.by_index(i)?;
                if !file.name().ends_with(".json") {
                    continue;
                }

                let mut content = String::new();
                file.read_to_string(&mut content)?;

                match serde_json::from_str::<Advisory>(&content) {
                    Ok(advisory) => advisories.push(advisory),
                    Err(e) => {
                        warn!("Failed to parse OSV advisory in {}: {}", ecosystem, e);
                    }
                }
            }
        }

        Ok(advisories)
    }
}
