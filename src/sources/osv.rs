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

        let ecosystems = if self.ecosystems.is_empty() {
            info!("No ecosystems specified, fetching list from OSV...");
            let url = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt";
            let response = client.get(url).send().await?;
            if !response.status().is_success() {
                warn!("Failed to fetch ecosystems list: {}", response.status());
                return Ok(vec![]);
            }
            let text = response.text().await?;
            text.lines().map(|s| s.to_string()).collect()
        } else {
            self.ecosystems.clone()
        };

        for ecosystem in &ecosystems {
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

            // Create a temporary file
            let mut tmp_file = tempfile::tempfile()?;
            let mut content = response.bytes_stream();

            // Stream download to file
            use futures_util::StreamExt;
            while let Some(chunk) = content.next().await {
                let chunk = chunk?;
                std::io::Write::write_all(&mut tmp_file, &chunk)?;
            }

            // Rewind file for reading
            use std::io::Seek;
            tmp_file.seek(std::io::SeekFrom::Start(0))?;

            let mut zip = zip::ZipArchive::new(tmp_file)?;

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
