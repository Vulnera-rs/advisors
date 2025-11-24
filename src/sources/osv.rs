use super::AdvisorySource;
use crate::error::{AdvisoryError, Result};
use crate::models::Advisory;
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
    async fn fetch(&self, since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>> {
        // ... implementation ...
        self.fetch_internal(since).await
    }

    fn name(&self) -> &str {
        "OSV"
    }
}

impl OSVSource {
    async fn fetch_internal(&self, since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>> {
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
            // Try incremental sync first if we have a timestamp
            if let Some(cutoff) = since {
                info!(
                    "Attempting incremental sync for {} since {}",
                    ecosystem, cutoff
                );
                match self.fetch_incremental(&client, ecosystem, cutoff).await {
                    Ok(mut incremental_advisories) => {
                        info!(
                            "Incremental sync for {}: {} advisories",
                            ecosystem,
                            incremental_advisories.len()
                        );
                        advisories.append(&mut incremental_advisories);
                        continue; // Skip full sync for this ecosystem
                    }
                    Err(e) => {
                        warn!(
                            "Incremental sync failed for {}, falling back to full sync: {}",
                            ecosystem, e
                        );
                        // Fall through to full sync
                    }
                }
            }

            // Full sync: download entire ZIP
            info!("Performing full sync for {}", ecosystem);
            match self.fetch_full(&client, ecosystem).await {
                Ok(mut full_advisories) => {
                    info!(
                        "Full sync for {}: {} advisories",
                        ecosystem,
                        full_advisories.len()
                    );
                    advisories.append(&mut full_advisories);
                }
                Err(e) => {
                    warn!("Failed to fetch OSV data for {}: {}", ecosystem, e);
                }
            }
        }

        Ok(advisories)
    }

    async fn fetch_incremental(
        &self,
        client: &reqwest::Client,
        ecosystem: &str,
        since: DateTime<Utc>,
    ) -> Result<Vec<Advisory>> {
        let csv_url = format!(
            "https://osv-vulnerabilities.storage.googleapis.com/{}/modified_id.csv",
            ecosystem
        );

        let response = client.get(&csv_url).send().await?;
        if !response.status().is_success() {
            return Err(AdvisoryError::source_fetch(
                "OSV",
                format!("Failed to fetch modified_id.csv: {}", response.status()),
            ));
        }

        let csv_text = response.text().await?;
        let mut changed_ids = Vec::new();

        // Parse CSV: format is "iso_date,id"
        for line in csv_text.lines() {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() != 2 {
                continue;
            }

            let timestamp_str = parts[0];
            let id = parts[1];

            // Parse timestamp
            match DateTime::parse_from_rfc3339(timestamp_str) {
                Ok(modified) => {
                    let modified_utc = modified.with_timezone(&chrono::Utc);
                    if modified_utc <= since {
                        // CSV is sorted newest first, so we can stop here
                        break;
                    }
                    changed_ids.push(id.to_string());
                }
                Err(_) => {
                    warn!(
                        "Failed to parse timestamp in modified_id.csv: {}",
                        timestamp_str
                    );
                    continue;
                }
            }
        }

        info!(
            "Found {} changed advisories for {}",
            changed_ids.len(),
            ecosystem
        );

        // Download individual JSONs for changed IDs
        let mut advisories = Vec::new();
        for id in changed_ids {
            let json_url = format!(
                "https://osv-vulnerabilities.storage.googleapis.com/{}/{}.json",
                ecosystem, id
            );

            match client.get(&json_url).send().await {
                Ok(response) if response.status().is_success() => {
                    match response.json::<Advisory>().await {
                        Ok(advisory) => advisories.push(advisory),
                        Err(e) => warn!("Failed to parse advisory {}: {}", id, e),
                    }
                }
                Ok(response) => {
                    warn!("Failed to fetch advisory {}: {}", id, response.status());
                }
                Err(e) => {
                    warn!("Network error fetching advisory {}: {}", id, e);
                }
            }
        }

        Ok(advisories)
    }

    async fn fetch_full(&self, client: &reqwest::Client, ecosystem: &str) -> Result<Vec<Advisory>> {
        let url = format!(
            "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip",
            ecosystem
        );

        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(AdvisoryError::source_fetch(
                "OSV",
                format!("Failed to fetch ZIP: {}", response.status()),
            ));
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
        let mut advisories = Vec::new();

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

        Ok(advisories)
    }
}
