use super::AdvisorySource;
use crate::error::{AdvisoryError, Result};
use crate::models::Advisory;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Maximum concurrent ecosystem syncs
const MAX_CONCURRENT_ECOSYSTEMS: usize = 4;
/// Maximum concurrent individual advisory fetches (incremental sync)
const MAX_CONCURRENT_ADVISORY_FETCHES: usize = 20;
/// Request timeout for individual requests
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// Connection timeout
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct OSVSource {
    ecosystems: Vec<String>,
    client: ClientWithMiddleware,
    /// Raw client for operations that need direct reqwest (like streaming ZIPs)
    raw_client: reqwest::Client,
}

impl OSVSource {
    pub fn new(ecosystems: Vec<String>) -> Self {
        let raw_client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_default();

        // Retry policy: 3 retries with exponential backoff
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
        let client = ClientBuilder::new(raw_client.clone())
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Self {
            ecosystems,
            client,
            raw_client,
        }
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
        let ecosystems = if self.ecosystems.is_empty() {
            info!("No ecosystems specified, fetching list from OSV...");
            let url = "https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt";
            let response = self.client.get(url).send().await?;
            if !response.status().is_success() {
                warn!("Failed to fetch ecosystems list: {}", response.status());
                return Ok(vec![]);
            }
            let text = response.text().await?;
            text.lines().map(|s| s.to_string()).collect()
        } else {
            self.ecosystems.clone()
        };

        // Process ecosystems concurrently with a semaphore to limit parallelism
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_ECOSYSTEMS));
        // Use raw_client for ecosystem fetches (streaming ZIP downloads)
        let client = self.raw_client.clone();

        let tasks: Vec<_> = ecosystems
            .into_iter()
            .map(|ecosystem| {
                let sem = semaphore.clone();
                let client = client.clone();

                tokio::spawn(async move {
                    let _permit = sem.acquire().await.expect("semaphore closed");
                    Self::fetch_ecosystem(&client, &ecosystem, since).await
                })
            })
            .collect();

        // Collect results from all tasks
        let mut all_advisories = Vec::new();
        for task in tasks {
            match task.await {
                Ok(Ok(advisories)) => {
                    all_advisories.extend(advisories);
                }
                Ok(Err(e)) => {
                    warn!("Ecosystem fetch error: {}", e);
                }
                Err(e) => {
                    warn!("Task join error: {}", e);
                }
            }
        }

        Ok(all_advisories)
    }

    /// Fetch advisories for a single ecosystem
    async fn fetch_ecosystem(
        client: &reqwest::Client,
        ecosystem: &str,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<Advisory>> {
        // Try incremental sync first if we have a timestamp
        if let Some(cutoff) = since {
            info!(
                "Attempting incremental sync for {} since {}",
                ecosystem, cutoff
            );
            match Self::fetch_incremental(client, ecosystem, cutoff).await {
                Ok(advisories) => {
                    info!(
                        "Incremental sync for {}: {} advisories",
                        ecosystem,
                        advisories.len()
                    );
                    return Ok(advisories);
                }
                Err(e) => {
                    warn!(
                        "Incremental sync failed for {}, falling back to full sync: {}",
                        ecosystem, e
                    );
                }
            }
        }

        // Full sync: download entire ZIP
        info!("Performing full sync for {}", ecosystem);
        match Self::fetch_full(client, ecosystem).await {
            Ok(advisories) => {
                info!(
                    "Full sync for {}: {} advisories",
                    ecosystem,
                    advisories.len()
                );
                Ok(advisories)
            }
            Err(e) => {
                warn!("Failed to fetch OSV data for {}: {}", ecosystem, e);
                Ok(vec![])
            }
        }
    }

    /// Fetch changed advisories incrementally using the modified_id.csv
    async fn fetch_incremental(
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

        if changed_ids.is_empty() {
            return Ok(vec![]);
        }

        // Download individual JSONs concurrently with rate limiting
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_ADVISORY_FETCHES));
        let client = client.clone();
        let ecosystem = ecosystem.to_string();

        let tasks: Vec<_> = changed_ids
            .into_iter()
            .map(|id| {
                let sem = semaphore.clone();
                let client = client.clone();
                let ecosystem = ecosystem.clone();

                tokio::spawn(async move {
                    let _permit = sem.acquire().await.expect("semaphore closed");
                    let json_url = format!(
                        "https://osv-vulnerabilities.storage.googleapis.com/{}/{}.json",
                        ecosystem, id
                    );

                    match client.get(&json_url).send().await {
                        Ok(response) if response.status().is_success() => {
                            match response.json::<Advisory>().await {
                                Ok(advisory) => Some(advisory),
                                Err(e) => {
                                    debug!("Failed to parse advisory {}: {}", id, e);
                                    None
                                }
                            }
                        }
                        Ok(response) => {
                            debug!("Failed to fetch advisory {}: {}", id, response.status());
                            None
                        }
                        Err(e) => {
                            debug!("Network error fetching advisory {}: {}", id, e);
                            None
                        }
                    }
                })
            })
            .collect();

        // Collect results
        let mut advisories = Vec::with_capacity(tasks.len());
        for task in tasks {
            if let Ok(Some(advisory)) = task.await {
                advisories.push(advisory);
            }
        }

        Ok(advisories)
    }

    /// Fetch all advisories from the ecosystem ZIP file
    async fn fetch_full(client: &reqwest::Client, ecosystem: &str) -> Result<Vec<Advisory>> {
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

        // Stream download to memory (ZIPs are usually <50MB compressed)
        let bytes = response.bytes().await?;
        let ecosystem = ecosystem.to_string();

        // Parse ZIP in a blocking task to avoid blocking the async runtime
        let advisories =
            tokio::task::spawn_blocking(move || Self::parse_zip_sync(&bytes, &ecosystem))
                .await
                .map_err(|e| {
                    AdvisoryError::source_fetch("OSV", format!("Task join error: {}", e))
                })??;

        Ok(advisories)
    }

    /// Synchronous ZIP parsing (runs in spawn_blocking)
    fn parse_zip_sync(bytes: &[u8], ecosystem: &str) -> Result<Vec<Advisory>> {
        use std::io::Cursor;

        let reader = Cursor::new(bytes);
        let mut zip = zip::ZipArchive::new(reader)?;
        let mut advisories = Vec::with_capacity(zip.len());

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
                    // Use eprintln since we're in a blocking context
                    // In production, you'd want structured logging
                    eprintln!("WARN: Failed to parse OSV advisory in {}: {}", ecosystem, e);
                }
            }
        }

        Ok(advisories)
    }
}
