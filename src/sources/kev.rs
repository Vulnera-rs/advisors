//! CISA Known Exploited Vulnerabilities (KEV) catalog source.
//!
//! This module fetches the KEV catalog which lists vulnerabilities that are
//! actively being exploited in the wild. This data is critical for prioritization.
//!
//! # Data Source
//!
//! - URL: <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
//! - Updated: As new exploited vulnerabilities are discovered
//! - License: Public domain

use crate::error::{AdvisoryError, Result};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// URL for the CISA KEV JSON feed.
pub const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

/// CISA KEV data source.
///
/// This source fetches the Known Exploited Vulnerabilities catalog and provides
/// enrichment data for advisories. Unlike other sources, KEV doesn't create new
/// advisories but enriches existing ones with exploitation status.
pub struct KevSource {
    client: reqwest::Client,
}

impl KevSource {
    /// Create a new KEV source.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Fetch the entire KEV catalog.
    ///
    /// Returns a map of CVE ID to KEV entry for efficient lookup.
    pub async fn fetch_catalog(&self) -> Result<HashMap<String, KevEntry>> {
        info!("Fetching CISA KEV catalog...");

        let response = self.client.get(KEV_URL).send().await?;

        if !response.status().is_success() {
            return Err(AdvisoryError::source_fetch(
                "KEV",
                format!("HTTP {}", response.status()),
            ));
        }

        let catalog: KevCatalog = response.json().await?;

        let entries: HashMap<String, KevEntry> = catalog
            .vulnerabilities
            .into_iter()
            .map(|v| (v.cve_id.clone(), v))
            .collect();

        info!(
            "Fetched {} KEV entries (catalog version: {})",
            entries.len(),
            catalog.catalog_version
        );

        Ok(entries)
    }

    /// Check if a CVE is in the KEV catalog.
    pub async fn is_kev(&self, cve_id: &str) -> Result<Option<KevEntry>> {
        let catalog = self.fetch_catalog().await?;
        Ok(catalog.get(cve_id).cloned())
    }

    /// Fetch KEV entries modified since a given date.
    ///
    /// Note: The KEV catalog doesn't have incremental updates, so this downloads
    /// the full catalog and filters locally.
    pub async fn fetch_since(&self, since: DateTime<Utc>) -> Result<Vec<KevEntry>> {
        let catalog = self.fetch_catalog().await?;
        let since_date = since.date_naive();

        let recent: Vec<KevEntry> = catalog
            .into_values()
            .filter(|entry| entry.date_added.map(|d| d >= since_date).unwrap_or(false))
            .collect();

        debug!("Found {} KEV entries added since {}", recent.len(), since);
        Ok(recent)
    }
}

impl Default for KevSource {
    fn default() -> Self {
        Self::new()
    }
}

/// The full KEV catalog response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevCatalog {
    /// Title of the catalog.
    pub title: String,
    /// Version of the catalog.
    pub catalog_version: String,
    /// When the catalog was last updated.
    #[serde(rename = "dateReleased")]
    pub date_released: Option<String>,
    /// Total number of vulnerabilities.
    pub count: u32,
    /// List of vulnerabilities.
    pub vulnerabilities: Vec<KevEntry>,
}

/// A single KEV entry representing an actively exploited vulnerability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KevEntry {
    /// CVE identifier (e.g., "CVE-2024-1234").
    pub cve_id: String,
    /// Vendor/project name.
    pub vendor_project: String,
    /// Product name.
    pub product: String,
    /// Human-readable vulnerability name.
    pub vulnerability_name: String,
    /// Date the CVE was added to KEV.
    #[serde(deserialize_with = "deserialize_date_option", default)]
    pub date_added: Option<NaiveDate>,
    /// Brief description.
    pub short_description: String,
    /// Required remediation action.
    pub required_action: String,
    /// Due date for remediation (for federal agencies).
    #[serde(deserialize_with = "deserialize_date_option", default)]
    pub due_date: Option<NaiveDate>,
    /// Whether known ransomware campaigns use this vulnerability.
    #[serde(default)]
    pub known_ransomware_campaign_use: Option<String>,
    /// Additional notes.
    #[serde(default)]
    pub notes: Option<String>,
    /// CWE identifiers.
    #[serde(default)]
    pub cwes: Option<Vec<String>>,
}

impl KevEntry {
    /// Check if this vulnerability is used in ransomware campaigns.
    pub fn is_ransomware_related(&self) -> bool {
        self.known_ransomware_campaign_use
            .as_ref()
            .map(|s| s.eq_ignore_ascii_case("Known"))
            .unwrap_or(false)
    }

    /// Get the due date as a UTC DateTime.
    pub fn due_date_utc(&self) -> Option<DateTime<Utc>> {
        self.due_date
            .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc())
    }

    /// Get the date added as a UTC DateTime.
    pub fn date_added_utc(&self) -> Option<DateTime<Utc>> {
        self.date_added
            .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc())
    }
}

/// Deserialize optional date fields from CISA format (YYYY-MM-DD).
fn deserialize_date_option<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<NaiveDate>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        Some(s) if !s.is_empty() => NaiveDate::parse_from_str(&s, "%Y-%m-%d")
            .map(Some)
            .map_err(serde::de::Error::custom),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kev_entry_ransomware() {
        let entry = KevEntry {
            cve_id: "CVE-2024-1234".to_string(),
            vendor_project: "Test".to_string(),
            product: "Test".to_string(),
            vulnerability_name: "Test".to_string(),
            date_added: None,
            short_description: "Test".to_string(),
            required_action: "Test".to_string(),
            due_date: None,
            known_ransomware_campaign_use: Some("Known".to_string()),
            notes: None,
            cwes: None,
        };

        assert!(entry.is_ransomware_related());
    }

    #[test]
    fn test_kev_entry_not_ransomware() {
        let entry = KevEntry {
            cve_id: "CVE-2024-1234".to_string(),
            vendor_project: "Test".to_string(),
            product: "Test".to_string(),
            vulnerability_name: "Test".to_string(),
            date_added: None,
            short_description: "Test".to_string(),
            required_action: "Test".to_string(),
            due_date: None,
            known_ransomware_campaign_use: Some("Unknown".to_string()),
            notes: None,
            cwes: None,
        };

        assert!(!entry.is_ransomware_related());
    }
}
