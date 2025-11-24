//! FIRST EPSS (Exploit Prediction Scoring System) source.
//!
//! This module fetches EPSS scores which predict the probability that a
//! vulnerability will be exploited in the next 30 days.
//!
//! # Data Source
//!
//! - API: <https://api.first.org/data/v1/epss>
//! - Documentation: <https://www.first.org/epss/api>
//! - License: Free to use

use crate::error::{AdvisoryError, Result};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// Base URL for the FIRST EPSS API.
pub const EPSS_API_URL: &str = "https://api.first.org/data/v1/epss";

/// EPSS data source.
///
/// Provides exploit probability scores for CVEs. These scores help prioritize
/// vulnerabilities based on likelihood of exploitation.
pub struct EpssSource {
    client: reqwest::Client,
}

impl EpssSource {
    /// Create a new EPSS source.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Fetch EPSS scores for specific CVE IDs.
    ///
    /// # Arguments
    ///
    /// * `cve_ids` - List of CVE IDs to look up (e.g., ["CVE-2024-1234", "CVE-2024-5678"])
    ///
    /// # Returns
    ///
    /// A map of CVE ID to EPSS score data.
    pub async fn fetch_scores(&self, cve_ids: &[&str]) -> Result<HashMap<String, EpssScore>> {
        if cve_ids.is_empty() {
            return Ok(HashMap::new());
        }

        // API accepts comma-separated CVE IDs
        let cve_param = cve_ids.join(",");
        let url = format!("{}?cve={}", EPSS_API_URL, cve_param);

        debug!("Fetching EPSS scores for {} CVEs", cve_ids.len());

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(AdvisoryError::source_fetch(
                "EPSS",
                format!("HTTP {}", response.status()),
            ));
        }

        let epss_response: EpssResponse = response.json().await?;

        let scores: HashMap<String, EpssScore> = epss_response
            .data
            .into_iter()
            .map(|s| (s.cve.clone(), s))
            .collect();

        debug!("Retrieved {} EPSS scores", scores.len());
        Ok(scores)
    }

    /// Fetch a single CVE's EPSS score.
    pub async fn fetch_score(&self, cve_id: &str) -> Result<Option<EpssScore>> {
        let scores = self.fetch_scores(&[cve_id]).await?;
        Ok(scores.get(cve_id).cloned())
    }

    /// Fetch all CVEs with EPSS score above a threshold.
    ///
    /// # Arguments
    ///
    /// * `min_epss` - Minimum EPSS probability (0.0 - 1.0)
    /// * `limit` - Maximum number of results (default: 100)
    pub async fn fetch_high_risk(
        &self,
        min_epss: f64,
        limit: Option<u32>,
    ) -> Result<Vec<EpssScore>> {
        let limit = limit.unwrap_or(100);
        let url = format!("{}?epss-gt={}&limit={}", EPSS_API_URL, min_epss, limit);

        info!("Fetching CVEs with EPSS > {}", min_epss);

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(AdvisoryError::source_fetch(
                "EPSS",
                format!("HTTP {}", response.status()),
            ));
        }

        let epss_response: EpssResponse = response.json().await?;
        info!("Found {} high-risk CVEs", epss_response.data.len());

        Ok(epss_response.data)
    }

    /// Fetch CVEs with EPSS percentile above a threshold.
    ///
    /// # Arguments
    ///
    /// * `min_percentile` - Minimum percentile (0.0 - 1.0, e.g., 0.95 for top 5%)
    /// * `limit` - Maximum number of results
    pub async fn fetch_top_percentile(
        &self,
        min_percentile: f64,
        limit: Option<u32>,
    ) -> Result<Vec<EpssScore>> {
        let limit = limit.unwrap_or(100);
        let url = format!(
            "{}?percentile-gt={}&limit={}",
            EPSS_API_URL, min_percentile, limit
        );

        info!(
            "Fetching CVEs in top {} percentile",
            (1.0 - min_percentile) * 100.0
        );

        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(AdvisoryError::source_fetch(
                "EPSS",
                format!("HTTP {}", response.status()),
            ));
        }

        let epss_response: EpssResponse = response.json().await?;
        Ok(epss_response.data)
    }

    /// Fetch EPSS scores in batches for a large list of CVEs.
    ///
    /// The API can handle many CVEs in a single request, but we batch
    /// to avoid URL length limits.
    pub async fn fetch_scores_batch(
        &self,
        cve_ids: &[String],
        batch_size: usize,
    ) -> Result<HashMap<String, EpssScore>> {
        let mut all_scores = HashMap::new();

        for chunk in cve_ids.chunks(batch_size) {
            let refs: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
            let scores = self.fetch_scores(&refs).await?;
            all_scores.extend(scores);
        }

        Ok(all_scores)
    }
}

impl Default for EpssSource {
    fn default() -> Self {
        Self::new()
    }
}

/// Response from the EPSS API.
#[derive(Debug, Clone, Deserialize)]
pub struct EpssResponse {
    /// Status of the request.
    pub status: String,
    /// API version.
    #[serde(rename = "status-code")]
    pub status_code: Option<i32>,
    /// API version string.
    pub version: Option<String>,
    /// Total number of CVEs with EPSS scores.
    pub total: Option<u64>,
    /// Offset for pagination.
    pub offset: Option<u64>,
    /// Limit used in the request.
    pub limit: Option<u64>,
    /// The EPSS score data.
    pub data: Vec<EpssScore>,
}

/// EPSS score for a single CVE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpssScore {
    /// CVE identifier.
    pub cve: String,
    /// EPSS probability score (0.0 - 1.0).
    /// Represents the probability of exploitation in the next 30 days.
    #[serde(deserialize_with = "deserialize_f64_from_string")]
    pub epss: f64,
    /// Percentile ranking (0.0 - 1.0).
    /// Indicates how this CVE ranks compared to all others.
    #[serde(deserialize_with = "deserialize_f64_from_string")]
    pub percentile: f64,
    /// Date when the score was calculated.
    #[serde(default)]
    pub date: Option<String>,
}

impl EpssScore {
    /// Check if this CVE is in the top N percentile.
    pub fn is_top_percentile(&self, threshold: f64) -> bool {
        self.percentile >= threshold
    }

    /// Get a risk category based on EPSS score.
    pub fn risk_category(&self) -> EpssRiskCategory {
        match self.epss {
            s if s >= 0.7 => EpssRiskCategory::Critical,
            s if s >= 0.4 => EpssRiskCategory::High,
            s if s >= 0.1 => EpssRiskCategory::Medium,
            _ => EpssRiskCategory::Low,
        }
    }

    /// Get the date as a parsed DateTime if available.
    pub fn date_utc(&self) -> Option<DateTime<Utc>> {
        self.date.as_ref().and_then(|d| {
            NaiveDate::parse_from_str(d, "%Y-%m-%d")
                .ok()
                .map(|nd| nd.and_hms_opt(0, 0, 0).unwrap().and_utc())
        })
    }
}

/// Risk categories based on EPSS scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpssRiskCategory {
    /// EPSS < 0.1 (low likelihood of exploitation)
    Low,
    /// EPSS 0.1 - 0.4
    Medium,
    /// EPSS 0.4 - 0.7
    High,
    /// EPSS >= 0.7 (very likely to be exploited)
    Critical,
}

/// Deserialize f64 from string (EPSS API returns numbers as strings).
fn deserialize_f64_from_string<'de, D>(deserializer: D) -> std::result::Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    s.parse().map_err(serde::de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epss_risk_category() {
        let score = EpssScore {
            cve: "CVE-2024-1234".to_string(),
            epss: 0.75,
            percentile: 0.98,
            date: None,
        };

        assert_eq!(score.risk_category(), EpssRiskCategory::Critical);
        assert!(score.is_top_percentile(0.95));
    }

    #[test]
    fn test_epss_low_risk() {
        let score = EpssScore {
            cve: "CVE-2024-5678".to_string(),
            epss: 0.05,
            percentile: 0.3,
            date: None,
        };

        assert_eq!(score.risk_category(), EpssRiskCategory::Low);
        assert!(!score.is_top_percentile(0.95));
    }
}
