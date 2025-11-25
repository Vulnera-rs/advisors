//! Core data models for vulnerability advisories.
//!
//! This module defines the canonical [`Advisory`] struct and related types that form
//! the unified data model for all vulnerability sources (GHSA, NVD, OSV, etc.).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A vulnerability advisory containing information about a security issue.
///
/// This is the canonical representation used internally, based on the OSV schema.
/// All sources convert their data to this format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    /// Unique identifier (e.g., "GHSA-xxxx-xxxx-xxxx", "CVE-2024-1234").
    pub id: String,
    /// Brief summary of the vulnerability.
    pub summary: Option<String>,
    /// Detailed description of the vulnerability.
    pub details: Option<String>,
    /// List of affected packages and version ranges. Optional per OSV schema.
    #[serde(default)]
    pub affected: Vec<Affected>,
    /// References to external resources (advisories, patches, etc.). Optional per OSV schema.
    #[serde(default)]
    pub references: Vec<Reference>,
    /// When the advisory was first published.
    pub published: Option<DateTime<Utc>>,
    /// When the advisory was last modified.
    pub modified: Option<DateTime<Utc>>,
    /// Alternative identifiers (e.g., CVE aliases for GHSA).
    pub aliases: Option<Vec<String>>,
    /// Source-specific metadata.
    pub database_specific: Option<serde_json::Value>,
    /// Enrichment data from EPSS, CISA KEV, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrichment: Option<Enrichment>,
}

/// Enrichment data aggregated from multiple sources.
///
/// This provides additional context for prioritization:
/// - EPSS scores indicate exploit probability
/// - KEV data indicates active exploitation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Enrichment {
    /// EPSS (Exploit Prediction Scoring System) probability score (0.0 - 1.0).
    /// Higher values indicate higher likelihood of exploitation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_score: Option<f64>,
    /// EPSS percentile (0.0 - 1.0) relative to all scored CVEs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_percentile: Option<f64>,
    /// Date when EPSS score was calculated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_date: Option<DateTime<Utc>>,
    /// Whether this CVE is in CISA's Known Exploited Vulnerabilities catalog.
    #[serde(default)]
    pub is_kev: bool,
    /// CISA KEV due date for remediation (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev_due_date: Option<DateTime<Utc>>,
    /// Date when CVE was added to KEV catalog.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev_date_added: Option<DateTime<Utc>>,
    /// Whether known ransomware campaigns use this vulnerability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev_ransomware: Option<bool>,
    /// Extracted CVSS v3 base score (0.0 - 10.0) if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_v3_score: Option<f64>,
    /// CVSS v3 severity level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_v3_severity: Option<Severity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Affected {
    pub package: Package,
    /// Version ranges affected (e.g., semver ranges).
    #[serde(default)]
    pub ranges: Vec<Range>,
    /// Explicit list of affected versions. Optional per OSV schema.
    #[serde(default)]
    pub versions: Vec<String>,
    pub ecosystem_specific: Option<serde_json::Value>,
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
    pub purl: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Range {
    #[serde(rename = "type")]
    pub range_type: RangeType,
    pub events: Vec<Event>,
    pub repo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RangeType {
    Semver,
    Ecosystem,
    Git,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    Introduced(String),
    Fixed(String),
    LastAffected(String),
    Limit(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    #[serde(rename = "type")]
    pub reference_type: ReferenceType,
    pub url: String,
}

/// Reference types as defined in the OSV schema.
/// Uses `#[serde(other)]` to gracefully handle unknown variants.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum ReferenceType {
    Advisory,
    Article,
    Detection,
    Discussion,
    Evidence,
    Fix,
    Git,
    Introduced,
    Package,
    Report,
    Web,
    /// Fallback for unknown/future reference types.
    #[default]
    #[serde(other)]
    Other,
}

/// CVSS v3 severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// CVSS score 0.0
    None,
    /// CVSS score 0.1 - 3.9
    Low,
    /// CVSS score 4.0 - 6.9
    Medium,
    /// CVSS score 7.0 - 8.9
    High,
    /// CVSS score 9.0 - 10.0
    Critical,
}

impl Severity {
    /// Convert a CVSS v3 score to a severity level.
    pub fn from_cvss_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Medium,
            s if s > 0.0 => Self::Low,
            _ => Self::None,
        }
    }

    /// Get the minimum CVSS score for this severity level.
    pub fn min_score(&self) -> f64 {
        match self {
            Self::None => 0.0,
            Self::Low => 0.1,
            Self::Medium => 4.0,
            Self::High => 7.0,
            Self::Critical => 9.0,
        }
    }
}
