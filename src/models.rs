use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub id: String,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub affected: Vec<Affected>,
    pub references: Vec<Reference>,
    pub published: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub aliases: Option<Vec<String>>,
    pub database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Affected {
    pub package: Package,
    pub ranges: Vec<Range>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ReferenceType {
    Advisory,
    Article,
    Report,
    Fix,
    Git,
    Package,
    Web,
    Other,
}
