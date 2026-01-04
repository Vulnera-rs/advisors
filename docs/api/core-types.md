# Core Types

This document describes the core types in Vulnera Advisor.

## VulnerabilityManager

The main entry point for using the library. Orchestrates syncing and querying vulnerabilities.

```rust
use vulnera_advisor::VulnerabilityManager;

// Using builder pattern
let manager = VulnerabilityManager::builder()
    .redis_url("redis://localhost:6379")
    .with_osv_defaults()
    .with_nvd(Some("your-api-key".to_string()))
    .with_ghsa("your-github-token".to_string())
    .build()?;
```

### Methods

| Method | Description |
|--------|-------------|
| `new(config)` | Create from Config |
| `builder()` | Create a builder for custom configuration |
| `sync_all()` | Sync advisories from all configured sources |
| `query(ecosystem, package)` | Query advisories for a package |
| `matches(ecosystem, package, version)` | Check if version is vulnerable |
| `suggest_remediation(ecosystem, package, version)` | Get safe version suggestions |

## Advisory

Represents a security vulnerability advisory (OSV-compatible format).

```rust
pub struct Advisory {
    pub id: String,                    // e.g., "CVE-2021-23337"
    pub summary: Option<String>,
    pub details: Option<String>,
    pub affected: Vec<Affected>,
    pub references: Vec<Reference>,
    pub published: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub aliases: Option<Vec<String>>,
    pub enrichment: Option<Enrichment>,
}
```

## Affected

Describes which package versions are affected by an advisory.

```rust
pub struct Affected {
    pub package: Package,
    pub ranges: Vec<Range>,
    pub versions: Vec<String>,
}
```

## Enrichment

Additional data from EPSS and CISA KEV.

```rust
pub struct Enrichment {
    pub epss_score: Option<f64>,       // 0.0 - 1.0
    pub epss_percentile: Option<f64>,
    pub is_kev: bool,
    pub kev_due_date: Option<DateTime<Utc>>,
    pub cvss_v3_score: Option<f64>,
    pub cvss_v3_severity: Option<Severity>,
}
```

## Severity

CVSS v3 severity levels.

```rust
pub enum Severity {
    None,     // 0.0
    Low,      // 0.1 - 3.9
    Medium,   // 4.0 - 6.9
    High,     // 7.0 - 8.9
    Critical, // 9.0 - 10.0
}
```

## MatchOptions

Filtering options for vulnerability queries.

```rust
pub struct MatchOptions {
    pub min_cvss: Option<f64>,
    pub min_epss: Option<f64>,
    pub kev_only: bool,
    pub min_severity: Option<Severity>,
    pub include_enrichment: bool,
}
```

### Preset Options

```rust
// Only high/critical severity
let options = MatchOptions::high_severity();

// Only actively exploited (KEV)
let options = MatchOptions::exploited_only();

// Include enrichment data
let options = MatchOptions::with_enrichment();
```
