# Vulnerability Sources

Vulnera Advisor integrates with multiple vulnerability data sources.

## Source Types

### GHSA (GitHub Security Advisories)

GitHub's security advisory database via GraphQL API.

```rust
use vulnera_advisor::GHSASource;

let manager = VulnerabilityManager::builder()
    .redis_url("redis://localhost:6379")
    .with_ghsa("your-github-token")
    .build()?;
```

**Environment Variable:** `VULNERA__APIS__GHSA__TOKEN`

### NVD (National Vulnerability Database)

NIST's vulnerability database via REST API v2.0.

```rust
let manager = VulnerabilityManager::builder()
    .redis_url("redis://localhost:6379")
    .with_nvd(Some("your-nvd-api-key".to_string()))
    .build()?;
```

**Environment Variable:** `VULNERA__APIS__NVD__API_KEY`

### OSV (Open Source Vulnerabilities)

Google's OSV database via bulk downloads.

```rust
let manager = VulnerabilityManager::builder()
    .redis_url("redis://localhost:6379")
    .with_osv_defaults()  // Includes npm, PyPI, Maven, etc.
    .build()?;

// Or specify ecosystems
let manager = VulnerabilityManager::builder()
    .redis_url("redis://localhost:6379")
    .with_osv(vec!["npm".to_string(), "PyPI".to_string()])
    .build()?;
```

### OSS Index

Sonatype's OSS Index for on-demand PURL queries.

```rust
use vulnera_advisor::Purl;

let manager = VulnerabilityManager::builder()
    .redis_url("redis://localhost:6379")
    .with_ossindex(None)  // Uses env vars
    .build()?;

let purls = vec![
    Purl::new("npm", "lodash").with_version("4.17.20").to_string(),
];
let advisories = manager.query_ossindex(&purls).await?;
```

**Environment Variables:**

- `OSSINDEX_USER`
- `OSSINDEX_TOKEN`

## Enrichment Sources

### EPSS (Exploit Prediction Scoring System)

Provides exploit probability scores.

```rust
let manager = VulnerabilityManager::new(config).await?;
manager.sync_enrichment().await?;

// Access via advisory enrichment
if let Some(enrichment) = &advisory.enrichment {
    println!("EPSS: {:?}", enrichment.epss_score);
}
```

### CISA KEV (Known Exploited Vulnerabilities)

Identifies actively exploited vulnerabilities.

```rust
// Check if a CVE is in KEV
let is_kev = manager.is_kev("CVE-2021-44228").await?;

// Filter to only KEV vulnerabilities
let options = MatchOptions::exploited_only();
let vulns = manager.matches_with_options("npm", "log4j", "2.14.1", &options).await?;
```

## AdvisorySource Trait

All sources implement this trait:

```rust
#[async_trait]
pub trait AdvisorySource: Send + Sync {
    fn name(&self) -> &str;
    async fn fetch(&self, since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>>;
}
```

## Custom Sources

Implement `AdvisorySource` for custom vulnerability feeds:

```rust
use vulnera_advisor::{AdvisorySource, Advisory, Result};
use async_trait::async_trait;

struct MySource;

#[async_trait]
impl AdvisorySource for MySource {
    fn name(&self) -> &str {
        "my-source"
    }
    
    async fn fetch(&self, since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>> {
        // Fetch from your source
        Ok(vec![])
    }
}

// Add to manager
let manager = VulnerabilityManager::builder()
    .redis_url("redis://localhost:6379")
    .add_source(Arc::new(MySource))
    .build()?;
```
