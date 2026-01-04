# Vulnera Advisors: Open Source Vulnerability Intelligence

[![Crates.io](https://img.shields.io/crates/v/vulnera-advisors.svg)](https://crates.io/crates/vulnera-advisor)
[![Documentation](https://docs.rs/vulnera-advisors/badge.svg)](https://docs.rs/vulnera-advisor)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Made with love by Rust](https://img.shields.io/badge/Made%20with%20love-by%20Rust-red.svg)](https://www.rust-lang.org/)
[![Open Source](https://img.shields.io/badge/Open%20Source-Vulnera-brightgreen.svg)](https://github.com/vulnera-rs)

A Rust library for aggregating and querying security vulnerability advisories from multiple sources. Designed for building vulnerability scanners, SCA tools, and security dashboards.

## About Vulnera

This project is an open source contribution from the Vulnera organization, dedicated to improving security tooling and vulnerability management. Vulnera provides security-focused libraries and tools to help developers build more secure applications.

## Features

- **Multi-Source Aggregation**: Fetch advisories from:
  - [GitHub Security Advisories (GHSA)](https://github.com/advisories) via GraphQL API
  - [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/) via REST API
  - [Open Source Vulnerabilities (OSV)](https://osv.dev/) via bulk downloads
  - [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  - [OSS Index](https://ossindex.sonatype.org/) for on-demand PURL queries

- **Enrichment Data**:
  - [EPSS](https://www.first.org/epss/) (Exploit Prediction Scoring System) scores
  - KEV status for identifying actively exploited vulnerabilities

- **Unified Data Model**: All sources normalized to OSV-compatible Advisory format
- **Efficient Storage**: Redis/DragonflyDB backend with zstd compression
- **Version Matching**: SemVer-aware vulnerability matching
- **Caching**: Automatic caching for OSS Index queries with configurable TTL
- **Remediation Suggestions**: Safe version recommendations with upgrade impact classification

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
vulnera-advisors = "0.1.5"
```

## Quick Start

```rust
use vulnera_advisors::{VulnerabilityManager, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration from environment variables
    let config = Config::from_env()?;
    let manager = VulnerabilityManager::new(config).await?;

    // Sync advisories from all configured sources
    manager.sync_all().await?;

    // Query vulnerabilities for a package
    let advisories = manager.query("npm", "lodash").await?;
    println!("Found {} advisories for lodash", advisories.len());

    // Check if a specific version is affected
    let affected = manager.matches("npm", "lodash", "4.17.20").await?;
    for advisory in affected {
        println!("CVE: {} - {}", advisory.id, advisory.summary.unwrap_or_default());
    }

    Ok(())
}
```

## Builder Pattern

For more control over configuration:

```rust
use vulnera_advisors::VulnerabilityManager;

let manager = VulnerabilityManager::builder()
    .redis_url("redis://localhost:6379")
    .with_osv_defaults()  // npm, PyPI, Maven, crates.io, Go, etc.
    .with_nvd(Some("your-nvd-api-key".to_string()))
    .with_ghsa("your-github-token".to_string())
    .with_ossindex(None)  // Uses env vars for auth
    .build()?;
```

## OSS Index Queries

Query vulnerabilities directly by Package URL (PURL):

```rust
use vulnera_advisors::{VulnerabilityManager, Purl};

// Build PURLs for packages
let purls = vec![
    Purl::new("npm", "lodash").with_version("4.17.20").to_string(),
    Purl::new("pypi", "requests").with_version("2.25.0").to_string(),
];

// Query with automatic caching
let advisories = manager.query_ossindex(&purls).await?;
```

## Filtering Options

Filter vulnerabilities by severity, EPSS score, or KEV status:

```rust
use vulnera_advisors::{MatchOptions, Severity};

// Only high/critical severity
let options = MatchOptions::high_severity();

// Only actively exploited (KEV)
let options = MatchOptions::exploited_only();

// Custom filters
let options = MatchOptions {
    min_cvss: Some(7.0),
    min_epss: Some(0.5),
    kev_only: false,
    min_severity: Some(Severity::Medium),
    include_enrichment: true,
};

let vulns = manager.matches_with_options("npm", "lodash", "4.17.20", &options).await?;
```

## Remediation Suggestions

Get safe version recommendations when vulnerabilities are detected:

```rust
use vulnera_advisors::{VulnerabilityManager, PackageRegistry};

// Get remediation suggestions using advisory data
let remediation = manager.suggest_remediation("npm", "lodash", "4.17.20").await?;

if let Some(nearest) = &remediation.nearest_safe {
    println!("Nearest safe version: {}", nearest);
    println!("Upgrade impact: {:?}", remediation.upgrade_impact);
}

if let Some(latest) = &remediation.latest_safe {
    println!("Latest safe version: {}", latest);
}

// Enhanced: Use package registry for complete version list
let registry = PackageRegistry::new();
let remediation = manager
    .suggest_remediation_with_registry("npm", "lodash", "4.17.20", &registry)
    .await?;
```

### Remediation Response Format

```json
{
  "ecosystem": "npm",
  "package": "lodash",
  "current_version": "4.17.20",
  "nearest_safe": "4.17.21",
  "latest_safe": "4.18.2",
  "upgrade_impact": "patch",
  "vulnerabilities": ["CVE-2021-23337", "GHSA-xxxx-xxxx-xxxx"]
}
```

### Upgrade Impact Classification

| Impact | Description |
|--------|-------------|
| `patch` | Bug fix only (x.y.Z) |
| `minor` | New features, backward compatible (x.Y.z) |
| `major` | Breaking changes (X.y.z) |

## Environment Variables

| Variable                      | Description                      | Required      |
| ----------------------------- | -------------------------------- | ------------- |
| `REDIS_URL`                   | Redis/DragonflyDB connection URL | Yes           |
| `VULNERA__APIS__GHSA__TOKEN`  | GitHub token for GHSA API        | For GHSA      |
| `VULNERA__APIS__NVD__API_KEY` | NVD API key (higher rate limits) | Optional      |
| `OSSINDEX_USER`               | OSS Index username               | For OSS Index |
| `OSSINDEX_TOKEN`              | OSS Index API token              | For OSS Index |
| `VULNERA__STORE__TTL_SECONDS` | Advisory cache TTL               | Optional      |

## Supported Ecosystems

The library supports Package URLs (PURLs) for these ecosystems:

- `npm` - Node.js packages
- `pypi` - Python packages
- `cargo` / `crates.io` - Rust crates
- `maven` - Java/Kotlin packages
- `nuget` - .NET packages
- `gem` - Ruby gems
- `golang` / `go` - Go modules
- `composer` / `packagist` - PHP packages
- `pub` - Dart/Flutter packages
- `hex` - Erlang/Elixir packages
- `cocoapods` - iOS/macOS packages
- `swift` - Swift packages

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    VulnerabilityManager                      │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────┐│
│  │  GHSA   │ │   NVD   │ │   OSV   │ │   KEV   │ │  EPSS  ││
│  │ Source  │ │ Source  │ │ Source  │ │ Source  │ │ Source ││
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └───┬────┘│
│       │           │           │           │          │      │
│       └───────────┴─────┬─────┴───────────┴──────────┘      │
│                         │                                    │
│                    ┌────▼────┐                               │
│                    │Aggregator│                              │
│                    └────┬────┘                               │
│                         │                                    │
│                    ┌────▼────┐                               │
│                    │  Store  │ ◄── Redis/DragonflyDB        │
│                    └─────────┘     + zstd compression       │
└─────────────────────────────────────────────────────────────┘
```

## Data Model

Advisories follow the [OSV Schema](https://ossf.github.io/osv-schema/):

```rust
pub struct Advisory {
    pub id: String,                    // e.g., "CVE-2021-23337", "GHSA-xxxx"
    pub summary: Option<String>,
    pub details: Option<String>,
    pub affected: Vec<Affected>,       // Affected packages and versions
    pub references: Vec<Reference>,
    pub published: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub aliases: Option<Vec<String>>,  // Cross-references (CVE ↔ GHSA)
    pub enrichment: Option<Enrichment>, // EPSS, KEV data
}
```

## Performance

- **Compressed Storage**: zstd compression reduces Redis memory usage by ~70%
- **Batch Operations**: Efficient bulk inserts and queries
- **Incremental Sync**: Only fetches new/modified advisories after initial sync
- **Parallel Fetching**: Sources are synced concurrently
- **Query Caching**: OSS Index results cached with configurable TTL

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

This is an open source project from the Vulnera organization. We welcome contributions from the security community!

### How to Contribute

- Fork the repository
- Create a feature branch
- Submit a Pull Request with detailed description
- Follow the existing code style and patterns
- Add tests for new functionality

### Security Contributions

We particularly welcome contributions that:

- Improve security coverage
- Add new vulnerability sources
- Enhance matching algorithms
- Optimize performance for large-scale analysis

## About Vulnera

Vulnera is an organization dedicated to providing open source security tools and libraries that help developers build more secure applications. Our projects focus on making security accessible and actionable through practical, well-maintained tools.

Our mission is to democratize security by providing high-quality, open source tools that can be easily integrated into development workflows.
