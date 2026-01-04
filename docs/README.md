# Vulnera Advisor API Documentation

Welcome to the API documentation for **Vulnera Advisor** - a Rust library for aggregating and querying security vulnerability advisories.

## Table of Contents

- [Core Types](./api/core-types.md) - Main types and structs
- [Remediation API](./api/remediation.md) - Safe version suggestions
- [Version Registry](./api/version-registry.md) - Package registry integration
- [Sources](./api/sources.md) - Vulnerability data sources
- [Store](./api/store.md) - Storage backends

## Quick Links

- [Getting Started](#getting-started)
- [API Reference](https://docs.rs/vulnera-advisor)
- [GitHub Repository](https://github.com/Vulnera-rs/advisors)
- [Crates.io](https://crates.io/crates/vulnera-advisor)

## Getting Started

Add Vulnera Advisor to your `Cargo.toml`:

```toml
[dependencies]
vulnera-advisor = "0.1.6"
```

### Basic Usage

```rust
use vulnera_advisor::{VulnerabilityManager, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let manager = VulnerabilityManager::new(config).await?;

    // Sync advisories
    manager.sync_all().await?;

    // Check for vulnerabilities
    let vulns = manager.matches("npm", "lodash", "4.17.20").await?;
    
    // Get remediation suggestions
    let remediation = manager.suggest_remediation("npm", "lodash", "4.17.20").await?;
    
    Ok(())
}
```

## Module Overview

| Module | Description |
|--------|-------------|
| `manager` | Main `VulnerabilityManager` for orchestrating queries |
| `remediation` | Safe version recommendations and upgrade analysis |
| `version_registry` | Package registry integration for version lookups |
| `models` | Core data types (`Advisory`, `Affected`, `Enrichment`) |
| `sources` | Vulnerability source implementations (GHSA, NVD, OSV, etc.) |
| `store` | Redis/DragonflyDB storage backend |
| `purl` | Package URL builder and parser |
