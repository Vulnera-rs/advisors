# Version Registry API

The Version Registry provides integration with package registries to fetch available versions.

## Types

### VersionRegistry Trait

Trait for fetching package versions from registries.

```rust
#[async_trait]
pub trait VersionRegistry: Send + Sync {
    async fn get_versions(&self, ecosystem: &str, package: &str) -> Result<Vec<String>>;
}
```

### PackageRegistry

Multi-ecosystem registry implementation.

```rust
use vulnera_advisor::PackageRegistry;

let registry = PackageRegistry::new();
let versions = registry.get_versions("npm", "lodash").await?;
```

## Supported Ecosystems

| Ecosystem | Registry URL | Aliases |
|-----------|-------------|---------|
| npm | registry.npmjs.org | - |
| PyPI | pypi.org | `pip` |
| Maven | search.maven.org | - |
| Cargo | crates.io | `crates.io` |
| Go | proxy.golang.org | `golang` |
| Composer | repo.packagist.org | `packagist` |
| RubyGems | rubygems.org | `gem`, `bundler` |
| NuGet | api.nuget.org | - |

## Usage Examples

### Basic Version Fetch

```rust
use vulnera_advisor::PackageRegistry;

let registry = PackageRegistry::new();

// npm packages
let versions = registry.get_versions("npm", "lodash").await?;

// Python packages
let versions = registry.get_versions("pypi", "requests").await?;

// Rust crates
let versions = registry.get_versions("cargo", "serde").await?;
```

### Maven Packages

Maven packages require the `group:artifact` format:

```rust
let versions = registry
    .get_versions("maven", "org.apache.logging.log4j:log4j-core")
    .await?;
```

### Custom HTTP Client

```rust
let client = reqwest::Client::builder()
    .timeout(std::time::Duration::from_secs(60))
    .build()?;

let registry = PackageRegistry::with_client(client);
```

### With Remediation

```rust
use vulnera_advisor::{VulnerabilityManager, PackageRegistry};

let manager = VulnerabilityManager::builder()
    .redis_url("redis://localhost:6379")
    .with_osv_defaults()
    .build()?;

let registry = PackageRegistry::new();

let remediation = manager
    .suggest_remediation_with_registry("npm", "lodash", "4.17.20", &registry)
    .await?;

println!("Safe versions available:");
println!("  Nearest: {:?}", remediation.nearest_safe);
println!("  Latest:  {:?}", remediation.latest_safe);
```

## Custom Registry Implementation

Implement `VersionRegistry` for custom package sources:

```rust
use vulnera_advisor::{VersionRegistry, Result};
use async_trait::async_trait;

struct MyRegistry;

#[async_trait]
impl VersionRegistry for MyRegistry {
    async fn get_versions(&self, ecosystem: &str, package: &str) -> Result<Vec<String>> {
        // Fetch versions from your custom source
        Ok(vec!["1.0.0".to_string(), "1.1.0".to_string()])
    }
}
```
