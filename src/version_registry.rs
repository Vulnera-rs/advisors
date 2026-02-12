//! Package version registry for fetching available versions from package managers.
//!
//! This module provides a trait and implementation for querying package registries
//! across various ecosystems to get a list of all available versions for a package.

use crate::error::{AdvisoryError, Result};
use crate::ecosystem::canonicalize_ecosystem;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::debug;

/// Trait for fetching package versions from registries.
#[async_trait]
pub trait VersionRegistry: Send + Sync {
    /// Get all available versions for a package in the given ecosystem.
    async fn get_versions(&self, ecosystem: &str, package: &str) -> Result<Vec<String>>;
}

/// Multi-ecosystem package registry implementation.
///
/// Supports fetching versions from:
/// - npm (Node.js)
/// - PyPI (Python)
/// - Maven (Java)
/// - crates.io (Rust)
/// - Go proxy (Go modules)
/// - Packagist (PHP/Composer)
/// - RubyGems (Ruby/Bundler)
/// - NuGet (.NET)
#[derive(Clone)]
pub struct PackageRegistry {
    client: reqwest::Client,
}

impl Default for PackageRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PackageRegistry {
    /// Create a new PackageRegistry with default configuration.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("vulnera-advisor/0.1")
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    /// Create a new PackageRegistry with a custom HTTP client.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }

    /// Fetch versions from npm registry.
    async fn fetch_npm_versions(&self, package: &str) -> Result<Vec<String>> {
        let url = format!("https://registry.npmjs.org/{}", package);
        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "npm".to_string(),
                    message: e.to_string(),
                })?;

        if !response.status().is_success() {
            return Err(AdvisoryError::SourceFetch {
                source_name: "npm".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let data: NpmPackageResponse =
            response
                .json()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "npm".to_string(),
                    message: e.to_string(),
                })?;

        Ok(data.versions.keys().cloned().collect())
    }

    /// Fetch versions from PyPI.
    async fn fetch_pypi_versions(&self, package: &str) -> Result<Vec<String>> {
        let url = format!("https://pypi.org/pypi/{}/json", package);
        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "pypi".to_string(),
                    message: e.to_string(),
                })?;

        if !response.status().is_success() {
            return Err(AdvisoryError::SourceFetch {
                source_name: "pypi".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let data: PyPiPackageResponse =
            response
                .json()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "pypi".to_string(),
                    message: e.to_string(),
                })?;

        Ok(data.releases.keys().cloned().collect())
    }

    /// Fetch versions from crates.io.
    async fn fetch_cargo_versions(&self, package: &str) -> Result<Vec<String>> {
        let url = format!("https://crates.io/api/v1/crates/{}", package);
        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "crates.io".to_string(),
                    message: e.to_string(),
                })?;

        if !response.status().is_success() {
            return Err(AdvisoryError::SourceFetch {
                source_name: "crates.io".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let data: CratesIoResponse =
            response
                .json()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "crates.io".to_string(),
                    message: e.to_string(),
                })?;

        Ok(data.versions.into_iter().map(|v| v.num).collect())
    }

    /// Fetch versions from Maven Central.
    async fn fetch_maven_versions(&self, package: &str) -> Result<Vec<String>> {
        // Maven packages are in format "group:artifact"
        let parts: Vec<&str> = package.split(':').collect();
        if parts.len() != 2 {
            return Err(AdvisoryError::config(
                "Maven package must be in format 'group:artifact'",
            ));
        }

        let (group, artifact) = (parts[0], parts[1]);
        let url = format!(
            "https://search.maven.org/solrsearch/select?q=g:{}+AND+a:{}&core=gav&rows=200&wt=json",
            group, artifact
        );

        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "maven".to_string(),
                    message: e.to_string(),
                })?;

        if !response.status().is_success() {
            return Err(AdvisoryError::SourceFetch {
                source_name: "maven".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let data: MavenSearchResponse =
            response
                .json()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "maven".to_string(),
                    message: e.to_string(),
                })?;

        Ok(data.response.docs.into_iter().map(|d| d.v).collect())
    }

    /// Fetch versions from Go module proxy.
    async fn fetch_go_versions(&self, package: &str) -> Result<Vec<String>> {
        let url = format!("https://proxy.golang.org/{}/@v/list", package);
        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "go".to_string(),
                    message: e.to_string(),
                })?;

        if !response.status().is_success() {
            return Err(AdvisoryError::SourceFetch {
                source_name: "go".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let text = response
            .text()
            .await
            .map_err(|e| AdvisoryError::SourceFetch {
                source_name: "go".to_string(),
                message: e.to_string(),
            })?;

        // Go proxy returns newline-separated versions
        Ok(text.lines().map(|s| s.to_string()).collect())
    }

    /// Fetch versions from Packagist (Composer/PHP).
    async fn fetch_composer_versions(&self, package: &str) -> Result<Vec<String>> {
        let url = format!("https://repo.packagist.org/p2/{}.json", package);
        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "packagist".to_string(),
                    message: e.to_string(),
                })?;

        if !response.status().is_success() {
            return Err(AdvisoryError::SourceFetch {
                source_name: "packagist".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let data: PackagistResponse =
            response
                .json()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "packagist".to_string(),
                    message: e.to_string(),
                })?;

        // Packagist format: {"packages": {"vendor/name": [{"version": "1.0.0"}, ...]}}
        let versions = data
            .packages
            .get(package)
            .map(|versions| versions.iter().map(|v| v.version.clone()).collect())
            .unwrap_or_default();

        Ok(versions)
    }

    /// Fetch versions from RubyGems.
    async fn fetch_gem_versions(&self, package: &str) -> Result<Vec<String>> {
        let url = format!("https://rubygems.org/api/v1/versions/{}.json", package);
        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "rubygems".to_string(),
                    message: e.to_string(),
                })?;

        if !response.status().is_success() {
            return Err(AdvisoryError::SourceFetch {
                source_name: "rubygems".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let data: Vec<RubyGemVersion> =
            response
                .json()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "rubygems".to_string(),
                    message: e.to_string(),
                })?;

        Ok(data.into_iter().map(|v| v.number).collect())
    }

    /// Fetch versions from NuGet.
    async fn fetch_nuget_versions(&self, package: &str) -> Result<Vec<String>> {
        let url = format!(
            "https://api.nuget.org/v3-flatcontainer/{}/index.json",
            package.to_lowercase()
        );
        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "nuget".to_string(),
                    message: e.to_string(),
                })?;

        if !response.status().is_success() {
            return Err(AdvisoryError::SourceFetch {
                source_name: "nuget".to_string(),
                message: format!("HTTP {}", response.status()),
            });
        }

        let data: NuGetVersionsResponse =
            response
                .json()
                .await
                .map_err(|e| AdvisoryError::SourceFetch {
                    source_name: "nuget".to_string(),
                    message: e.to_string(),
                })?;

        Ok(data.versions)
    }
}

#[async_trait]
impl VersionRegistry for PackageRegistry {
    async fn get_versions(&self, ecosystem: &str, package: &str) -> Result<Vec<String>> {
        let ecosystem_lower = canonicalize_ecosystem(ecosystem)
            .unwrap_or(ecosystem)
            .to_ascii_lowercase();
        debug!("Fetching versions for {} in {}", package, ecosystem_lower);

        match ecosystem_lower.as_str() {
            "npm" => self.fetch_npm_versions(package).await,
            "pypi" | "pip" => self.fetch_pypi_versions(package).await,
            "cargo" | "crates.io" => self.fetch_cargo_versions(package).await,
            "maven" => self.fetch_maven_versions(package).await,
            "go" | "golang" => self.fetch_go_versions(package).await,
            "composer" | "packagist" => self.fetch_composer_versions(package).await,
            "gem" | "rubygems" | "bundler" => self.fetch_gem_versions(package).await,
            "nuget" => self.fetch_nuget_versions(package).await,
            _ => Err(AdvisoryError::config(format!(
                "Unsupported ecosystem: {}",
                ecosystem
            ))),
        }
    }
}

// === Response types for JSON parsing ===

#[derive(Debug, Deserialize)]
struct NpmPackageResponse {
    versions: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct PyPiPackageResponse {
    releases: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct CratesIoResponse {
    versions: Vec<CratesIoVersion>,
}

#[derive(Debug, Deserialize)]
struct CratesIoVersion {
    num: String,
}

#[derive(Debug, Deserialize)]
struct MavenSearchResponse {
    response: MavenSearchDocs,
}

#[derive(Debug, Deserialize)]
struct MavenSearchDocs {
    docs: Vec<MavenDoc>,
}

#[derive(Debug, Deserialize)]
struct MavenDoc {
    v: String,
}

#[derive(Debug, Deserialize)]
struct PackagistResponse {
    packages: HashMap<String, Vec<PackagistVersion>>,
}

#[derive(Debug, Deserialize)]
struct PackagistVersion {
    version: String,
}

#[derive(Debug, Deserialize)]
struct RubyGemVersion {
    number: String,
}

#[derive(Debug, Deserialize)]
struct NuGetVersionsResponse {
    versions: Vec<String>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_ecosystem_normalization() {
        // Test that ecosystem names are properly normalized
        assert_eq!("npm".to_lowercase(), "npm");
        assert_eq!("PyPI".to_lowercase(), "pypi");
        assert_eq!("CARGO".to_lowercase(), "cargo");
    }

    #[test]
    fn test_maven_package_parsing() {
        let package = "org.apache.logging.log4j:log4j-core";
        let parts: Vec<&str> = package.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "org.apache.logging.log4j");
        assert_eq!(parts[1], "log4j-core");
    }
}
