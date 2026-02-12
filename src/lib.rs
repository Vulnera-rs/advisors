//! # Vulnera Advisors
//!
//! A Rust library for aggregating and querying security vulnerability advisories
//! from multiple sources including GitHub Security Advisories (GHSA), NIST NVD,
//! and Google OSV.
//!
//! ## Features
//!
//! - **Multi-source aggregation**: Fetch from GHSA, NVD, OSV, CISA KEV, and OSS Index
//! - **Unified data model**: All sources are normalized to a common Advisory format
//! - **Enrichment**: EPSS scores and KEV status for prioritization
//! - **Efficient storage**: Redis/DragonflyDB with zstd compression
//! - **Flexible matching**: SemVer and ecosystem-specific version matching
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use vulnera_advisors::{VulnerabilityManager, Config};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Load config from environment
//!     let config = Config::from_env()?;
//!     let manager = VulnerabilityManager::new(config).await?;
//!
//!     // Sync advisories from all sources
//!     manager.sync_all().await?;
//!
//!     // Query vulnerabilities for a package
//!     let advisories = manager.query("npm", "lodash").await?;
//!
//!     // Check if a specific version is affected
//!     let affected = manager.matches("npm", "lodash", "4.17.20").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Builder Pattern
//!
//! For more control over configuration:
//!
//! ```rust,ignore
//! use vulnera_advisors::VulnerabilityManager;
//!
//! let manager = VulnerabilityManager::builder()
//!     .redis_url("redis://localhost:6379")
//!     .with_osv_defaults()
//!     .with_nvd(Some("your-api-key".to_string()))
//!     .with_ghsa("your-github-token".to_string())
//!     .build()?;
//! ```

pub mod aggregator;
pub mod config;
pub mod ecosystem;
pub mod error;
pub mod logging;
pub mod manager;
pub mod models;
pub mod purl;
pub mod remediation;
pub mod sources;
pub mod store;
pub mod version_registry;

// Re-export main types
pub use config::{Config, NvdConfig, OssIndexConfig, StoreConfig};
pub use error::{AdvisoryError, Result};
pub use manager::{
    BatchFailure, BatchFailureStage, BatchOutcome, BatchSummary, MatchOptions, PackageKey,
    VulnerabilityManager, VulnerabilityManagerBuilder,
};
pub use models::{
    Advisory, Affected, Enrichment, Event, Package, Range, RangeTranslation,
    RangeTranslationStatus, RangeType, Reference, ReferenceType, Severity,
};
pub use store::{AdvisoryStore, DragonflyStore, EnrichmentData, HealthStatus, OssIndexCache};

// Re-export remediation types
pub use remediation::{Remediation, UpgradeImpact, build_remediation, classify_upgrade_impact};
pub use version_registry::{PackageRegistry, VersionRegistry};

// Re-export PURL helper
pub use purl::{KNOWN_ECOSYSTEMS, Purl, PurlError, purl, purls_from_packages, purls_to_strings};

// Re-export source types
pub use sources::{
    AdvisorySource,
    epss::{EpssScore, EpssSource},
    ghsa::GHSASource,
    kev::{KevEntry, KevSource},
    nvd::NVDSource,
    ossindex::{ComponentReport, OssIndexSource, OssVulnerability},
    osv::OSVSource,
};
