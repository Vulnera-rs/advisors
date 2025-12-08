# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2025-12-08

### Added
- Ecosystem-aware range matcher with dotted numeric fallback for non-SemVer ecosystems.
- Enrichment sync now accepts extra CVE IDs for broader EPSS coverage via `sync_enrichment_with_cves`.
- New unit tests for semver interval matching, ecosystem ranges, and enrichment helpers.

### Changed
- OSS Index grouping now matches ecosystem and version to avoid cross-ecosystem collisions.
- Package fetches use batched retrieval to reduce Redis round trips.

### Fixed
- Clippy-cleanup across aggregator and OSV source (entry API, Copy captures).

## [0.1.2] - 2025-11-29

### Fixed
- **GHSA Source**: Fixed GraphQL error by switching to `securityAdvisories` query root to support `updatedSince` argument.

## [0.1.1] - 2025-11-25

### Added
- **Sync Examples**: Added example for syncing advisories from multiple sources.
- **Timestamp Reset**: Implement reset functionality for sync timestamps in `VulnerabilityManager`.
- **NVD Parsing**: Added custom deserializer for NVD datetime format.
- **OSV Concurrency**: Enhance OSV source to support concurrent ecosystem syncs and advisory fetching.

### Changed
- **Batch Querying**: Enhanced batch querying for advisories with concurrent execution.
- **Resilience**: Refactored EPSS and GHSA sources to use reqwest middleware with retry policies.
- **Store Interface**: Update store interface to include reset sync timestamp functionality.
- **Dependencies**: Bumped version and updated dependencies.

### Fixed
- **Timestamps**: Improved advisory storage logic to update timestamps only on successful sync.
- **Error Handling**: Improved error handling in NVD and GHSA sources for better debugging.

## [0.1.0] - 2025-11-25

### Added

#### Core Features
- **Unified Advisory Model**: OSV-compatible `Advisory` struct as the canonical data format
- **VulnerabilityManager**: Main entry point for syncing and querying vulnerabilities
- **Builder Pattern**: `VulnerabilityManagerBuilder` for flexible configuration
- **Custom Error Types**: `AdvisoryError` enum with typed variants for different error conditions

#### Vulnerability Sources
- **GHSA (GitHub Security Advisories)**: GraphQL API integration with pagination
- **NVD (National Vulnerability Database)**: REST API v2.0 with rate limiting
- **OSV (Open Source Vulnerabilities)**: Bulk ZIP downloads for multiple ecosystems
- **CISA KEV**: Known Exploited Vulnerabilities catalog integration
- **EPSS**: Exploit Prediction Scoring System scores
- **OSS Index**: On-demand PURL-based queries with automatic batching (128 components/request)

#### Storage
- **DragonflyStore**: Redis/DragonflyDB backend implementation
- **zstd Compression**: Advisory data compressed before storage (~70% space savings)
- **Indexing**: Package-based indexes for efficient querying
- **TTL Support**: Configurable time-to-live for cached data

#### Version Matching
- **SemVer Support**: Version range matching using `introduced`, `fixed`, `last_affected` events
- **Ecosystem Ranges**: Fallback to semver for ecosystem-specific ranges
- **Match Options**: Filter by CVSS score, EPSS score, KEV status, severity level

#### PURL Support
- **Purl Builder**: Type-safe Package URL construction
- **Ecosystem Mapping**: Automatic mapping (e.g., "crates.io" → "cargo", "PyPI" → "pypi")
- **Validation**: Known ecosystem validation with `KNOWN_ECOSYSTEMS` constant
- **Parsing**: Parse existing PURL strings back to structured format
- **Cache Keys**: Deterministic hash generation for cache keys

#### OSS Index Integration
- **Auto-Caching**: Query results cached with configurable TTL (default: 1 hour)
- **Batch Queries**: Automatic chunking for large PURL lists
- **Parallel Execution**: Concurrent requests with semaphore-based rate limiting
- **Fallback Support**: `query_batch_with_ossindex()` falls back to local store on failure
- **Cache Invalidation**: Methods to invalidate specific PURLs or all cached results

#### Enrichment
- **EPSS Scores**: Exploit probability and percentile data
- **KEV Status**: Active exploitation indicator with due dates
- **CVSS Severity**: Automatic severity level from CVSS v3 scores
- **Ransomware Flag**: KEV ransomware campaign association

#### Configuration
- **Environment Variables**: Load config from `REDIS_URL`, `VULNERA__*` variables
- **Per-Source Config**: `NvdConfig`, `OssIndexConfig`, `StoreConfig`
- **Rate Limiting**: Configurable requests per window for NVD API

### Supported Ecosystems

Initial support for the following package ecosystems:
- npm (Node.js)
- PyPI (Python)
- cargo/crates.io (Rust)
- Maven (Java/Kotlin)
- NuGet (.NET)
- gem/RubyGems (Ruby)
- golang/Go (Go modules)
- composer/Packagist (PHP)
- pub (Dart/Flutter)
- hex (Erlang/Elixir)
- cocoapods (iOS/macOS)
- swift (Swift)
- conda (Conda)
- deb (Debian)
- rpm (RPM)

### API

#### Main Types
- `VulnerabilityManager` - Orchestrates sync and query operations
- `Advisory` - Canonical vulnerability advisory format
- `Affected` - Affected package with version ranges
- `Enrichment` - EPSS/KEV enrichment data
- `Purl` - Package URL builder and parser

#### Source Types
- `GHSASource` - GitHub Security Advisories
- `NVDSource` - NIST NVD
- `OSVSource` - Google OSV
- `KevSource` - CISA KEV
- `EpssSource` - FIRST EPSS
- `OssIndexSource` - Sonatype OSS Index

#### Store Types
- `AdvisoryStore` - Storage trait
- `DragonflyStore` - Redis implementation
- `OssIndexCache` - Cached OSS Index results

### Dependencies

- `tokio` - Async runtime
- `reqwest` - HTTP client with retry middleware
- `redis` - Redis client with async support
- `serde` / `serde_json` - Serialization
- `chrono` - Date/time handling
- `semver` - Version parsing and comparison
- `zstd` - Compression
- `thiserror` - Error handling
- `tracing` - Logging

[0.1.0]: https://github.com/Vulnera-rs/advisors/releases/tag/v0.1.0
