//! Vulnerability manager for orchestrating syncs and queries.
//!
//! The [`VulnerabilityManager`] is the main entry point for using this crate.
//! Use [`VulnerabilityManagerBuilder`] for flexible configuration.

use crate::config::{Config, OssIndexConfig, StoreConfig};
use crate::ecosystem::normalize_package_key;
use crate::error::{AdvisoryError, Result};
use crate::models::{Advisory, Enrichment, Event, RangeType, Severity};
use crate::purl::Purl;
use crate::sources::epss::EpssSource;
use crate::sources::kev::KevSource;
use crate::sources::ossindex::OssIndexSource;
use crate::sources::{AdvisorySource, ghsa::GHSASource, nvd::NVDSource, osv::OSVSource};
use crate::store::{AdvisoryStore, DragonflyStore, EnrichmentData, HealthStatus, OssIndexCache};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Options for filtering vulnerability matches.
#[derive(Debug, Clone, Default)]
pub struct MatchOptions {
    /// Minimum CVSS v3 score (0.0 - 10.0).
    pub min_cvss: Option<f64>,
    /// Minimum EPSS score (0.0 - 1.0).
    pub min_epss: Option<f64>,
    /// Only return KEV (actively exploited) vulnerabilities.
    pub kev_only: bool,
    /// Minimum severity level.
    pub min_severity: Option<Severity>,
    /// Include enrichment data (EPSS, KEV) in results.
    pub include_enrichment: bool,
    /// Filter by CWE IDs (e.g., ["CWE-79", "CWE-89"]).
    /// Only advisories with at least one matching CWE will be returned.
    pub cwe_ids: Option<Vec<String>>,
}

/// Statistics for a sync operation.
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    /// Total number of sources attempted.
    pub total_sources: usize,
    /// Number of sources that synced successfully.
    pub successful_sources: usize,
    /// Number of sources that failed.
    pub failed_sources: usize,
    /// Total advisories synced across all sources.
    pub total_advisories_synced: usize,
    /// Map of source name to error message for failed sources.
    pub errors: HashMap<String, String>,
}

/// Observer for monitoring sync progress and events.
pub trait SyncObserver: Send + Sync {
    /// Called when the sync operation starts.
    fn on_sync_start(&self);

    /// Called when a specific source starts syncing.
    fn on_source_start(&self, source_name: &str);

    /// Called when a source successfully syncs.
    fn on_source_success(&self, source_name: &str, count: usize);

    /// Called when a source fails to sync.
    fn on_source_error(&self, source_name: &str, error: &crate::error::AdvisoryError);

    /// Called when the sync operation completes.
    fn on_sync_complete(&self, stats: &SyncStats);
}

/// Default observer that logs events using the `tracing` crate.
pub struct TracingSyncObserver;

impl SyncObserver for TracingSyncObserver {
    fn on_sync_start(&self) {
        info!("Starting full vulnerability sync...");
    }

    fn on_source_start(&self, source_name: &str) {
        debug!("Syncing {}...", source_name);
    }

    fn on_source_success(&self, source_name: &str, count: usize) {
        if count > 0 {
            info!(
                "Successfully synced {} advisories from {}",
                count, source_name
            );
        } else {
            debug!(
                "Successfully synced {} advisories from {}",
                count, source_name
            );
        }
    }

    fn on_source_error(&self, source_name: &str, error: &crate::error::AdvisoryError) {
        error!("Failed to sync {}: {}", source_name, error);
    }

    fn on_sync_complete(&self, _stats: &SyncStats) {
        info!("Sync completed.");
    }
}

impl MatchOptions {
    /// Create options that include all vulnerabilities with enrichment.
    pub fn with_enrichment() -> Self {
        Self {
            include_enrichment: true,
            ..Default::default()
        }
    }

    /// Create options for high-severity vulnerabilities only.
    pub fn high_severity() -> Self {
        Self {
            min_severity: Some(Severity::High),
            include_enrichment: true,
            ..Default::default()
        }
    }

    /// Create options for actively exploited vulnerabilities only.
    pub fn exploited_only() -> Self {
        Self {
            kev_only: true,
            include_enrichment: true,
            ..Default::default()
        }
    }

    /// Create options to filter by specific CWE IDs.
    ///
    /// Only advisories containing at least one of the specified CWEs will match.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use vulnera_advisors::MatchOptions;
    ///
    /// // Filter for XSS (CWE-79) or SQL Injection (CWE-89)
    /// let options = MatchOptions::with_cwes(vec!["CWE-79".to_string(), "CWE-89".to_string()]);
    /// ```
    pub fn with_cwes(cwe_ids: Vec<String>) -> Self {
        Self {
            cwe_ids: Some(cwe_ids),
            include_enrichment: true,
            ..Default::default()
        }
    }
}

/// A key identifying a package for batch queries.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct PackageKey {
    /// Package ecosystem (e.g., "npm", "PyPI").
    pub ecosystem: String,
    /// Package name.
    pub name: String,
    /// Optional version for matching.
    pub version: Option<String>,
}

/// Stage where a batch query failure occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchFailureStage {
    /// Local advisory store lookup/filtering failed.
    StoreLookup,
    /// OSS Index enrichment query failed.
    OssIndex,
}

/// Structured per-package failure details for batch operations.
#[derive(Debug, Clone)]
pub struct BatchFailure {
    /// Package key associated with the failure.
    pub package: PackageKey,
    /// Stage that produced the error.
    pub stage: BatchFailureStage,
    /// Whether the failure is retryable.
    pub retryable: bool,
    /// Error message for diagnostics.
    pub error: String,
}

/// Aggregate batch query summary counters.
#[derive(Debug, Clone, Default)]
pub struct BatchSummary {
    /// Number of requested packages.
    pub total: usize,
    /// Number of packages with successful results.
    pub succeeded: usize,
    /// Number of packages that failed.
    pub failed: usize,
    /// Aggregated range translation status counters from returned advisories.
    pub range_translation_statuses: HashMap<String, usize>,
}

/// Structured output for batch operations.
#[derive(Debug, Clone)]
pub struct BatchOutcome<T> {
    /// Successful results keyed by package.
    pub successes: HashMap<PackageKey, T>,
    /// Per-package failures with stage metadata.
    pub failures: Vec<BatchFailure>,
    /// Aggregate counters.
    pub summary: BatchSummary,
}

impl<T> BatchOutcome<T> {
    fn from_parts(
        successes: HashMap<PackageKey, T>,
        failures: Vec<BatchFailure>,
        total: usize,
    ) -> Self {
        use std::collections::HashSet;

        let failed_packages: HashSet<_> = failures
            .iter()
            .map(|failure| failure.package.clone())
            .collect();
        Self {
            summary: BatchSummary {
                total,
                succeeded: successes.len(),
                failed: failed_packages.len(),
                range_translation_statuses: HashMap::new(),
            },
            successes,
            failures,
        }
    }
}

impl PackageKey {
    /// Create a new package key.
    pub fn new(ecosystem: impl Into<String>, name: impl Into<String>) -> Self {
        let (ecosystem, name) = normalize_package_key(&ecosystem.into(), &name.into());
        Self {
            ecosystem,
            name,
            version: None,
        }
    }

    /// Create a package key with a version.
    pub fn with_version(
        ecosystem: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        let (ecosystem, name) = normalize_package_key(&ecosystem.into(), &name.into());
        Self {
            ecosystem,
            name,
            version: Some(version.into()),
        }
    }
}

/// Builder for configuring VulnerabilityManager.
pub struct VulnerabilityManagerBuilder {
    redis_url: Option<String>,
    store_config: StoreConfig,
    sources: Vec<Arc<dyn AdvisorySource + Send + Sync>>,
    custom_store: Option<Arc<dyn AdvisoryStore + Send + Sync>>,
    ossindex_source: Option<OssIndexSource>,
    observer: Option<Arc<dyn SyncObserver>>,
}

impl Default for VulnerabilityManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnerabilityManagerBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self {
            redis_url: None,
            store_config: StoreConfig::default(),
            sources: Vec::new(),
            custom_store: None,
            ossindex_source: None,
            observer: None,
        }
    }

    /// Set the Redis connection URL.
    pub fn redis_url(mut self, url: impl Into<String>) -> Self {
        self.redis_url = Some(url.into());
        self
    }

    /// Set the store configuration.
    pub fn store_config(mut self, config: StoreConfig) -> Self {
        self.store_config = config;
        self
    }

    /// Use a custom store implementation.
    pub fn store(mut self, store: Arc<dyn AdvisoryStore + Send + Sync>) -> Self {
        self.custom_store = Some(store);
        self
    }

    /// Add a vulnerability source.
    pub fn add_source(mut self, source: Arc<dyn AdvisorySource + Send + Sync>) -> Self {
        self.sources.push(source);
        self
    }

    /// Add the GHSA source with the given token.
    pub fn with_ghsa(mut self, token: impl Into<String>) -> Self {
        self.sources.push(Arc::new(GHSASource::new(token.into())));
        self
    }

    /// Add the NVD source with optional API key.
    pub fn with_nvd(mut self, api_key: Option<String>) -> Self {
        self.sources.push(Arc::new(NVDSource::new(api_key)));
        self
    }

    /// Add the OSV source for specified ecosystems.
    pub fn with_osv(mut self, ecosystems: Vec<String>) -> Self {
        self.sources.push(Arc::new(OSVSource::new(ecosystems)));
        self
    }

    /// Add default OSV ecosystems.
    pub fn with_osv_defaults(self) -> Self {
        self.with_osv(vec![
            "npm".to_string(),
            "PyPI".to_string(),
            "Maven".to_string(),
            "crates.io".to_string(),
            "Go".to_string(),
            "Packagist".to_string(),
            "RubyGems".to_string(),
            "NuGet".to_string(),
        ])
    }

    /// Add the OSS Index source with optional configuration.
    ///
    /// OSS Index provides on-demand vulnerability queries by PURL.
    /// If no config is provided, credentials are loaded from environment variables.
    pub fn with_ossindex(mut self, config: Option<OssIndexConfig>) -> Self {
        match OssIndexSource::new(config) {
            Ok(source) => {
                self.ossindex_source = Some(source);
            }
            Err(e) => {
                warn!("Failed to configure OSS Index source: {}", e);
            }
        }
        self
    }

    /// Set a custom sync observer.
    pub fn with_observer(mut self, observer: Arc<dyn SyncObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Build the VulnerabilityManager.
    pub fn build(self) -> Result<VulnerabilityManager> {
        let store: Arc<dyn AdvisoryStore + Send + Sync> = match self.custom_store {
            Some(s) => s,
            None => {
                let url = self.redis_url.ok_or_else(|| {
                    AdvisoryError::config("Redis URL is required. Use .redis_url() or .store()")
                })?;
                Arc::new(DragonflyStore::with_config(&url, self.store_config)?)
            }
        };

        if self.sources.is_empty() {
            warn!("No sources configured. Use .with_ghsa(), .with_nvd(), or .with_osv()");
        }

        Ok(VulnerabilityManager {
            store,
            sources: self.sources,
            kev_source: KevSource::new(),
            epss_source: EpssSource::new(),
            ossindex_source: self.ossindex_source,
            observer: self
                .observer
                .unwrap_or_else(|| Arc::new(TracingSyncObserver)),
        })
    }
}

/// Main vulnerability manager for syncing and querying advisories.
pub struct VulnerabilityManager {
    store: Arc<dyn AdvisoryStore + Send + Sync>,
    sources: Vec<Arc<dyn AdvisorySource + Send + Sync>>,
    kev_source: KevSource,
    epss_source: EpssSource,
    ossindex_source: Option<OssIndexSource>,
    observer: Arc<dyn SyncObserver>,
}

impl VulnerabilityManager {
    fn collect_range_translation_statuses(
        advisories_by_package: &HashMap<PackageKey, Vec<Advisory>>,
    ) -> HashMap<String, usize> {
        let mut counters = HashMap::new();

        for advisories in advisories_by_package.values() {
            for advisory in advisories {
                for affected in &advisory.affected {
                    let Some(database_specific) = &affected.database_specific else {
                        continue;
                    };
                    let Some(status) = database_specific
                        .get("range_translation")
                        .and_then(|translation| translation.get("status"))
                        .and_then(|status| status.as_str())
                    else {
                        continue;
                    };

                    *counters.entry(status.to_string()).or_insert(0) += 1;
                }
            }
        }

        counters
    }

    /// Create a new manager from a Config.
    ///
    /// This is a convenience method. For more control, use [`VulnerabilityManagerBuilder`].
    pub async fn new(config: Config) -> Result<Self> {
        let mut builder = VulnerabilityManagerBuilder::new()
            .redis_url(&config.redis_url)
            .store_config(config.store.clone());

        // Add OSV source
        builder = builder.with_osv_defaults();

        // Add NVD source
        builder = builder.with_nvd(config.nvd_api_key.clone());

        // Add GHSA source if token is provided
        if let Some(token) = &config.ghsa_token {
            builder = builder.with_ghsa(token.clone());
        }

        // Add OSS Index source if configured
        if config.ossindex.is_some() {
            builder = builder.with_ossindex(config.ossindex.clone());
        }

        builder.build()
    }

    /// Create a builder for custom configuration.
    pub fn builder() -> VulnerabilityManagerBuilder {
        VulnerabilityManagerBuilder::new()
    }

    /// Get a reference to the underlying store.
    pub fn store(&self) -> &Arc<dyn AdvisoryStore + Send + Sync> {
        &self.store
    }

    /// Check the health of the store connection.
    pub async fn health_check(&self) -> Result<HealthStatus> {
        self.store.health_check().await
    }

    /// Sync advisories from all configured sources.
    pub async fn sync_all(&self) -> Result<SyncStats> {
        self.observer.on_sync_start();

        let mut handles = Vec::new();
        let mut stats = SyncStats {
            total_sources: self.sources.len(),
            ..Default::default()
        };

        for source in &self.sources {
            let source = source.clone();
            let store = self.store.clone();
            let observer = self.observer.clone();

            let handle = tokio::spawn(async move {
                observer.on_source_start(source.name());

                let last_sync = match store.last_sync(source.name()).await {
                    Ok(Some(ts)) => match chrono::DateTime::parse_from_rfc3339(&ts) {
                        Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                        Err(_) => None,
                    },
                    _ => None,
                };

                match source.fetch(last_sync).await {
                    Ok(advisories) => {
                        if !advisories.is_empty() {
                            match store.upsert_batch(&advisories, source.name()).await {
                                Ok(_) => {
                                    observer.on_source_success(source.name(), advisories.len());
                                    // Update timestamp only after successful storage
                                    if let Err(e) = store.update_sync_timestamp(source.name()).await
                                    {
                                        let err = AdvisoryError::source_fetch(
                                            source.name(),
                                            format!("Failed to update timestamp: {}", e),
                                        );
                                        observer.on_source_error(source.name(), &err);
                                        // Non-critical error, count as success but maybe log warn?
                                        // Observer handles logging.
                                    }
                                    Ok((source.name().to_string(), advisories.len()))
                                }
                                Err(e) => {
                                    // Store error is critical for this source
                                    observer.on_source_error(source.name(), &e);
                                    Err((source.name().to_string(), e.to_string()))
                                }
                            }
                        } else {
                            observer.on_source_success(source.name(), 0);
                            // Update sync timestamp even if no new advisories
                            if let Err(e) = store.update_sync_timestamp(source.name()).await {
                                let err = AdvisoryError::source_fetch(
                                    source.name(),
                                    format!("Failed to update timestamp: {}", e),
                                );
                                observer.on_source_error(source.name(), &err);
                            }
                            Ok((source.name().to_string(), 0))
                        }
                    }
                    Err(e) => {
                        observer.on_source_error(source.name(), &e);
                        Err((source.name().to_string(), e.to_string()))
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            match handle.await {
                Ok(result) => match result {
                    Ok((_, count)) => {
                        stats.successful_sources += 1;
                        stats.total_advisories_synced += count;
                    }
                    Err((name, error)) => {
                        stats.failed_sources += 1;
                        stats.errors.insert(name, error);
                    }
                },
                Err(e) => {
                    // Task panic or join error
                    error!("Task join error: {}", e);
                    stats.failed_sources += 1;
                    stats
                        .errors
                        .insert("unknown".to_string(), format!("Task join error: {}", e));
                }
            }
        }

        self.observer.on_sync_complete(&stats);
        Ok(stats)
    }

    /// Reset the sync timestamp for a specific source.
    ///
    /// This forces a full re-sync on the next `sync_all()` call.
    pub async fn reset_sync(&self, source: &str) -> Result<()> {
        self.store.reset_sync_timestamp(source).await
    }

    /// Reset all sync timestamps, forcing a full re-sync of all sources.
    pub async fn reset_all_syncs(&self) -> Result<()> {
        for source in &self.sources {
            self.store.reset_sync_timestamp(source.name()).await?;
        }
        Ok(())
    }

    /// Sync enrichment data (KEV and EPSS).
    pub async fn sync_enrichment(&self) -> Result<()> {
        self.sync_enrichment_with_cves(&[]).await
    }

    /// Sync enrichment data with optional extra CVE IDs to broaden EPSS coverage.
    pub async fn sync_enrichment_with_cves(&self, extra_cves: &[String]) -> Result<()> {
        debug!("Syncing enrichment data (KEV, EPSS)...");

        let mut enrichment: HashMap<String, EnrichmentData> = HashMap::new();

        // Sync KEV data
        match self.kev_source.fetch_catalog().await {
            Ok(kev_entries) => {
                debug!("Processing {} KEV entries", kev_entries.len());
                for (cve_id, entry) in kev_entries {
                    let data = enrichment
                        .entry(cve_id.clone())
                        .or_insert_with(|| EnrichmentData {
                            epss_score: None,
                            epss_percentile: None,
                            is_kev: false,
                            kev_due_date: None,
                            kev_date_added: None,
                            kev_ransomware: None,
                            updated_at: String::new(),
                        });

                    data.is_kev = true;
                    data.kev_due_date = entry.due_date_utc().map(|d| d.to_rfc3339());
                    data.kev_date_added = entry.date_added_utc().map(|d| d.to_rfc3339());
                    data.kev_ransomware = Some(entry.is_ransomware_related());
                }
            }
            Err(e) => {
                error!("Failed to fetch KEV catalog: {}", e);
            }
        }

        // Sync EPSS for known CVEs plus any extra provided by caller
        let epss_targets = Self::collect_enrichment_targets(&enrichment, extra_cves);
        if !epss_targets.is_empty() {
            match self
                .epss_source
                .fetch_scores_batch(&epss_targets, 200)
                .await
            {
                Ok(scores) => {
                    Self::merge_epss_scores(&mut enrichment, scores);
                }
                Err(e) => {
                    warn!("Failed to fetch EPSS scores: {}", e);
                }
            }
        }

        // Persist merged enrichment data
        if !enrichment.is_empty() {
            let now = chrono::Utc::now().to_rfc3339();
            for (cve_id, mut data) in enrichment {
                if data.updated_at.is_empty() {
                    data.updated_at = now.clone();
                }
                if let Err(e) = self.store.store_enrichment(&cve_id, &data).await {
                    debug!("Failed to store enrichment for {}: {}", cve_id, e);
                }
            }
        }

        Ok(())
    }

    /// Build the list of CVE IDs to request EPSS for.
    fn collect_enrichment_targets(
        current: &HashMap<String, EnrichmentData>,
        extra: &[String],
    ) -> Vec<String> {
        let mut set: std::collections::HashSet<String> = current.keys().cloned().collect();
        for c in extra {
            set.insert(c.clone());
        }
        set.into_iter().collect()
    }

    /// Merge EPSS scores into enrichment map.
    fn merge_epss_scores(
        enrichment: &mut HashMap<String, EnrichmentData>,
        scores: HashMap<String, crate::sources::epss::EpssScore>,
    ) {
        for (cve_id, score) in scores {
            let data = enrichment
                .entry(cve_id.clone())
                .or_insert_with(|| EnrichmentData {
                    epss_score: None,
                    epss_percentile: None,
                    is_kev: false,
                    kev_due_date: None,
                    kev_date_added: None,
                    kev_ransomware: None,
                    updated_at: String::new(),
                });

            data.epss_score = Some(score.epss);
            data.epss_percentile = Some(score.percentile);
            if let Some(date) = score.date_utc() {
                data.updated_at = date.to_rfc3339();
            }
        }
    }

    /// Query advisories for a specific package.
    pub async fn query(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>> {
        let (ecosystem, package) = normalize_package_key(ecosystem, package);
        let advisories = self.store.get_by_package(&ecosystem, &package).await?;
        Ok(crate::aggregator::ReportAggregator::aggregate(advisories))
    }

    /// Query advisories with enrichment data.
    pub async fn query_enriched(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>> {
        let mut advisories = self.query(ecosystem, package).await?;
        self.enrich_advisories(&mut advisories).await?;
        Ok(advisories)
    }

    /// Query multiple packages in a batch (concurrent).
    ///
    /// All queries run in parallel for maximum throughput.
    pub async fn query_batch(
        &self,
        packages: &[PackageKey],
    ) -> Result<BatchOutcome<Vec<Advisory>>> {
        use futures_util::future::join_all;

        let tasks: Vec<_> = packages
            .iter()
            .map(|pkg| {
                let pkg = pkg.clone();
                let ecosystem = pkg.ecosystem.clone();
                let name = pkg.name.clone();
                let version = pkg.version.clone();
                let store = self.store.clone();

                async move {
                    let advisories = if let Some(ver) = &version {
                        // For version matching, we need the full logic
                        match store.get_by_package(&ecosystem, &name).await {
                            Ok(all) => {
                                let aggregated =
                                    crate::aggregator::ReportAggregator::aggregate(all);
                                Ok(Self::filter_by_version(aggregated, &ecosystem, &name, ver))
                            }
                            Err(e) => Err(e),
                        }
                    } else {
                        match store.get_by_package(&ecosystem, &name).await {
                            Ok(all) => Ok(crate::aggregator::ReportAggregator::aggregate(all)),
                            Err(e) => Err(e),
                        }
                    };
                    (pkg, advisories)
                }
            })
            .collect();

        let results: Vec<_> = join_all(tasks).await;

        let mut successes = HashMap::new();
        let mut failures = Vec::new();
        for (pkg, result) in results {
            match result {
                Ok(advisories) => {
                    successes.insert(pkg, advisories);
                }
                Err(e) => {
                    failures.push(BatchFailure {
                        package: pkg,
                        stage: BatchFailureStage::StoreLookup,
                        retryable: e.is_retryable(),
                        error: e.to_string(),
                    });
                }
            }
        }

        let mut outcome = BatchOutcome::from_parts(successes, failures, packages.len());
        outcome.summary.range_translation_statuses =
            Self::collect_range_translation_statuses(&outcome.successes);
        Ok(outcome)
    }

    /// Filter advisories by version (static helper for concurrent batch queries)
    fn filter_by_version(
        advisories: Vec<Advisory>,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Vec<Advisory> {
        let (ecosystem, package) = normalize_package_key(ecosystem, package);
        advisories
            .into_iter()
            .filter(|advisory| {
                for affected in &advisory.affected {
                    let (affected_ecosystem, affected_package) =
                        normalize_package_key(&affected.package.ecosystem, &affected.package.name);
                    if affected_package != package || affected_ecosystem != ecosystem {
                        continue;
                    }

                    // Check explicit versions
                    if affected.versions.contains(&version.to_string()) {
                        return true;
                    }

                    // Check ranges
                    for range in &affected.ranges {
                        match range.range_type {
                            RangeType::Semver => {
                                if Self::matches_semver_range(version, &range.events) {
                                    return true;
                                }
                            }
                            RangeType::Ecosystem => {
                                if Self::matches_ecosystem_range(version, &range.events) {
                                    return true;
                                }
                            }
                            RangeType::Git => {}
                        }
                    }
                }
                false
            })
            .collect()
    }

    /// Check if a specific package version is affected by any vulnerabilities.
    pub async fn matches(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Result<Vec<Advisory>> {
        self.matches_with_options(ecosystem, package, version, &MatchOptions::default())
            .await
    }

    /// Check if a package version is affected, with filtering options.
    pub async fn matches_with_options(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
        options: &MatchOptions,
    ) -> Result<Vec<Advisory>> {
        let advisories = self.query(ecosystem, package).await?;
        let mut matched = Vec::new();

        for mut advisory in advisories {
            let mut is_vulnerable = false;
            for affected in &advisory.affected {
                if affected.package.name != package || affected.package.ecosystem != ecosystem {
                    continue;
                }

                // Check explicit versions
                if affected.versions.contains(&version.to_string()) {
                    is_vulnerable = true;
                    break;
                }

                // Check ranges
                for range in &affected.ranges {
                    match range.range_type {
                        RangeType::Semver => {
                            if Self::matches_semver_range(version, &range.events) {
                                is_vulnerable = true;
                                break;
                            }
                        }
                        RangeType::Ecosystem => {
                            if Self::matches_ecosystem_range(version, &range.events) {
                                is_vulnerable = true;
                                break;
                            }
                        }
                        RangeType::Git => {
                            // Git ranges require commit hash comparison, skip for now
                        }
                    }
                }
                if is_vulnerable {
                    break;
                }
            }

            if is_vulnerable {
                // Apply enrichment if requested
                if options.include_enrichment {
                    self.enrich_advisory(&mut advisory).await?;
                }

                // Apply filters
                if self.advisory_passes_filters(&advisory, options) {
                    matched.push(advisory);
                }
            }
        }

        Ok(matched)
    }

    /// Check if a version matches any semver interval described by OSV events.
    ///
    /// OSV allows multiple introduced/fixed pairs; we evaluate each interval in order.
    fn matches_semver_range(version: &str, events: &[Event]) -> bool {
        let Ok(v) = semver::Version::parse(version) else {
            return false;
        };

        #[derive(Default)]
        struct Interval {
            start: Option<semver::Version>,
            end: Option<semver::Version>,
            end_inclusive: bool,
        }

        let mut intervals: Vec<Interval> = Vec::new();
        let mut current_start: Option<semver::Version> = None;

        for event in events {
            match event {
                Event::Introduced(ver) => {
                    if let Ok(parsed) = semver::Version::parse(ver) {
                        current_start = Some(parsed);
                    } else if ver == "0" {
                        current_start = Some(semver::Version::new(0, 0, 0));
                    }
                }
                Event::Fixed(ver) => {
                    let end = semver::Version::parse(ver).ok();
                    intervals.push(Interval {
                        start: current_start.clone(),
                        end,
                        end_inclusive: false,
                    });
                    current_start = None;
                }
                Event::LastAffected(ver) => {
                    let end = semver::Version::parse(ver).ok();
                    intervals.push(Interval {
                        start: current_start.clone(),
                        end,
                        end_inclusive: true,
                    });
                    current_start = None;
                }
                Event::Limit(ver) => {
                    // Treat limit as an exclusive upper bound for any open interval.
                    let end = semver::Version::parse(ver).ok();
                    intervals.push(Interval {
                        start: current_start.clone(),
                        end,
                        end_inclusive: false,
                    });
                    current_start = None;
                }
            }
        }

        // Open-ended interval from the last introduction.
        if current_start.is_some() {
            intervals.push(Interval {
                start: current_start,
                end: None,
                end_inclusive: false,
            });
        }

        intervals.into_iter().any(|interval| {
            if let Some(start) = &interval.start {
                if v < *start {
                    return false;
                }
            }

            match (&interval.end, interval.end_inclusive) {
                (Some(end), true) => v <= *end,
                (Some(end), false) => v < *end,
                (None, _) => true,
            }
        })
    }

    /// Check if a version matches an ecosystem range. Falls back to semver if both parse as semver,
    /// otherwise uses dotted numeric comparison (e.g., "1.10" > "1.2").
    fn matches_ecosystem_range(version: &str, events: &[Event]) -> bool {
        // Try semver first; if any boundary fails semver parsing, fall back to dotted.
        if events.iter().all(|e| match e {
            Event::Introduced(v) | Event::Fixed(v) | Event::LastAffected(v) | Event::Limit(v) => {
                semver::Version::parse(v).is_ok() || v == "0"
            }
        }) {
            return Self::matches_semver_range(version, events);
        }

        let version_parts = match Self::parse_dotted(version) {
            Some(p) => p,
            None => return false,
        };

        #[derive(Default)]
        struct Interval {
            start: Option<Vec<u64>>,
            end: Option<Vec<u64>>,
            end_inclusive: bool,
        }

        let mut intervals: Vec<Interval> = Vec::new();
        let mut current_start: Option<Vec<u64>> = None;

        for event in events {
            match event {
                Event::Introduced(ver) => {
                    current_start = Self::parse_dotted(ver);
                }
                Event::Fixed(ver) => {
                    intervals.push(Interval {
                        start: current_start.clone(),
                        end: Self::parse_dotted(ver),
                        end_inclusive: false,
                    });
                    current_start = None;
                }
                Event::LastAffected(ver) => {
                    intervals.push(Interval {
                        start: current_start.clone(),
                        end: Self::parse_dotted(ver),
                        end_inclusive: true,
                    });
                    current_start = None;
                }
                Event::Limit(ver) => {
                    intervals.push(Interval {
                        start: current_start.clone(),
                        end: Self::parse_dotted(ver),
                        end_inclusive: false,
                    });
                    current_start = None;
                }
            }
        }

        if current_start.is_some() {
            intervals.push(Interval {
                start: current_start,
                end: None,
                end_inclusive: false,
            });
        }

        intervals.into_iter().any(|interval| {
            if let Some(start) = &interval.start {
                if Self::cmp_dotted(&version_parts, start) == Ordering::Less {
                    return false;
                }
            }

            match (&interval.end, interval.end_inclusive) {
                (Some(end), true) => Self::cmp_dotted(&version_parts, end) != Ordering::Greater,
                (Some(end), false) => Self::cmp_dotted(&version_parts, end) == Ordering::Less,
                (None, _) => true,
            }
        })
    }

    /// Parse dotted numeric versions (e.g., "1.2.10"). Non-numeric segments cause failure.
    fn parse_dotted(v: &str) -> Option<Vec<u64>> {
        let mut parts = Vec::new();
        for chunk in v.split(|c: char| !c.is_ascii_digit()) {
            if chunk.is_empty() {
                continue;
            }
            let Ok(num) = chunk.parse::<u64>() else {
                return None;
            };
            parts.push(num);
        }
        if parts.is_empty() { None } else { Some(parts) }
    }

    /// Compare dotted numeric versions.
    fn cmp_dotted(a: &[u64], b: &[u64]) -> Ordering {
        let max_len = a.len().max(b.len());
        for i in 0..max_len {
            let ai = *a.get(i).unwrap_or(&0);
            let bi = *b.get(i).unwrap_or(&0);
            match ai.cmp(&bi) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        Ordering::Equal
    }

    /// Enrich a single advisory with EPSS/KEV data.
    async fn enrich_advisory(&self, advisory: &mut Advisory) -> Result<()> {
        // Find CVE aliases
        let cve_ids = Self::extract_cve_ids(advisory);

        if cve_ids.is_empty() {
            return Ok(());
        }

        // Look up enrichment data
        for cve_id in &cve_ids {
            if let Ok(Some(data)) = self.store.get_enrichment(cve_id).await {
                let enrichment = advisory.enrichment.get_or_insert_with(Enrichment::default);
                enrichment.epss_score = data.epss_score.or(enrichment.epss_score);
                enrichment.epss_percentile = data.epss_percentile.or(enrichment.epss_percentile);
                enrichment.is_kev = enrichment.is_kev || data.is_kev;
                if data.kev_due_date.is_some() {
                    enrichment.kev_due_date = data
                        .kev_due_date
                        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
                        .map(|d| d.with_timezone(&chrono::Utc));
                }
                if data.kev_ransomware.is_some() {
                    enrichment.kev_ransomware = data.kev_ransomware;
                }
            }
        }

        Ok(())
    }

    /// Enrich multiple advisories with EPSS/KEV data.
    async fn enrich_advisories(&self, advisories: &mut [Advisory]) -> Result<()> {
        for advisory in advisories.iter_mut() {
            self.enrich_advisory(advisory).await?;
        }
        Ok(())
    }

    /// Extract CVE IDs from an advisory (from ID or aliases).
    fn extract_cve_ids(advisory: &Advisory) -> Vec<String> {
        let mut cve_ids = Vec::new();

        if advisory.id.starts_with("CVE-") {
            cve_ids.push(advisory.id.clone());
        }

        if let Some(aliases) = &advisory.aliases {
            for alias in aliases {
                if alias.starts_with("CVE-") && !cve_ids.contains(alias) {
                    cve_ids.push(alias.clone());
                }
            }
        }

        cve_ids
    }

    /// Check if an advisory passes the filter options.
    fn advisory_passes_filters(&self, advisory: &Advisory, options: &MatchOptions) -> bool {
        // Check KEV filter
        if options.kev_only {
            let is_kev = advisory
                .enrichment
                .as_ref()
                .map(|e| e.is_kev)
                .unwrap_or(false);
            if !is_kev {
                return false;
            }
        }

        // Check CVSS filter
        if let Some(min_cvss) = options.min_cvss {
            let cvss = advisory
                .enrichment
                .as_ref()
                .and_then(|e| e.cvss_v3_score)
                .unwrap_or(0.0);
            if cvss < min_cvss {
                return false;
            }
        }

        // Check EPSS filter
        if let Some(min_epss) = options.min_epss {
            let epss = advisory
                .enrichment
                .as_ref()
                .and_then(|e| e.epss_score)
                .unwrap_or(0.0);
            if epss < min_epss {
                return false;
            }
        }

        // Check severity filter
        if let Some(min_severity) = &options.min_severity {
            let severity = advisory
                .enrichment
                .as_ref()
                .and_then(|e| e.cvss_v3_severity)
                .unwrap_or(Severity::None);
            if severity < *min_severity {
                return false;
            }
        }

        // Check CWE filter
        if let Some(ref filter_cwes) = options.cwe_ids {
            if !filter_cwes.is_empty() {
                let advisory_cwes = Self::extract_cwes_from_advisory(advisory);
                // Normalize both filter CWEs and advisory CWEs for consistent matching
                let normalized_filter: Vec<String> = filter_cwes
                    .iter()
                    .map(|c| Self::normalize_cwe_id(c))
                    .collect();
                let normalized_advisory: Vec<String> = advisory_cwes
                    .iter()
                    .map(|c| Self::normalize_cwe_id(c))
                    .collect();
                // Advisory must have at least one matching CWE
                let has_match = normalized_filter
                    .iter()
                    .any(|cwe| normalized_advisory.iter().any(|ac| ac == cwe));
                if !has_match {
                    return false;
                }
            }
        }

        true
    }

    /// Normalize a CWE identifier to uppercase "CWE-XXX" format.
    ///
    /// Handles various input formats:
    /// - "79" → "CWE-79"
    /// - "cwe-79" → "CWE-79"
    /// - "CWE-79" → "CWE-79"
    fn normalize_cwe_id(cwe: &str) -> String {
        let trimmed = cwe.trim();
        let upper = trimmed.to_uppercase();

        if upper.starts_with("CWE-") {
            upper
        } else {
            format!("CWE-{}", trimmed)
        }
    }

    /// Extract CWE identifiers from an advisory.
    ///
    /// CWEs may be stored in `database_specific.cwe_ids` (from OSS Index and some OSV sources).
    fn extract_cwes_from_advisory(advisory: &Advisory) -> Vec<String> {
        let mut cwes = Vec::new();

        // Check database_specific.cwe_ids (OSS Index, some OSV sources)
        if let Some(ref db_specific) = advisory.database_specific {
            if let Some(cwe_ids) = db_specific.get("cwe_ids") {
                if let Some(arr) = cwe_ids.as_array() {
                    for cwe in arr {
                        if let Some(s) = cwe.as_str() {
                            cwes.push(s.to_string());
                        }
                    }
                }
            }
        }

        cwes
    }

    /// Fetch live EPSS scores for CVEs (not from cache).
    pub async fn fetch_epss_scores(&self, cve_ids: &[&str]) -> Result<HashMap<String, f64>> {
        let scores = self.epss_source.fetch_scores(cve_ids).await?;
        Ok(scores.into_iter().map(|(k, v)| (k, v.epss)).collect())
    }

    /// Check if a CVE is in the CISA KEV catalog.
    pub async fn is_kev(&self, cve_id: &str) -> Result<bool> {
        // Check cache first
        if let Some(data) = self.store.get_enrichment(cve_id).await? {
            return Ok(data.is_kev);
        }

        // Fetch from source
        let entry = self.kev_source.is_kev(cve_id).await?;
        Ok(entry.is_some())
    }

    // === OSS Index Methods ===

    /// Query OSS Index for vulnerabilities affecting the given PURLs.
    ///
    /// This method provides automatic caching:
    /// - First checks the cache for each PURL
    /// - Only queries OSS Index for cache misses
    /// - Caches results for future queries
    ///
    /// # Arguments
    ///
    /// * `purls` - Package URLs to query (e.g., "pkg:npm/lodash@4.17.20")
    ///
    /// # Returns
    ///
    /// Vector of advisories for all vulnerabilities found.
    ///
    /// # Errors
    ///
    /// Returns an error if OSS Index is not configured or if the query fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use vulnera_advisors::{VulnerabilityManager, Purl};
    ///
    /// let manager = VulnerabilityManager::builder()
    ///     .redis_url("redis://localhost:6379")
    ///     .with_ossindex(None)
    ///     .build()?;
    ///
    /// let purls = vec![
    ///     Purl::new("npm", "lodash").with_version("4.17.20").to_string(),
    /// ];
    ///
    /// let advisories = manager.query_ossindex(&purls).await?;
    /// ```
    pub async fn query_ossindex(&self, purls: &[String]) -> Result<Vec<Advisory>> {
        let source = self.ossindex_source.as_ref().ok_or_else(|| {
            AdvisoryError::config("OSS Index not configured. Use .with_ossindex() in builder.")
        })?;

        // Check cache for all PURLs
        let mut cached_advisories = Vec::new();
        let mut cache_misses = Vec::new();

        for purl in purls {
            let cache_key = Purl::cache_key_from_str(purl);
            match self.store.get_ossindex_cache(&cache_key).await {
                Ok(Some(cache)) if !cache.is_expired() => {
                    debug!("OSS Index cache hit for {}", purl);
                    cached_advisories.extend(cache.advisories);
                }
                _ => {
                    debug!("OSS Index cache miss for {}", purl);
                    cache_misses.push(purl.clone());
                }
            }
        }

        // Query OSS Index for cache misses
        if !cache_misses.is_empty() {
            debug!("Querying OSS Index for {} cache misses", cache_misses.len());
            let fresh_advisories = source.query_advisories(&cache_misses).await.map_err(|e| {
                AdvisoryError::SourceFetch {
                    source_name: "ossindex".to_string(),
                    message: e.to_string(),
                }
            })?;

            // Group advisories by PURL for caching
            let advisory_map = Self::group_advisories_by_purl(&cache_misses, &fresh_advisories);

            // Cache results for each PURL
            for (purl, advisories) in &advisory_map {
                let cache_key = Purl::cache_key_from_str(purl);
                let cache = OssIndexCache::new(advisories.clone());
                if let Err(e) = self.store.store_ossindex_cache(&cache_key, &cache).await {
                    debug!("Failed to cache OSS Index result for {}: {}", purl, e);
                }
            }

            // Flatten and add to results
            for advisories in advisory_map.into_values() {
                cached_advisories.extend(advisories);
            }
        }

        Ok(cached_advisories)
    }

    /// Query OSS Index for vulnerabilities with fallback to stored advisories.
    ///
    /// This method first queries OSS Index, then falls back to the local store
    /// if the OSS Index query fails or returns no results.
    ///
    /// # Arguments
    ///
    /// * `packages` - List of packages to query (ecosystem, name, optional version)
    ///
    /// # Returns
    ///
    /// Structured batch outcome with successful results and per-package failures.
    pub async fn query_batch_with_ossindex(
        &self,
        packages: &[PackageKey],
    ) -> Result<BatchOutcome<Vec<Advisory>>> {
        let mut successes: HashMap<PackageKey, Vec<Advisory>> = HashMap::new();
        let mut failures: Vec<BatchFailure> = Vec::new();

        // Build PURLs for packages that have versions
        let (with_version, without_version): (Vec<_>, Vec<_>) =
            packages.iter().partition(|p| p.version.is_some());

        // Query OSS Index for packages with versions
        if !with_version.is_empty() && self.ossindex_source.is_some() {
            let purls: Vec<String> = with_version
                .iter()
                .map(|p| {
                    Purl::new(&p.ecosystem, &p.name)
                        .with_version(p.version.as_ref().unwrap())
                        .to_string()
                })
                .collect();

            match self.query_ossindex(&purls).await {
                Ok(advisories) => {
                    // Group advisories by package key
                    for pkg in &with_version {
                        let pkg_advisories: Vec<_> = advisories
                            .iter()
                            .filter(|a| {
                                a.affected.iter().any(|aff| {
                                    aff.package.ecosystem.eq_ignore_ascii_case(&pkg.ecosystem)
                                        && aff.package.name == pkg.name
                                })
                            })
                            .cloned()
                            .collect();
                        successes.insert((*pkg).clone(), pkg_advisories);
                    }
                }
                Err(e) => {
                    warn!("OSS Index query failed, falling back to local store: {}", e);
                    // Fallback to local store
                    for pkg in &with_version {
                        failures.push(BatchFailure {
                            package: (*pkg).clone(),
                            stage: BatchFailureStage::OssIndex,
                            retryable: e.is_retryable(),
                            error: e.to_string(),
                        });
                        let advisories = if let Some(version) = &pkg.version {
                            self.matches(&pkg.ecosystem, &pkg.name, version).await
                        } else {
                            self.query(&pkg.ecosystem, &pkg.name).await
                        };

                        match advisories {
                            Ok(advisories) => {
                                successes.insert((*pkg).clone(), advisories);
                            }
                            Err(fallback_err) => {
                                failures.push(BatchFailure {
                                    package: (*pkg).clone(),
                                    stage: BatchFailureStage::StoreLookup,
                                    retryable: fallback_err.is_retryable(),
                                    error: fallback_err.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Query local store for packages without versions
        for pkg in &without_version {
            match self.query(&pkg.ecosystem, &pkg.name).await {
                Ok(advisories) => {
                    successes.insert((*pkg).clone(), advisories);
                }
                Err(e) => {
                    failures.push(BatchFailure {
                        package: (*pkg).clone(),
                        stage: BatchFailureStage::StoreLookup,
                        retryable: e.is_retryable(),
                        error: e.to_string(),
                    });
                }
            }
        }

        let mut outcome = BatchOutcome::from_parts(successes, failures, packages.len());
        outcome.summary.range_translation_statuses =
            Self::collect_range_translation_statuses(&outcome.successes);
        Ok(outcome)
    }

    /// Invalidate cached OSS Index results for specific PURLs.
    ///
    /// Use this to force a fresh query on the next call.
    pub async fn invalidate_ossindex_cache(&self, purls: &[String]) -> Result<()> {
        for purl in purls {
            let cache_key = Purl::cache_key_from_str(purl);
            self.store.invalidate_ossindex_cache(&cache_key).await?;
        }
        Ok(())
    }

    /// Invalidate all cached OSS Index results.
    pub async fn invalidate_all_ossindex_cache(&self) -> Result<()> {
        self.store.invalidate_all_ossindex_cache().await?;
        Ok(())
    }

    // === Remediation Methods ===

    /// Get remediation suggestions for a vulnerable package.
    ///
    /// This method checks if the specified version is vulnerable, and if so,
    /// suggests the nearest and latest safe versions based on fixed versions
    /// declared in the advisories.
    ///
    /// # Arguments
    ///
    /// * `ecosystem` - Package ecosystem (e.g., "npm", "pypi")
    /// * `package` - Package name
    /// * `current_version` - Current version to analyze
    ///
    /// # Returns
    ///
    /// A [`crate::remediation::Remediation`] containing safe version suggestions and upgrade impact.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use vulnera_advisors::VulnerabilityManager;
    ///
    /// let remediation = manager.suggest_remediation("npm", "lodash", "4.17.20").await?;
    /// if let Some(nearest) = remediation.nearest_safe {
    ///     println!("Upgrade to {} ({:?} impact)", nearest, remediation.upgrade_impact);
    /// }
    /// ```
    pub async fn suggest_remediation(
        &self,
        ecosystem: &str,
        package: &str,
        current_version: &str,
    ) -> Result<crate::remediation::Remediation> {
        // Get matching advisories for this version
        let advisories = self.matches(ecosystem, package, current_version).await?;

        // Build remediation using the semver matcher
        let remediation = crate::remediation::build_remediation(
            ecosystem,
            package,
            current_version,
            &advisories,
            None, // No registry versions, use only fixed versions from advisories
            Self::matches_semver_range,
        );

        Ok(remediation)
    }

    /// Get remediation suggestions with registry lookup for all available versions.
    ///
    /// This is an enhanced version of [`Self::suggest_remediation`] that fetches
    /// available versions from package registries to provide more complete
    /// upgrade suggestions.
    ///
    /// # Arguments
    ///
    /// * `ecosystem` - Package ecosystem (e.g., "npm", "pypi")
    /// * `package` - Package name
    /// * `current_version` - Current version to analyze
    /// * `registry` - A version registry implementation to fetch available versions
    ///
    /// # Returns
    ///
    /// A [`crate::remediation::Remediation`] containing safe version suggestions from the full version list.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use vulnera_advisors::{VulnerabilityManager, PackageRegistry};
    ///
    /// let registry = PackageRegistry::new();
    /// let remediation = manager
    ///     .suggest_remediation_with_registry("npm", "lodash", "4.17.20", &registry)
    ///     .await?;
    /// ```
    pub async fn suggest_remediation_with_registry(
        &self,
        ecosystem: &str,
        package: &str,
        current_version: &str,
        registry: &dyn crate::version_registry::VersionRegistry,
    ) -> Result<crate::remediation::Remediation> {
        // Get matching advisories for this version
        let advisories = self.matches(ecosystem, package, current_version).await?;

        // Fetch all available versions from registry
        let available_versions = match registry.get_versions(ecosystem, package).await {
            Ok(versions) => Some(versions),
            Err(e) => {
                warn!(
                    "Failed to fetch versions from registry, using advisory data only: {}",
                    e
                );
                None
            }
        };

        // Build remediation with registry versions
        let remediation = crate::remediation::build_remediation(
            ecosystem,
            package,
            current_version,
            &advisories,
            available_versions.as_deref(),
            Self::matches_semver_range,
        );

        Ok(remediation)
    }

    /// Group advisories by their associated PURL.
    fn group_advisories_by_purl(
        purls: &[String],
        advisories: &[Advisory],
    ) -> HashMap<String, Vec<Advisory>> {
        let mut map: HashMap<String, Vec<Advisory>> = HashMap::new();

        // Initialize map with empty vectors for all PURLs
        for purl in purls {
            map.insert(purl.clone(), Vec::new());
        }

        for advisory in advisories {
            for affected in &advisory.affected {
                for purl in purls {
                    let Ok(parsed) = Purl::parse(purl) else {
                        continue;
                    };

                    // Match on ecosystem as well as name to avoid cross-ecosystem collisions
                    let affected_eco = affected.package.ecosystem.to_lowercase();
                    let purl_eco = parsed.purl_type.to_lowercase();
                    let purl_eco_alt = parsed.ecosystem().to_lowercase();
                    if affected_eco != purl_eco && affected_eco != purl_eco_alt {
                        continue;
                    }

                    if parsed.name != affected.package.name {
                        continue;
                    }

                    if let Some(ver) = parsed.version.as_deref() {
                        // If a version is specified, ensure the advisory actually covers it.
                        let version_matches = affected.versions.contains(&ver.to_string())
                            || affected.ranges.iter().any(|r| {
                                matches!(r.range_type, RangeType::Semver | RangeType::Ecosystem)
                                    && Self::matches_semver_range(ver, &r.events)
                            });

                        if !version_matches {
                            continue;
                        }
                    }

                    map.entry(purl.clone()).or_default().push(advisory.clone());
                    break;
                }
            }
        }

        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Advisory, Enrichment, Severity};

    /// Helper to create a test advisory with optional CWEs in database_specific
    fn create_advisory_with_cwes(id: &str, cwes: Option<Vec<&str>>) -> Advisory {
        let database_specific = cwes.map(|cwe_list| {
            serde_json::json!({
                "cwe_ids": cwe_list
            })
        });

        Advisory {
            id: id.to_string(),
            summary: Some("Test advisory".to_string()),
            details: None,
            affected: vec![],
            references: vec![],
            published: None,
            modified: None,
            aliases: None,
            database_specific,
            enrichment: None,
        }
    }

    /// Helper to create a test advisory with enrichment data
    fn create_advisory_with_enrichment(id: &str, severity: Severity, is_kev: bool) -> Advisory {
        Advisory {
            id: id.to_string(),
            summary: Some("Test advisory".to_string()),
            details: None,
            affected: vec![],
            references: vec![],
            published: None,
            modified: None,
            aliases: None,
            database_specific: None,
            enrichment: Some(Enrichment {
                cvss_v3_severity: Some(severity),
                is_kev,
                ..Default::default()
            }),
        }
    }

    #[test]
    fn test_match_options_default() {
        let options = MatchOptions::default();
        assert!(options.cwe_ids.is_none());
        assert!(options.min_cvss.is_none());
        assert!(!options.kev_only);
    }

    #[test]
    fn test_match_options_with_cwes() {
        let options = MatchOptions::with_cwes(vec!["CWE-79".to_string(), "CWE-89".to_string()]);
        assert!(options.cwe_ids.is_some());
        let cwes = options.cwe_ids.unwrap();
        assert_eq!(cwes.len(), 2);
        assert!(cwes.contains(&"CWE-79".to_string()));
        assert!(cwes.contains(&"CWE-89".to_string()));
        assert!(options.include_enrichment);
    }

    #[test]
    fn test_extract_cwes_from_advisory_with_cwes() {
        let advisory = create_advisory_with_cwes("CVE-2024-1234", Some(vec!["CWE-79", "CWE-89"]));
        let cwes = VulnerabilityManager::extract_cwes_from_advisory(&advisory);
        assert_eq!(cwes.len(), 2);
        assert!(cwes.contains(&"CWE-79".to_string()));
        assert!(cwes.contains(&"CWE-89".to_string()));
    }

    #[test]
    fn test_extract_cwes_from_advisory_no_cwes() {
        let advisory = create_advisory_with_cwes("CVE-2024-1234", None);
        let cwes = VulnerabilityManager::extract_cwes_from_advisory(&advisory);
        assert!(cwes.is_empty());
    }

    #[test]
    fn test_extract_cwes_from_advisory_empty_cwes() {
        let advisory = create_advisory_with_cwes("CVE-2024-1234", Some(vec![]));
        let cwes = VulnerabilityManager::extract_cwes_from_advisory(&advisory);
        assert!(cwes.is_empty());
    }

    #[test]
    fn test_cwe_filter_case_insensitive() {
        // Test that CWE matching is case-insensitive
        let advisory = create_advisory_with_cwes("CVE-2024-1234", Some(vec!["cwe-79"]));

        // Create options with uppercase CWE
        let options = MatchOptions::with_cwes(vec!["CWE-79".to_string()]);

        // Extract CWEs
        let advisory_cwes = VulnerabilityManager::extract_cwes_from_advisory(&advisory);

        // Check case-insensitive matching
        let filter_cwes = options.cwe_ids.as_ref().unwrap();
        let has_match = filter_cwes
            .iter()
            .any(|cwe| advisory_cwes.iter().any(|ac| ac.eq_ignore_ascii_case(cwe)));
        assert!(has_match, "CWE matching should be case-insensitive");
    }

    #[test]
    fn test_cwe_filter_no_match() {
        let advisory = create_advisory_with_cwes("CVE-2024-1234", Some(vec!["CWE-79"]));

        // Create options filtering for a different CWE
        let options = MatchOptions::with_cwes(vec!["CWE-89".to_string()]);

        let advisory_cwes = VulnerabilityManager::extract_cwes_from_advisory(&advisory);
        let filter_cwes = options.cwe_ids.as_ref().unwrap();
        let has_match = filter_cwes
            .iter()
            .any(|cwe| advisory_cwes.iter().any(|ac| ac.eq_ignore_ascii_case(cwe)));
        assert!(!has_match, "Should not match when CWEs don't overlap");
    }

    #[test]
    fn test_cwe_filter_partial_match() {
        // Advisory has multiple CWEs, filter matches one of them
        let advisory =
            create_advisory_with_cwes("CVE-2024-1234", Some(vec!["CWE-79", "CWE-352", "CWE-94"]));

        let options = MatchOptions::with_cwes(vec!["CWE-89".to_string(), "CWE-79".to_string()]);

        let advisory_cwes = VulnerabilityManager::extract_cwes_from_advisory(&advisory);
        let filter_cwes = options.cwe_ids.as_ref().unwrap();
        let has_match = filter_cwes
            .iter()
            .any(|cwe| advisory_cwes.iter().any(|ac| ac.eq_ignore_ascii_case(cwe)));
        assert!(has_match, "Should match when at least one CWE overlaps");
    }

    #[test]
    fn test_match_options_empty_cwe_list() {
        // Empty CWE list should not filter anything
        let options = MatchOptions {
            cwe_ids: Some(vec![]),
            ..Default::default()
        };

        // The filter check should pass when cwe_ids list is empty
        assert!(options.cwe_ids.as_ref().is_none_or(|v| v.is_empty()));
    }

    #[test]
    fn test_match_options_combined_filters() {
        // Test that CWE filter can be combined with other filters
        let options = MatchOptions {
            cwe_ids: Some(vec!["CWE-79".to_string()]),
            min_severity: Some(Severity::High),
            kev_only: true,
            include_enrichment: true,
            ..Default::default()
        };

        assert!(options.cwe_ids.is_some());
        assert_eq!(options.min_severity, Some(Severity::High));
        assert!(options.kev_only);
    }

    #[test]
    fn test_normalize_cwe_id_with_prefix() {
        assert_eq!(VulnerabilityManager::normalize_cwe_id("CWE-79"), "CWE-79");
        assert_eq!(VulnerabilityManager::normalize_cwe_id("cwe-79"), "CWE-79");
        assert_eq!(VulnerabilityManager::normalize_cwe_id("Cwe-89"), "CWE-89");
    }

    #[test]
    fn test_normalize_cwe_id_bare_number() {
        assert_eq!(VulnerabilityManager::normalize_cwe_id("79"), "CWE-79");
        assert_eq!(VulnerabilityManager::normalize_cwe_id("89"), "CWE-89");
        assert_eq!(VulnerabilityManager::normalize_cwe_id("352"), "CWE-352");
    }

    #[test]
    fn test_normalize_cwe_id_with_whitespace() {
        assert_eq!(VulnerabilityManager::normalize_cwe_id(" CWE-79 "), "CWE-79");
        assert_eq!(VulnerabilityManager::normalize_cwe_id(" 79 "), "CWE-79");
    }

    #[test]
    fn test_cwe_filter_bare_id_matches_prefixed() {
        // User filters with bare "79", advisory has "CWE-79"
        let advisory = create_advisory_with_cwes("CVE-2024-1234", Some(vec!["CWE-79"]));
        let advisory_cwes = VulnerabilityManager::extract_cwes_from_advisory(&advisory);

        let filter_cwes = ["79".to_string()];
        let normalized_filter: Vec<String> = filter_cwes
            .iter()
            .map(|c| VulnerabilityManager::normalize_cwe_id(c))
            .collect();
        let normalized_advisory: Vec<String> = advisory_cwes
            .iter()
            .map(|c| VulnerabilityManager::normalize_cwe_id(c))
            .collect();

        let has_match = normalized_filter
            .iter()
            .any(|cwe| normalized_advisory.iter().any(|ac| ac == cwe));
        assert!(has_match, "Bare '79' should match 'CWE-79'");
    }

    #[test]
    fn test_cwe_filter_prefixed_matches_bare() {
        // User filters with "CWE-79", advisory has bare "79"
        let advisory = create_advisory_with_cwes("CVE-2024-1234", Some(vec!["79"]));
        let advisory_cwes = VulnerabilityManager::extract_cwes_from_advisory(&advisory);

        let filter_cwes = ["CWE-79".to_string()];
        let normalized_filter: Vec<String> = filter_cwes
            .iter()
            .map(|c| VulnerabilityManager::normalize_cwe_id(c))
            .collect();
        let normalized_advisory: Vec<String> = advisory_cwes
            .iter()
            .map(|c| VulnerabilityManager::normalize_cwe_id(c))
            .collect();

        let has_match = normalized_filter
            .iter()
            .any(|cwe| normalized_advisory.iter().any(|ac| ac == cwe));
        assert!(has_match, "'CWE-79' should match bare '79'");
    }

    #[test]
    fn test_cwe_filter_with_enrichment_severity() {
        // Test CWE filtering works correctly with enrichment data (severity)
        let mut advisory = create_advisory_with_enrichment("CVE-2024-1234", Severity::High, false);

        // Add CWE data to the advisory
        let mut db_specific = serde_json::Map::new();
        db_specific.insert(
            "cwe_ids".to_string(),
            serde_json::json!(["CWE-79", "CWE-89"]),
        );
        advisory.database_specific = Some(serde_json::Value::Object(db_specific));

        // Verify enrichment is present
        assert!(advisory.enrichment.is_some());
        assert_eq!(
            advisory.enrichment.as_ref().unwrap().cvss_v3_severity,
            Some(Severity::High)
        );

        // Verify CWE extraction works with enrichment
        let cwes = VulnerabilityManager::extract_cwes_from_advisory(&advisory);
        assert_eq!(cwes, vec!["CWE-79", "CWE-89"]);
    }

    #[test]
    fn test_cwe_filter_with_enrichment_kev() {
        // Test CWE filtering works correctly with KEV status
        let mut advisory =
            create_advisory_with_enrichment("CVE-2024-5678", Severity::Critical, true);

        // Add CWE data
        let mut db_specific = serde_json::Map::new();
        db_specific.insert("cwe_ids".to_string(), serde_json::json!(["CWE-78"]));
        advisory.database_specific = Some(serde_json::Value::Object(db_specific));

        // Verify KEV status is present
        assert!(advisory.enrichment.as_ref().unwrap().is_kev);

        // Verify CWE extraction still works
        let cwes = VulnerabilityManager::extract_cwes_from_advisory(&advisory);
        assert_eq!(cwes, vec!["CWE-78"]);

        // Test normalization
        let normalized: Vec<String> = cwes
            .iter()
            .map(|c| VulnerabilityManager::normalize_cwe_id(c))
            .collect();
        assert_eq!(normalized, vec!["CWE-78"]);
    }
}
