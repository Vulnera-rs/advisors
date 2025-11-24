//! Vulnerability manager for orchestrating syncs and queries.
//!
//! The [`VulnerabilityManager`] is the main entry point for using this crate.
//! Use [`VulnerabilityManagerBuilder`] for flexible configuration.

use crate::config::{Config, OssIndexConfig, StoreConfig};
use crate::error::{AdvisoryError, Result};
use crate::models::{Advisory, Enrichment, Event, RangeType, Severity};
use crate::purl::Purl;
use crate::sources::epss::EpssSource;
use crate::sources::kev::KevSource;
use crate::sources::ossindex::OssIndexSource;
use crate::sources::{AdvisorySource, ghsa::GHSASource, nvd::NVDSource, osv::OSVSource};
use crate::store::{AdvisoryStore, DragonflyStore, EnrichmentData, HealthStatus, OssIndexCache};
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

impl PackageKey {
    /// Create a new package key.
    pub fn new(ecosystem: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            ecosystem: ecosystem.into(),
            name: name.into(),
            version: None,
        }
    }

    /// Create a package key with a version.
    pub fn with_version(
        ecosystem: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            ecosystem: ecosystem.into(),
            name: name.into(),
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
}

impl VulnerabilityManager {
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
    pub async fn sync_all(&self) -> Result<()> {
        info!("Starting full vulnerability sync...");

        let mut handles = Vec::new();

        for source in &self.sources {
            let source = source.clone();
            let store = self.store.clone();

            let handle = tokio::spawn(async move {
                let last_sync = match store.last_sync(source.name()).await {
                    Ok(Some(ts)) => match chrono::DateTime::parse_from_rfc3339(&ts) {
                        Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
                        Err(_) => None,
                    },
                    _ => None,
                };

                if let Some(since) = last_sync {
                    info!("Syncing {} since {}", source.name(), since);
                } else {
                    info!("Syncing {} (full)", source.name());
                }

                match source.fetch(last_sync).await {
                    Ok(advisories) => {
                        if !advisories.is_empty() {
                            if let Err(e) = store.upsert_batch(&advisories, source.name()).await {
                                error!("Failed to store advisories for {}: {}", source.name(), e);
                            }
                        } else {
                            info!("No new advisories for {}", source.name());
                            // Update sync timestamp even if no new advisories
                            if let Err(e) = store.update_sync_timestamp(source.name()).await {
                                error!(
                                    "Failed to update sync timestamp for {}: {}",
                                    source.name(),
                                    e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to fetch from {}: {}", source.name(), e);
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            if let Err(e) = handle.await {
                error!("Task join error: {}", e);
            }
        }

        info!("Sync completed.");
        Ok(())
    }

    /// Sync enrichment data (KEV and EPSS).
    pub async fn sync_enrichment(&self) -> Result<()> {
        info!("Syncing enrichment data (KEV, EPSS)...");

        // Sync KEV data
        match self.kev_source.fetch_catalog().await {
            Ok(kev_entries) => {
                info!("Processing {} KEV entries", kev_entries.len());
                for (cve_id, entry) in kev_entries {
                    let data = EnrichmentData {
                        epss_score: None,
                        epss_percentile: None,
                        is_kev: true,
                        kev_due_date: entry.due_date_utc().map(|d| d.to_rfc3339()),
                        kev_date_added: entry.date_added_utc().map(|d| d.to_rfc3339()),
                        kev_ransomware: Some(entry.is_ransomware_related()),
                        updated_at: chrono::Utc::now().to_rfc3339(),
                    };
                    if let Err(e) = self.store.store_enrichment(&cve_id, &data).await {
                        debug!("Failed to store KEV enrichment for {}: {}", cve_id, e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to fetch KEV catalog: {}", e);
            }
        }

        Ok(())
    }

    /// Query advisories for a specific package.
    pub async fn query(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>> {
        let advisories = self.store.get_by_package(ecosystem, package).await?;
        Ok(crate::aggregator::ReportAggregator::aggregate(advisories))
    }

    /// Query advisories with enrichment data.
    pub async fn query_enriched(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>> {
        let mut advisories = self.query(ecosystem, package).await?;
        self.enrich_advisories(&mut advisories).await?;
        Ok(advisories)
    }

    /// Query multiple packages in a batch.
    pub async fn query_batch(
        &self,
        packages: &[PackageKey],
    ) -> Result<HashMap<PackageKey, Vec<Advisory>>> {
        let mut results = HashMap::new();

        for pkg in packages {
            let advisories = if let Some(version) = &pkg.version {
                self.matches(&pkg.ecosystem, &pkg.name, version).await?
            } else {
                self.query(&pkg.ecosystem, &pkg.name).await?
            };
            results.insert(pkg.clone(), advisories);
        }

        Ok(results)
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
                            // For ecosystem ranges, try semver first as fallback
                            if Self::matches_semver_range(version, &range.events) {
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

    /// Check if a version matches a semver range.
    fn matches_semver_range(version: &str, events: &[Event]) -> bool {
        let Ok(v) = semver::Version::parse(version) else {
            return false;
        };

        let mut introduced: Option<semver::Version> = None;
        let mut fixed: Option<semver::Version> = None;
        let mut last_affected: Option<semver::Version> = None;

        for event in events {
            match event {
                Event::Introduced(ver) => {
                    if let Ok(parsed) = semver::Version::parse(ver) {
                        introduced = Some(parsed);
                    } else if ver == "0" {
                        introduced = Some(semver::Version::new(0, 0, 0));
                    }
                }
                Event::Fixed(ver) => {
                    if let Ok(parsed) = semver::Version::parse(ver) {
                        fixed = Some(parsed);
                    }
                }
                Event::LastAffected(ver) => {
                    if let Ok(parsed) = semver::Version::parse(ver) {
                        last_affected = Some(parsed);
                    }
                }
                Event::Limit(_) => {}
            }
        }

        match (introduced, fixed, last_affected) {
            (Some(start), Some(end), _) => v >= start && v < end,
            (Some(start), None, Some(last)) => v >= start && v <= last,
            (Some(start), None, None) => v >= start,
            (None, Some(end), _) => v < end,
            _ => false,
        }
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

        true
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
    /// Map of package keys to their advisories.
    pub async fn query_batch_with_ossindex(
        &self,
        packages: &[PackageKey],
    ) -> Result<HashMap<PackageKey, Vec<Advisory>>> {
        let mut results: HashMap<PackageKey, Vec<Advisory>> = HashMap::new();

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
                        results.insert((*pkg).clone(), pkg_advisories);
                    }
                }
                Err(e) => {
                    warn!("OSS Index query failed, falling back to local store: {}", e);
                    // Fallback to local store
                    for pkg in &with_version {
                        let advisories = if let Some(version) = &pkg.version {
                            self.matches(&pkg.ecosystem, &pkg.name, version).await?
                        } else {
                            self.query(&pkg.ecosystem, &pkg.name).await?
                        };
                        results.insert((*pkg).clone(), advisories);
                    }
                }
            }
        }

        // Query local store for packages without versions
        for pkg in &without_version {
            let advisories = self.query(&pkg.ecosystem, &pkg.name).await?;
            results.insert((*pkg).clone(), advisories);
        }

        Ok(results)
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

        // Group advisories
        for advisory in advisories {
            for affected in &advisory.affected {
                // Find matching PURL
                for purl in purls {
                    if let Ok(parsed) = Purl::parse(purl) {
                        if parsed.name == affected.package.name {
                            map.entry(purl.clone()).or_default().push(advisory.clone());
                            break;
                        }
                    }
                }
            }
        }

        map
    }
}
