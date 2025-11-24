//! Storage backends for advisory data.
//!
//! This module provides the [`AdvisoryStore`] trait and implementations for
//! persisting and querying vulnerability advisories.

use crate::config::StoreConfig;
use crate::error::{AdvisoryError, Result};
use crate::models::Advisory;
use async_stream::try_stream;
use async_trait::async_trait;
use futures_util::Stream;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::pin::Pin;
use std::time::Instant;
use tracing::{info, instrument};

/// Trait for advisory storage backends.
#[async_trait]
pub trait AdvisoryStore: Send + Sync {
    /// Insert or update a batch of advisories.
    async fn upsert_batch(&self, advisories: &[Advisory], source: &str) -> Result<()>;

    /// Get a single advisory by ID.
    async fn get(&self, id: &str) -> Result<Option<Advisory>>;

    /// Get all advisories affecting a specific package.
    async fn get_by_package(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>>;

    /// Get the timestamp of the last sync for a source.
    async fn last_sync(&self, source: &str) -> Result<Option<String>>;

    /// Check the health of the store connection.
    async fn health_check(&self) -> Result<HealthStatus>;

    /// Get advisories as a stream for memory-efficient processing.
    async fn get_by_package_stream(
        &self,
        ecosystem: &str,
        package: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Advisory>> + Send + '_>>>;

    /// Get multiple advisories by IDs in a batch.
    async fn get_batch(&self, ids: &[String]) -> Result<Vec<Advisory>>;

    /// Store enrichment data (EPSS/KEV) for a CVE.
    async fn store_enrichment(&self, cve_id: &str, data: &EnrichmentData) -> Result<()>;

    /// Get enrichment data for a CVE.
    async fn get_enrichment(&self, cve_id: &str) -> Result<Option<EnrichmentData>>;

    /// Get enrichment data for multiple CVEs.
    async fn get_enrichment_batch(
        &self,
        cve_ids: &[String],
    ) -> Result<Vec<(String, EnrichmentData)>>;

    /// Update the last sync timestamp for a source.
    async fn update_sync_timestamp(&self, source: &str) -> Result<()>;

    /// Get the count of stored advisories.
    async fn advisory_count(&self) -> Result<u64>;

    /// Store an OSS Index component report in cache.
    ///
    /// # Arguments
    ///
    /// * `purl` - The Package URL that was queried
    /// * `cache` - The cached component report with metadata
    async fn store_ossindex_cache(&self, purl: &str, cache: &OssIndexCache) -> Result<()>;

    /// Get a cached OSS Index component report.
    ///
    /// Returns `None` if not cached or if the cache has expired.
    async fn get_ossindex_cache(&self, purl: &str) -> Result<Option<OssIndexCache>>;

    /// Invalidate (delete) a cached OSS Index component report.
    async fn invalidate_ossindex_cache(&self, purl: &str) -> Result<()>;

    /// Invalidate all OSS Index cache entries.
    async fn invalidate_all_ossindex_cache(&self) -> Result<u64>;
}

/// Health status of the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Whether the connection is working.
    pub connected: bool,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u64,
    /// Number of advisory keys (approximate).
    pub advisory_count: u64,
    /// Redis server info (version, etc.).
    pub server_info: Option<String>,
}

/// Enrichment data stored separately for CVEs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentData {
    /// EPSS score (0.0 - 1.0).
    pub epss_score: Option<f64>,
    /// EPSS percentile (0.0 - 1.0).
    pub epss_percentile: Option<f64>,
    /// Whether in CISA KEV catalog.
    pub is_kev: bool,
    /// KEV due date (RFC3339).
    pub kev_due_date: Option<String>,
    /// KEV date added (RFC3339).
    pub kev_date_added: Option<String>,
    /// Whether used in ransomware campaigns.
    pub kev_ransomware: Option<bool>,
    /// Last updated timestamp.
    pub updated_at: String,
}

/// Cached OSS Index component report.
///
/// Stores advisories from OSS Index along with
/// cache metadata for TTL management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OssIndexCache {
    /// The converted advisories from OSS Index.
    pub advisories: Vec<crate::models::Advisory>,
    /// When this was cached.
    pub cached_at: chrono::DateTime<chrono::Utc>,
    /// TTL in seconds from cache time.
    pub ttl_seconds: u64,
}

/// Default cache TTL: 1 hour.
const DEFAULT_OSSINDEX_CACHE_TTL: u64 = 3600;

impl OssIndexCache {
    /// Create a new cache entry with default TTL.
    pub fn new(advisories: Vec<crate::models::Advisory>) -> Self {
        Self {
            advisories,
            cached_at: chrono::Utc::now(),
            ttl_seconds: DEFAULT_OSSINDEX_CACHE_TTL,
        }
    }

    /// Create a new cache entry with custom TTL.
    pub fn with_ttl(advisories: Vec<crate::models::Advisory>, ttl_seconds: u64) -> Self {
        Self {
            advisories,
            cached_at: chrono::Utc::now(),
            ttl_seconds,
        }
    }

    /// Check if this cache entry is still valid (not expired).
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// Check if this cache entry has expired.
    pub fn is_expired(&self) -> bool {
        let age = chrono::Utc::now().signed_duration_since(self.cached_at);
        age.num_seconds() >= self.ttl_seconds as i64
    }

    /// Get the remaining TTL in seconds.
    pub fn remaining_ttl(&self) -> i64 {
        let age = chrono::Utc::now().signed_duration_since(self.cached_at);
        (self.ttl_seconds as i64) - age.num_seconds()
    }
}

/// Redis/DragonflyDB storage implementation.
pub struct DragonflyStore {
    client: redis::Client,
    config: StoreConfig,
}

impl DragonflyStore {
    /// Create a new store with default configuration.
    pub fn new(url: &str) -> Result<Self> {
        Self::with_config(url, StoreConfig::default())
    }

    /// Create a new store with custom configuration.
    pub fn with_config(url: &str, config: StoreConfig) -> Result<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self { client, config })
    }

    /// Get the key prefix for this store.
    pub fn key_prefix(&self) -> &str {
        &self.config.key_prefix
    }

    /// Build a key with the configured prefix.
    fn key(&self, suffix: &str) -> String {
        format!("{}:{}", self.config.key_prefix, suffix)
    }

    fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder =
            zstd::stream::write::Encoder::new(Vec::new(), self.config.compression_level)?;
        encoder.write_all(data)?;
        encoder
            .finish()
            .map_err(|e| AdvisoryError::compression(e.to_string()))
    }

    fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = zstd::stream::read::Decoder::new(data)?;
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decoded)?;
        Ok(decoded)
    }

    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(AdvisoryError::from)
    }
}

#[async_trait]
impl AdvisoryStore for DragonflyStore {
    #[instrument(skip(self, advisories), fields(count = advisories.len()))]
    async fn upsert_batch(&self, advisories: &[Advisory], source: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let mut pipe = redis::pipe();

        for advisory in advisories {
            let json = serde_json::to_vec(advisory)?;
            let compressed = self.compress(&json)?;

            let data_key = self.key(&format!("data:{}", advisory.id));

            // Store data with optional TTL
            if let Some(ttl) = self.config.ttl_seconds {
                pipe.cmd("SETEX").arg(&data_key).arg(ttl).arg(compressed);
            } else {
                pipe.set(&data_key, compressed);
            }

            // Update index
            for affected in &advisory.affected {
                let idx_key = self.key(&format!(
                    "idx:{}:{}",
                    affected.package.ecosystem, affected.package.name
                ));
                pipe.sadd(&idx_key, &advisory.id);
            }
        }

        // Update meta
        pipe.set(
            self.key(&format!("meta:{}", source)),
            chrono::Utc::now().to_rfc3339(),
        );

        pipe.query_async::<()>(&mut conn).await?;
        info!("Upserted {} advisories from {}", advisories.len(), source);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Advisory>> {
        let mut conn = self.get_connection().await?;
        let data: Option<Vec<u8>> = conn.get(self.key(&format!("data:{}", id))).await?;

        match data {
            Some(bytes) => {
                let decompressed = Self::decompress(&bytes)?;
                let advisory = serde_json::from_slice(&decompressed)?;
                Ok(Some(advisory))
            }
            None => Ok(None),
        }
    }

    async fn get_by_package(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>> {
        let mut conn = self.get_connection().await?;
        let ids: Vec<String> = conn
            .smembers(self.key(&format!("idx:{}:{}", ecosystem, package)))
            .await?;

        let mut advisories = Vec::new();
        for id in ids {
            if let Some(advisory) = self.get(&id).await? {
                advisories.push(advisory);
            }
        }
        Ok(advisories)
    }

    async fn last_sync(&self, source: &str) -> Result<Option<String>> {
        let mut conn = self.get_connection().await?;
        Ok(conn.get(self.key(&format!("meta:{}", source))).await?)
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        let start = Instant::now();

        let mut conn = self.get_connection().await?;

        // Ping to check connection
        let pong: String = redis::cmd("PING").query_async(&mut conn).await?;
        let connected = pong == "PONG";

        let latency_ms = start.elapsed().as_millis() as u64;

        // Get approximate key count
        let advisory_count = self.advisory_count().await.unwrap_or(0);

        // Get server info
        let info: std::result::Result<String, _> = redis::cmd("INFO")
            .arg("server")
            .query_async(&mut conn)
            .await;
        let server_info = info.ok().and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("redis_version:"))
                .map(|l| l.to_string())
        });

        Ok(HealthStatus {
            connected,
            latency_ms,
            advisory_count,
            server_info,
        })
    }

    async fn get_by_package_stream(
        &self,
        ecosystem: &str,
        package: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Advisory>> + Send + '_>>> {
        let idx_key = self.key(&format!("idx:{}:{}", ecosystem, package));

        let stream = try_stream! {
            let mut conn = self.get_connection().await?;

            // Use SSCAN for memory-efficient iteration
            let mut cursor = 0u64;
            loop {
                let (new_cursor, ids): (u64, Vec<String>) = redis::cmd("SSCAN")
                    .arg(&idx_key)
                    .arg(cursor)
                    .arg("COUNT")
                    .arg(100)
                    .query_async(&mut conn)
                    .await?;

                for id in ids {
                    if let Some(advisory) = self.get(&id).await? {
                        yield advisory;
                    }
                }

                cursor = new_cursor;
                if cursor == 0 {
                    break;
                }
            }
        };

        Ok(Box::pin(stream))
    }

    async fn get_batch(&self, ids: &[String]) -> Result<Vec<Advisory>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut conn = self.get_connection().await?;
        let keys: Vec<String> = ids
            .iter()
            .map(|id| self.key(&format!("data:{}", id)))
            .collect();

        let data: Vec<Option<Vec<u8>>> =
            redis::cmd("MGET").arg(&keys).query_async(&mut conn).await?;

        let mut advisories = Vec::new();
        for bytes_opt in data {
            if let Some(bytes) = bytes_opt {
                let decompressed = Self::decompress(&bytes)?;
                let advisory: Advisory = serde_json::from_slice(&decompressed)?;
                advisories.push(advisory);
            }
        }

        Ok(advisories)
    }

    async fn store_enrichment(&self, cve_id: &str, data: &EnrichmentData) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let key = self.key(&format!("enrich:{}", cve_id));
        let json = serde_json::to_string(data)?;

        if let Some(ttl) = self.config.ttl_seconds {
            redis::cmd("SETEX")
                .arg(&key)
                .arg(ttl)
                .arg(json)
                .query_async::<()>(&mut conn)
                .await?;
        } else {
            let _: () = conn.set(&key, json).await?;
        }

        Ok(())
    }

    async fn get_enrichment(&self, cve_id: &str) -> Result<Option<EnrichmentData>> {
        let mut conn = self.get_connection().await?;
        let key = self.key(&format!("enrich:{}", cve_id));
        let data: Option<String> = conn.get(&key).await?;

        match data {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    async fn get_enrichment_batch(
        &self,
        cve_ids: &[String],
    ) -> Result<Vec<(String, EnrichmentData)>> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut conn = self.get_connection().await?;
        let keys: Vec<String> = cve_ids
            .iter()
            .map(|id| self.key(&format!("enrich:{}", id)))
            .collect();

        let data: Vec<Option<String>> =
            redis::cmd("MGET").arg(&keys).query_async(&mut conn).await?;

        let mut results = Vec::new();
        for (cve_id, json_opt) in cve_ids.iter().zip(data) {
            if let Some(json) = json_opt {
                if let Ok(enrichment) = serde_json::from_str(&json) {
                    results.push((cve_id.clone(), enrichment));
                }
            }
        }

        Ok(results)
    }

    async fn update_sync_timestamp(&self, source: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let _: () = conn
            .set(
                self.key(&format!("meta:{}", source)),
                chrono::Utc::now().to_rfc3339(),
            )
            .await?;
        Ok(())
    }

    async fn advisory_count(&self) -> Result<u64> {
        let mut conn = self.get_connection().await?;
        let pattern = self.key("data:*");

        // Use SCAN to count keys matching pattern
        let mut count = 0u64;
        let mut cursor = 0u64;

        loop {
            let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(1000)
                .query_async(&mut conn)
                .await?;

            count += keys.len() as u64;
            cursor = new_cursor;

            if cursor == 0 {
                break;
            }
        }

        Ok(count)
    }

    async fn store_ossindex_cache(&self, purl: &str, cache: &OssIndexCache) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let key = self.key(&format!("ossidx:{}", Self::hash_purl(purl)));
        let json = serde_json::to_string(cache)?;

        // Use the remaining TTL or the configured TTL
        let ttl = cache.remaining_ttl().max(1) as u64;
        redis::cmd("SETEX")
            .arg(&key)
            .arg(ttl)
            .arg(json)
            .query_async::<()>(&mut conn)
            .await?;

        Ok(())
    }

    async fn get_ossindex_cache(&self, purl: &str) -> Result<Option<OssIndexCache>> {
        let mut conn = self.get_connection().await?;
        let key = self.key(&format!("ossidx:{}", Self::hash_purl(purl)));
        let data: Option<String> = conn.get(&key).await?;

        match data {
            Some(json) => {
                let cache: OssIndexCache = serde_json::from_str(&json)?;
                // Double-check validity (Redis TTL should handle this, but be safe)
                if cache.is_valid() {
                    Ok(Some(cache))
                } else {
                    // Cache expired, delete it
                    let _: () = conn.del(&key).await?;
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn invalidate_ossindex_cache(&self, purl: &str) -> Result<()> {
        let mut conn = self.get_connection().await?;
        let key = self.key(&format!("ossidx:{}", Self::hash_purl(purl)));
        let _: () = conn.del(&key).await?;
        Ok(())
    }

    async fn invalidate_all_ossindex_cache(&self) -> Result<u64> {
        let mut conn = self.get_connection().await?;
        let pattern = self.key("ossidx:*");

        // Use SCAN to find all OSS Index cache keys
        let mut deleted = 0u64;
        let mut cursor = 0u64;

        loop {
            let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(1000)
                .query_async(&mut conn)
                .await?;

            if !keys.is_empty() {
                let count: u64 = redis::cmd("DEL").arg(&keys).query_async(&mut conn).await?;
                deleted += count;
            }

            cursor = new_cursor;
            if cursor == 0 {
                break;
            }
        }

        Ok(deleted)
    }
}

impl DragonflyStore {
    /// Generate a hash key for a PURL string.
    fn hash_purl(purl: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        purl.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}
