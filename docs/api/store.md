# Storage Backend

Vulnera Advisor uses Redis/DragonflyDB for persistent storage with zstd compression.

## Store Types

### DragonflyStore

The default Redis/DragonflyDB implementation.

```rust
use vulnera_advisor::{DragonflyStore, StoreConfig};

let config = StoreConfig::default();
let store = DragonflyStore::new("redis://localhost:6379", config).await?;
```

### StoreConfig

Configuration options for the store.

```rust
pub struct StoreConfig {
    pub ttl_seconds: Option<u64>,           // Advisory cache TTL
    pub ossindex_ttl_seconds: Option<u64>,  // OSS Index cache TTL
    pub compression_level: i32,              // zstd compression level
}
```

## AdvisoryStore Trait

All stores implement this trait:

```rust
#[async_trait]
pub trait AdvisoryStore: Send + Sync {
    async fn store_advisory(&self, advisory: &Advisory) -> Result<()>;
    async fn get_advisory(&self, id: &str) -> Result<Option<Advisory>>;
    async fn get_by_package(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>>;
    async fn health_check(&self) -> Result<HealthStatus>;
    // ... more methods
}
```

## Health Check

```rust
let health = manager.health_check().await?;
println!("Store status: {:?}", health.status);
println!("Advisory count: {}", health.advisory_count);
```

### HealthStatus

```rust
pub struct HealthStatus {
    pub status: StoreStatus,
    pub advisory_count: usize,
    pub last_sync: Option<DateTime<Utc>>,
}

pub enum StoreStatus {
    Healthy,
    Degraded,
    Unavailable,
}
```

## Caching

### OSS Index Cache

Results from OSS Index are automatically cached:

```rust
let manager = VulnerabilityManager::builder()
    .redis_url("redis://localhost:6379")
    .store_config(StoreConfig {
        ossindex_ttl_seconds: Some(3600), // 1 hour
        ..Default::default()
    })
    .with_ossindex(None)
    .build()?;

// Results are cached automatically
let advisories = manager.query_ossindex(&purls).await?;

// Invalidate cache if needed
manager.invalidate_ossindex_cache(&purls).await?;
```

### Enrichment Cache

EPSS and KEV data is cached with enrichment:

```rust
// Sync enrichment data
manager.sync_enrichment().await?;

// Data is cached for subsequent queries
let advisories = manager.query_enriched("npm", "lodash").await?;
```

## Sync Timestamps

Track when sources were last synced:

```rust
// Reset sync to force full re-sync
manager.reset_sync("osv").await?;

// Reset all syncs
manager.reset_all_syncs().await?;
```

## Compression

All advisory data is compressed with zstd before storage:

- ~70% space savings
- Transparent compression/decompression
- Configurable compression level (default: 3)

```rust
let config = StoreConfig {
    compression_level: 5, // 1-22, higher = better compression
    ..Default::default()
};
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis connection URL | Required |
| `VULNERA__STORE__TTL_SECONDS` | Advisory cache TTL | None |
