use crate::config::Config;
use crate::models::Advisory;
use crate::sources::{AdvisorySource, ghsa::GHSASource, nvd::NVDSource, osv::OSVSource};
use crate::store::{AdvisoryStore, DragonflyStore};
use anyhow::Result;
use std::sync::Arc;
use tracing::{error, info};

pub struct VulnerabilityManager {
    store: Arc<dyn AdvisoryStore + Send + Sync>,
    sources: Vec<Box<dyn AdvisorySource + Send + Sync>>,
}

impl VulnerabilityManager {
    pub async fn new(config: Config) -> Result<Self> {
        let store = Arc::new(DragonflyStore::new(&config.redis_url)?);

        let mut sources: Vec<Box<dyn AdvisorySource + Send + Sync>> = Vec::new();

        // OSV Source
        // Default ecosystems. In a real app, this might be configurable.
        let osv_ecosystems = vec![
            "npm".to_string(),
            "PyPI".to_string(),
            "crates.io".to_string(),
        ];
        sources.push(Box::new(OSVSource::new(osv_ecosystems)));

        // NVD Source
        sources.push(Box::new(NVDSource::new(config.nvd_api_key)));

        // GHSA Source
        sources.push(Box::new(GHSASource::new(config.ghsa_token)));

        Ok(Self { store, sources })
    }

    pub async fn sync_all(&self) -> Result<()> {
        info!("Starting full vulnerability sync...");

        for source in &self.sources {
            // In a real implementation, we might want to run these in parallel or track source names better
            // For now, we just run sequentially.
            match source.fetch(None).await {
                Ok(advisories) => {
                    if !advisories.is_empty() {
                        // We use a generic source name here, but ideally the source trait would return its name
                        if let Err(e) = self.store.upsert_batch(&advisories, "unknown_source").await
                        {
                            error!("Failed to store advisories: {}", e);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to fetch from source: {}", e);
                }
            }
        }

        info!("Sync completed.");
        Ok(())
    }

    pub async fn query(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>> {
        self.store.get_by_package(ecosystem, package).await
    }
}
