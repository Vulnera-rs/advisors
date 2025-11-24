use crate::config::Config;
use crate::models::Advisory;
use crate::sources::{AdvisorySource, ghsa::GHSASource, nvd::NVDSource, osv::OSVSource};
use crate::store::{AdvisoryStore, DragonflyStore};
use anyhow::Result;
use std::sync::Arc;
use tracing::{error, info};

pub struct VulnerabilityManager {
    store: Arc<dyn AdvisoryStore + Send + Sync>,
    sources: Vec<Arc<dyn AdvisorySource + Send + Sync>>,
}

impl VulnerabilityManager {
    pub async fn new(config: Config) -> Result<Self> {
        let store = Arc::new(DragonflyStore::new(&config.redis_url)?);

        let mut sources: Vec<Arc<dyn AdvisorySource + Send + Sync>> = Vec::new();

        // OSV Source
        let osv_ecosystems = vec![
            "npm".to_string(),
            "PyPI".to_string(),
            "Maven".to_string(),
            "crates.io".to_string(),
            "Go".to_string(),
            "Packagist".to_string(),
            "RubyGems".to_string(),
            "NuGet".to_string(),
        ];
        sources.push(Arc::new(OSVSource::new(osv_ecosystems)));

        // NVD Source
        sources.push(Arc::new(NVDSource::new(config.nvd_api_key)));

        // GHSA Source
        sources.push(Arc::new(GHSASource::new(config.ghsa_token)));

        Ok(Self { store, sources })
    }

    pub async fn sync_all(&self) -> Result<()> {
        info!("Starting full vulnerability sync...");

        let mut handles = Vec::new();

        for source in &self.sources {
            let source = source.clone();
            let store = self.store.clone();

            let handle = tokio::spawn(async move {
                match source.fetch(None).await {
                    Ok(advisories) => {
                        if !advisories.is_empty() {
                            // Ideally we'd have a source identifier here
                            if let Err(e) = store.upsert_batch(&advisories, "unknown_source").await
                            {
                                error!("Failed to store advisories: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to fetch from source: {}", e);
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

    pub async fn query(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>> {
        self.store.get_by_package(ecosystem, package).await
    }
}
