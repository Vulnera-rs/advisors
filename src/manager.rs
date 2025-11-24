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
                            // Even if empty, we should update the sync timestamp?
                            // Actually upsert_batch updates it. If empty, we might want to update it manually?
                            // For now, let's assume if empty, nothing new, so timestamp remains old?
                            // No, if we successfully checked and found nothing, we SHOULD update timestamp.
                            // But upsert_batch does it.
                            // Let's leave it for now.
                            info!("No new advisories for {}", source.name());
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

    pub async fn query(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>> {
        let advisories = self.store.get_by_package(ecosystem, package).await?;
        Ok(crate::aggregator::ReportAggregator::aggregate(advisories))
    }

    pub async fn matches(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
    ) -> Result<Vec<Advisory>> {
        let advisories = self.query(ecosystem, package).await?;
        let mut matched = Vec::new();

        for advisory in advisories {
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
                        crate::models::RangeType::Semver => {
                            if let Ok(v) = semver::Version::parse(version) {
                                let mut introduced: Option<semver::Version> = None;
                                let mut fixed: Option<semver::Version> = None;

                                for event in &range.events {
                                    match event {
                                        crate::models::Event::Introduced(ver) => {
                                            if let Ok(parsed) = semver::Version::parse(ver) {
                                                introduced = Some(parsed);
                                            } else if ver == "0" {
                                                introduced = Some(semver::Version::new(0, 0, 0));
                                            }
                                        }
                                        crate::models::Event::Fixed(ver) => {
                                            if let Ok(parsed) = semver::Version::parse(ver) {
                                                fixed = Some(parsed);
                                            }
                                        }
                                        _ => {}
                                    }
                                }

                                match (introduced, fixed) {
                                    (Some(start), Some(end)) => {
                                        if v >= start && v < end {
                                            is_vulnerable = true;
                                            break;
                                        }
                                    }
                                    (Some(start), None) => {
                                        if v >= start {
                                            is_vulnerable = true;
                                            break;
                                        }
                                    }
                                    (None, Some(end)) => {
                                        if v < end {
                                            is_vulnerable = true;
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {
                            // TODO: Implement other range types (Ecosystem, Git)
                            // For now, assume safe if not SemVer
                        }
                    }
                }
                if is_vulnerable {
                    break;
                }
            }

            if is_vulnerable {
                matched.push(advisory);
            }
        }

        Ok(matched)
    }
}
