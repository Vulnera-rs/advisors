use crate::models::Advisory;
use anyhow::Result;
use async_trait::async_trait;
use redis::AsyncCommands;
use std::io::Write;
use tracing::{info, instrument};

#[async_trait]
pub trait AdvisoryStore {
    async fn upsert_batch(&self, advisories: &[Advisory], source: &str) -> Result<()>;
    async fn get(&self, id: &str) -> Result<Option<Advisory>>;
    async fn get_by_package(&self, ecosystem: &str, package: &str) -> Result<Vec<Advisory>>;
    async fn last_sync(&self, source: &str) -> Result<Option<String>>;
}

pub struct DragonflyStore {
    client: redis::Client,
}

impl DragonflyStore {
    pub fn new(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)?;
        Ok(Self { client })
    }

    fn compress(data: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3)?;
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    fn decompress(data: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = zstd::stream::read::Decoder::new(data)?;
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decoded)?;
        Ok(decoded)
    }
}

#[async_trait]
impl AdvisoryStore for DragonflyStore {
    #[instrument(skip(self, advisories), fields(count = advisories.len()))]
    async fn upsert_batch(&self, advisories: &[Advisory], source: &str) -> Result<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let mut pipe = redis::pipe();

        for advisory in advisories {
            let json = serde_json::to_vec(advisory)?;
            let compressed = Self::compress(&json)?;

            // Store data
            pipe.set(format!("vuln:data:{}", advisory.id), compressed);

            // Update index
            for affected in &advisory.affected {
                let key = format!(
                    "vuln:idx:{}:{}",
                    affected.package.ecosystem, affected.package.name
                );
                pipe.sadd(key, &advisory.id);
            }
        }

        // Update meta
        pipe.set(
            format!("vuln:meta:{}", source),
            chrono::Utc::now().to_rfc3339(),
        );

        pipe.query_async::<()>(&mut conn).await?;
        info!("Upserted {} advisories from {}", advisories.len(), source);
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<Advisory>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let data: Option<Vec<u8>> = conn.get(format!("vuln:data:{}", id)).await?;

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
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let ids: Vec<String> = conn
            .smembers(format!("vuln:idx:{}:{}", ecosystem, package))
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
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        Ok(conn.get(format!("vuln:meta:{}", source)).await?)
    }
}
