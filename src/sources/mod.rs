pub mod ghsa;
pub mod nvd;
pub mod osv;

use crate::models::Advisory;
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait AdvisorySource: Send + Sync {
    async fn fetch(&self, since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>>;
    fn name(&self) -> &str;
}
