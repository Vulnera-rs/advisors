use super::AdvisorySource;
use crate::error::{AdvisoryError, Result};
use crate::models::{
    Advisory, Affected, Event, Package, Range, RangeType, Reference, ReferenceType,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{RetryTransientMiddleware, policies::ExponentialBackoff};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct GHSASource {
    token: String,
    client: ClientWithMiddleware,
}

impl GHSASource {
    pub fn new(token: String) -> Self {
        // Build client with timeout and retry policy
        let base_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build HTTP client");

        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(3);
        let client = ClientBuilder::new(base_client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        Self { token, client }
    }
}

#[async_trait]
impl AdvisorySource for GHSASource {
    async fn fetch(&self, since: Option<DateTime<Utc>>) -> Result<Vec<Advisory>> {
        let mut advisories = Vec::new();
        let mut cursor: Option<String> = None;
        let mut page_count = 0;

        info!(
            "Starting GHSA sync{}",
            since
                .map(|d| format!(" since {}", d))
                .unwrap_or_else(|| " (full)".to_string())
        );

        loop {
            page_count += 1;
            // Use updatedSince filter when available
            let query = if since.is_some() {
                r#"
                query($cursor: String, $updatedSince: DateTime!) {
                    securityVulnerabilities(first: 100, after: $cursor, updatedSince: $updatedSince) {
                        pageInfo {
                            hasNextPage
                            endCursor
                        }
                        nodes {
                            advisory {
                                ghsaId
                                summary
                                description
                                publishedAt
                                updatedAt
                                references {
                                    url
                                }
                                identifiers {
                                    type
                                    value
                                }
                            }
                            package {
                                name
                                ecosystem
                            }
                            vulnerableVersionRange
                            firstPatchedVersion {
                                identifier
                            }
                        }
                    }
                }
                "#
            } else {
                r#"
                query($cursor: String) {
                    securityVulnerabilities(first: 100, after: $cursor) {
                        pageInfo {
                            hasNextPage
                            endCursor
                        }
                        nodes {
                            advisory {
                                ghsaId
                                summary
                                description
                                publishedAt
                                updatedAt
                                references {
                                    url
                                }
                                identifiers {
                                    type
                                    value
                                }
                            }
                            package {
                                name
                                ecosystem
                            }
                            vulnerableVersionRange
                            firstPatchedVersion {
                                identifier
                            }
                        }
                    }
                }
                "#
            };

            let variables = if let Some(since_dt) = since {
                json!({
                    "cursor": cursor,
                    "updatedSince": since_dt.to_rfc3339(),
                })
            } else {
                json!({
                    "cursor": cursor,
                })
            };

            let body = serde_json::to_string(&json!({
                "query": query,
                "variables": variables
            }))?;

            let response = self
                .client
                .post("https://api.github.com/graphql")
                .header("Authorization", format!("Bearer {}", self.token))
                .header("User-Agent", "vulnera-advisors")
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await?;

            if !response.status().is_success() {
                let status = response.status();
                let text = response.text().await?;
                warn!("GHSA API error {}: {}", status, text);
                // Return error instead of silently failing
                return Err(AdvisoryError::source_fetch(
                    "GHSA",
                    format!("API returned {}: {}", status, text),
                ));
            }

            let data: GraphQlResponse = response.json().await?;

            if let Some(errors) = data.errors {
                warn!("GraphQL errors: {:?}", errors);
                // Return error if GraphQL reports errors
                return Err(AdvisoryError::source_fetch(
                    "GHSA",
                    format!("GraphQL errors: {:?}", errors),
                ));
            }

            if let Some(data) = data.data {
                for node in data.security_vulnerabilities.nodes {
                    let advisory_data = node.advisory;

                    // Map to canonical Advisory
                    let mut references: Vec<Reference> = advisory_data
                        .references
                        .iter()
                        .map(|r| Reference {
                            reference_type: ReferenceType::Web,
                            url: r.url.clone(),
                        })
                        .collect();

                    // Add identifiers as aliases
                    let mut aliases = Vec::new();
                    for id in &advisory_data.identifiers {
                        aliases.push(id.value.clone());
                    }

                    // Add identifiers as references/aliases
                    for id in advisory_data.identifiers {
                        references.push(Reference {
                            reference_type: ReferenceType::Other,
                            url: format!("{}:{}", id.id_type, id.value),
                        });
                    }

                    let affected = vec![Affected {
                        package: Package {
                            ecosystem: node.package.ecosystem,
                            name: node.package.name,
                            purl: None, // Could construct PURL if needed
                        },
                        ranges: vec![Range {
                            range_type: RangeType::Ecosystem,
                            events: vec![
                                Event::Introduced("0".to_string()), // Simplified
                                Event::Fixed(
                                    node.first_patched_version
                                        .map(|v| v.identifier)
                                        .unwrap_or_else(|| "0.0.0".to_string()),
                                ),
                            ],
                            repo: None,
                        }],
                        versions: vec![], // We have ranges
                        ecosystem_specific: Some(json!({
                            "vulnerable_range": node.vulnerable_version_range
                        })),
                        database_specific: None,
                    }];

                    advisories.push(Advisory {
                        id: advisory_data.ghsa_id,
                        summary: Some(advisory_data.summary),
                        details: Some(advisory_data.description),
                        affected,
                        references,
                        published: Some(advisory_data.published_at),
                        modified: Some(advisory_data.updated_at),
                        aliases: Some(aliases),
                        database_specific: Some(json!({ "source": "GHSA" })),
                        enrichment: None,
                    });
                }

                if data.security_vulnerabilities.page_info.has_next_page {
                    cursor = data.security_vulnerabilities.page_info.end_cursor;
                    if page_count % 10 == 0 {
                        info!(
                            "GHSA sync progress: {} pages, {} advisories so far",
                            page_count,
                            advisories.len()
                        );
                    }
                    debug!("Fetching next page of GHSA advisories...");
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        info!("Fetched {} advisories from GHSA", advisories.len());
        Ok(advisories)
    }

    fn name(&self) -> &str {
        "GHSA"
    }
}

#[derive(Deserialize)]
struct GraphQlResponse {
    data: Option<Data>,
    errors: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize)]
struct Data {
    #[serde(rename = "securityVulnerabilities")]
    security_vulnerabilities: SecurityVulnerabilities,
}

#[derive(Deserialize)]
struct SecurityVulnerabilities {
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}

#[derive(Deserialize)]
struct Node {
    advisory: GhsaAdvisory,
    package: GhsaPackage,
    #[serde(rename = "vulnerableVersionRange")]
    vulnerable_version_range: String,
    #[serde(rename = "firstPatchedVersion")]
    first_patched_version: Option<GhsaVersion>,
}

#[derive(Deserialize)]
struct GhsaAdvisory {
    #[serde(rename = "ghsaId")]
    ghsa_id: String,
    summary: String,
    description: String,
    #[serde(rename = "publishedAt")]
    published_at: DateTime<Utc>,
    #[serde(rename = "updatedAt")]
    updated_at: DateTime<Utc>,
    references: Vec<GhsaReference>,
    identifiers: Vec<GhsaIdentifier>,
}

#[derive(Deserialize)]
struct GhsaReference {
    url: String,
}

#[derive(Deserialize)]
struct GhsaIdentifier {
    #[serde(rename = "type")]
    id_type: String,
    value: String,
}

#[derive(Deserialize)]
struct GhsaPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct GhsaVersion {
    identifier: String,
}
