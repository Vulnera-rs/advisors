use super::AdvisorySource;
use crate::error::{AdvisoryError, Result};
use crate::models::{
    Advisory, Affected, Event, Package, Range, RangeTranslation, RangeTranslationStatus,
    RangeType, Reference, ReferenceType,
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
    api_url: String,
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

        Self {
            token,
            client,
            api_url: "https://api.github.com/graphql".to_string(),
        }
    }

    #[cfg(test)]
    pub fn with_api_url(mut self, url: String) -> Self {
        self.api_url = url;
        self
    }

    fn translate_vulnerable_range(raw: &str, fixed: Option<&str>) -> (Vec<Event>, RangeTranslation) {
        let range = raw.trim();
        if range.is_empty() {
            let translation = RangeTranslation {
                source: "GHSA".to_string(),
                raw: Some(raw.to_string()),
                status: RangeTranslationStatus::Invalid,
                reason: Some("empty vulnerableVersionRange".to_string()),
            };
            return (Vec::new(), translation);
        }

        let mut introduced: Option<String> = None;
        let mut fixed_event: Option<String> = None;
        let mut last_affected: Option<String> = None;
        let mut status = RangeTranslationStatus::Exact;
        let mut reason: Option<String> = None;

        for part in range.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
            if let Some(value) = part.strip_prefix(">=") {
                introduced = Some(value.trim().to_string());
            } else if let Some(value) = part.strip_prefix("<=") {
                last_affected = Some(value.trim().to_string());
            } else if let Some(value) = part.strip_prefix('>') {
                introduced = Some(value.trim().to_string());
                status = RangeTranslationStatus::Lossy;
                reason = Some("exclusive lower bound mapped to introduced event".to_string());
            } else if let Some(value) = part.strip_prefix("<") {
                fixed_event = Some(value.trim().to_string());
            } else if let Some(value) = part.strip_prefix('=') {
                introduced = Some(value.trim().to_string());
                last_affected = Some(value.trim().to_string());
            } else {
                status = RangeTranslationStatus::Unsupported;
                reason = Some(format!("unsupported comparator segment: {part}"));
            }
        }

        if matches!(status, RangeTranslationStatus::Unsupported)
            && introduced.is_none()
            && fixed_event.is_none()
            && last_affected.is_none()
        {
            let translation = RangeTranslation {
                source: "GHSA".to_string(),
                raw: Some(raw.to_string()),
                status,
                reason,
            };
            return (Vec::new(), translation);
        }

        let mut events = Vec::new();
        if let Some(intro) = introduced {
            events.push(Event::Introduced(intro));
        } else {
            events.push(Event::Introduced("0".to_string()));
            if matches!(status, RangeTranslationStatus::Exact) {
                status = RangeTranslationStatus::Lossy;
                reason = Some("missing lower bound; defaulted to introduced=0".to_string());
            }
        }

        if let Some(fixed) = fixed_event {
            events.push(Event::Fixed(fixed));
        } else if let Some(last) = last_affected {
            events.push(Event::LastAffected(last));
        } else if let Some(fixed) = fixed {
            events.push(Event::Fixed(fixed.to_string()));
            if matches!(status, RangeTranslationStatus::Exact) {
                status = RangeTranslationStatus::Lossy;
                reason = Some("missing upper bound; used firstPatchedVersion".to_string());
            }
        }

        let translation = RangeTranslation {
            source: "GHSA".to_string(),
            raw: Some(raw.to_string()),
            status,
            reason,
        };
        (events, translation)
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

            let query = r#"
            query($cursor: String, $updatedSince: DateTime) {
                securityAdvisories(first: 100, after: $cursor, updatedSince: $updatedSince) {
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                    nodes {
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
                        vulnerabilities(first: 100) {
                            nodes {
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
                }
            }
            "#;

            let variables = if let Some(since_dt) = since {
                json!({
                    "cursor": cursor,
                    "updatedSince": since_dt.to_rfc3339(),
                })
            } else {
                json!({
                    "cursor": cursor,
                    "updatedSince": serde_json::Value::Null,
                })
            };

            let body = serde_json::to_string(&json!({
                "query": query,
                "variables": variables
            }))?;

            let response = self
                .client
                .post(&self.api_url)
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
                return Err(AdvisoryError::source_fetch(
                    "GHSA",
                    format!("API returned {}: {}", status, text),
                ));
            }

            let data: GraphQlResponse = response.json().await?;

            if let Some(errors) = data.errors {
                warn!("GraphQL errors: {:?}", errors);
                return Err(AdvisoryError::source_fetch(
                    "GHSA",
                    format!("GraphQL errors: {:?}", errors),
                ));
            }

            if let Some(data) = data.data {
                for advisory_node in data.security_advisories.nodes {
                    // Map to canonical Advisory
                    let mut references: Vec<Reference> = advisory_node
                        .references
                        .iter()
                        .map(|r| Reference {
                            reference_type: ReferenceType::Web,
                            url: r.url.clone(),
                        })
                        .collect();

                    // Add identifiers as aliases
                    let mut aliases = Vec::new();
                    for id in &advisory_node.identifiers {
                        aliases.push(id.value.clone());
                    }

                    // Add identifiers as references/aliases
                    for id in &advisory_node.identifiers {
                        references.push(Reference {
                            reference_type: ReferenceType::Other,
                            url: format!("{}:{}", id.id_type, id.value),
                        });
                    }

                    let mut affected = Vec::new();
                    for vuln in advisory_node.vulnerabilities.nodes {
                        let fixed = vuln
                            .first_patched_version
                            .as_ref()
                            .map(|v| v.identifier.as_str());
                        let (events, translation) =
                            Self::translate_vulnerable_range(&vuln.vulnerable_version_range, fixed);

                        affected.push(Affected {
                            package: Package {
                                ecosystem: vuln.package.ecosystem,
                                name: vuln.package.name,
                                purl: None,
                            },
                            ranges: vec![Range {
                                range_type: RangeType::Ecosystem,
                                events,
                                repo: None,
                            }],
                            versions: vec![],
                            ecosystem_specific: Some(json!({
                                "vulnerable_range": vuln.vulnerable_version_range
                            })),
                            database_specific: Some(json!({
                                "range_translation": translation,
                            })),
                        });
                    }

                    advisories.push(Advisory {
                        id: advisory_node.ghsa_id,
                        summary: Some(advisory_node.summary),
                        details: Some(advisory_node.description),
                        affected,
                        references,
                        published: Some(advisory_node.published_at),
                        modified: Some(advisory_node.updated_at),
                        aliases: Some(aliases),
                        database_specific: Some(json!({ "source": "GHSA" })),
                        enrichment: None,
                    });
                }

                if data.security_advisories.page_info.has_next_page {
                    cursor = data.security_advisories.page_info.end_cursor;
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
    #[serde(rename = "securityAdvisories")]
    security_advisories: SecurityAdvisories,
}

#[derive(Deserialize)]
struct SecurityAdvisories {
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
    nodes: Vec<GhsaAdvisoryNode>,
}

#[derive(Deserialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}

#[derive(Deserialize)]
struct GhsaAdvisoryNode {
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
    vulnerabilities: GhsaVulnerabilitiesConnection,
}

#[derive(Deserialize)]
struct GhsaVulnerabilitiesConnection {
    nodes: Vec<GhsaVulnerability>,
}

#[derive(Deserialize)]
struct GhsaVulnerability {
    package: GhsaPackage,
    #[serde(rename = "vulnerableVersionRange")]
    vulnerable_version_range: String,
    #[serde(rename = "firstPatchedVersion")]
    first_patched_version: Option<GhsaVersion>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_fetch_advisories_full() {
        let mock_server = MockServer::start().await;
        let source = GHSASource::new("fake_token".to_string()).with_api_url(mock_server.uri());

        let response_body = json!({
            "data": {
                "securityAdvisories": {
                    "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": null
                    },
                    "nodes": [
                        {
                            "ghsaId": "GHSA-xxxx-yyyy-zzzz",
                            "summary": "Test Advisory",
                            "description": "This is a test advisory",
                            "publishedAt": "2023-01-01T00:00:00Z",
                            "updatedAt": "2023-01-02T00:00:00Z",
                            "references": [
                                { "url": "https://example.com" }
                            ],
                            "identifiers": [
                                { "type": "CVE", "value": "CVE-2023-1234" }
                            ],
                            "vulnerabilities": {
                                "nodes": [
                                    {
                                        "package": {
                                            "name": "test-package",
                                            "ecosystem": "NPM"
                                        },
                                        "vulnerableVersionRange": "< 1.0.0",
                                        "firstPatchedVersion": {
                                            "identifier": "1.0.0"
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        });

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains("securityAdvisories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        let advisories = source.fetch(None).await.unwrap();
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0].id, "GHSA-xxxx-yyyy-zzzz");
        assert_eq!(advisories[0].affected.len(), 1);
        assert_eq!(advisories[0].affected[0].package.name, "test-package");
    }

    #[tokio::test]
    async fn test_fetch_advisories_since() {
        let mock_server = MockServer::start().await;
        let source = GHSASource::new("fake_token".to_string()).with_api_url(mock_server.uri());

        let response_body = json!({
            "data": {
                "securityAdvisories": {
                    "pageInfo": {
                        "hasNextPage": false,
                        "endCursor": null
                    },
                    "nodes": []
                }
            }
        });

        Mock::given(method("POST"))
            .and(path("/"))
            .and(body_string_contains("updatedSince"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response_body))
            .mount(&mock_server)
            .await;

        let since = Utc::now();
        let advisories = source.fetch(Some(since)).await.unwrap();
        assert_eq!(advisories.len(), 0);
    }
}
