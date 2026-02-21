//! Advisory aggregation and deduplication.
//!
//! This module merges advisories from multiple sources based on their aliases
//! and CVE identifiers (e.g., a GHSA advisory and its corresponding CVE are merged into one).

use crate::models::{Advisory, Enrichment};
use once_cell::sync::Lazy;
use regex_lite::Regex;
use std::collections::{HashMap, HashSet};

static CVE_REGEX: Lazy<Result<Regex, regex_lite::Error>> =
    Lazy::new(|| Regex::new(r"(?i)(CVE-\d{4}-\d{4,})"));

/// Aggregator for merging and deduplicating advisories.
pub struct ReportAggregator;

impl ReportAggregator {
    /// Extract CVE IDs from an advisory ID or references.
    ///
    /// Looks for patterns like CVE-YYYY-XXXXX in the advisory ID and references.
    fn extract_cve_ids(advisory: &Advisory) -> HashSet<String> {
        let mut cves = HashSet::new();

        // Try to extract CVE from the advisory ID itself
        if let Some(cve) = Self::extract_cve_from_string(&advisory.id) {
            cves.insert(cve);
        }

        // Extract CVE from aliases if present
        if let Some(aliases) = &advisory.aliases {
            for alias in aliases {
                if let Some(cve) = Self::extract_cve_from_string(alias) {
                    cves.insert(cve);
                }
            }
        }

        // Extract CVE from references
        for reference in &advisory.references {
            if let Some(cve) = Self::extract_cve_from_string(&reference.url) {
                cves.insert(cve);
            }
        }

        cves
    }

    /// Extract a CVE ID from a string using a compiled regex.
    pub fn extract_cve_from_string(text: &str) -> Option<String> {
        // Use a static, pre-compiled regex for performance.
        if let Ok(regex) = &*CVE_REGEX
            && let Some(caps) = regex.captures(text)
        {
            return Some(caps[1].to_uppercase());
        }
        None
    }

    /// Aggregate advisories by merging duplicates based on aliases and CVE IDs.
    ///
    /// When multiple advisories refer to the same vulnerability (via aliases or CVE IDs),
    /// they are merged into a single advisory with combined information.
    pub fn aggregate(advisories: Vec<Advisory>) -> Vec<Advisory> {
        let mut deduplicated: HashMap<String, Advisory> = HashMap::new();
        let mut alias_map: HashMap<String, String> = HashMap::new();
        let mut cve_map: HashMap<String, String> = HashMap::new();

        // First pass: Index all advisories by ID, aliases, and extract CVEs
        for advisory in &advisories {
            // Build alias map
            if let Some(aliases) = &advisory.aliases {
                for alias in aliases {
                    alias_map.insert(alias.clone(), advisory.id.clone());
                }
            }

            // Build CVE map for cross-source deduplication
            let cves = Self::extract_cve_ids(advisory);
            for cve in cves {
                // Only use CVE as canonical if not already mapped to another ID
                cve_map.entry(cve).or_insert_with(|| advisory.id.clone());
            }
        }

        // Second pass: Merge
        for advisory in advisories {
            // Determine the "canonical" ID using aliases first
            let mut canonical_id = alias_map
                .get(&advisory.id)
                .cloned()
                .unwrap_or_else(|| advisory.id.clone());

            // Also check if this advisory has CVEs that map to another ID
            let advisory_cves = Self::extract_cve_ids(&advisory);
            for cve in advisory_cves {
                if let Some(mapped_id) = cve_map.get(&cve) {
                    // If we find a CVE mapping, use it (prefer CVE-based consolidation)
                    if mapped_id != &canonical_id {
                        canonical_id = mapped_id.clone();
                        break;
                    }
                }
            }

            match deduplicated.get_mut(&canonical_id) {
                Some(existing) => {
                    Self::merge(existing, advisory);
                }
                None => {
                    let mut new_entry = advisory;
                    new_entry.id = canonical_id.clone();
                    deduplicated.insert(canonical_id, new_entry);
                }
            }
        }

        deduplicated.into_values().collect()
    }

    /// Merge source advisory into target.
    fn merge(target: &mut Advisory, source: Advisory) {
        // Merge aliases
        let mut aliases = target.aliases.clone().unwrap_or_default();
        if let Some(source_aliases) = source.aliases {
            aliases.extend(source_aliases);
        }
        // Add source ID as alias if it's different
        if source.id != target.id {
            aliases.push(source.id.clone());
        }
        // Dedupe aliases
        let unique_aliases: HashSet<_> = aliases.into_iter().collect();
        target.aliases = Some(unique_aliases.into_iter().collect());

        // Merge references
        let mut refs = target.references.clone();
        refs.extend(source.references);
        // Simple dedupe by URL
        let mut unique_refs = Vec::new();
        let mut seen_urls = HashSet::new();
        for r in refs {
            if seen_urls.insert(r.url.clone()) {
                unique_refs.push(r);
            }
        }
        target.references = unique_refs;

        // Merge affected
        target.affected.extend(source.affected);

        // Merge details (prefer longer)
        if let Some(d) = &source.details
            && (target.details.is_none() || d.len() > target.details.as_ref().unwrap().len())
        {
            target.details = Some(d.clone());
        }

        // Merge summary (prefer longer)
        if let Some(s) = &source.summary
            && (target.summary.is_none() || s.len() > target.summary.as_ref().unwrap().len())
        {
            target.summary = Some(s.clone());
        }

        // Merge enrichment data
        Self::merge_enrichment(target, source.enrichment);
    }

    /// Merge enrichment data, preferring non-None values.
    fn merge_enrichment(target: &mut Advisory, source_enrichment: Option<Enrichment>) {
        let Some(source) = source_enrichment else {
            return;
        };

        let enrichment = target.enrichment.get_or_insert_with(Enrichment::default);

        // EPSS: prefer higher scores (more conservative)
        if let Some(score) = source.epss_score
            && enrichment.epss_score.map(|s| score > s).unwrap_or(true)
        {
            enrichment.epss_score = Some(score);
            enrichment.epss_percentile = source.epss_percentile;
            enrichment.epss_date = source.epss_date;
        }

        // KEV: OR the flags (if any source says it's KEV, it's KEV)
        enrichment.is_kev = enrichment.is_kev || source.is_kev;
        if source.kev_due_date.is_some() {
            enrichment.kev_due_date = source.kev_due_date;
        }
        if source.kev_date_added.is_some() {
            enrichment.kev_date_added = source.kev_date_added;
        }
        if source.kev_ransomware.is_some() {
            enrichment.kev_ransomware = source.kev_ransomware;
        }

        // CVSS: prefer higher scores (more conservative)
        if let Some(score) = source.cvss_v3_score
            && enrichment.cvss_v3_score.map(|s| score > s).unwrap_or(true)
        {
            enrichment.cvss_v3_score = Some(score);
            enrichment.cvss_v3_severity = source.cvss_v3_severity;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Affected, Package, Reference, ReferenceType};
    use chrono::Utc;

    /// Helper function to create a test advisory
    fn create_advisory(
        id: &str,
        summary: Option<&str>,
        aliases: Option<Vec<&str>>,
        references: Option<Vec<&str>>,
    ) -> Advisory {
        Advisory {
            id: id.to_string(),
            summary: summary.map(|s| s.to_string()),
            details: None,
            affected: vec![Affected {
                package: Package {
                    ecosystem: "pypi".to_string(),
                    name: "test-package".to_string(),
                    purl: None,
                },
                ranges: vec![],
                versions: vec![],
                ecosystem_specific: None,
                database_specific: None,
            }],
            references: references
                .unwrap_or_default()
                .into_iter()
                .map(|url| Reference {
                    reference_type: ReferenceType::Web,
                    url: url.to_string(),
                })
                .collect(),
            published: Some(Utc::now()),
            modified: Some(Utc::now()),
            aliases: aliases.map(|a| a.into_iter().map(|s| s.to_string()).collect()),
            database_specific: None,
            enrichment: None,
        }
    }

    #[test]
    fn test_extract_cve_from_id() {
        let cve = ReportAggregator::extract_cve_from_string("CVE-2023-12345");
        assert_eq!(cve, Some("CVE-2023-12345".to_string()));
    }

    #[test]
    fn test_extract_cve_case_insensitive() {
        let cve = ReportAggregator::extract_cve_from_string("cve-2023-12345");
        assert_eq!(cve, Some("CVE-2023-12345".to_string()));
    }

    #[test]
    fn test_extract_cve_from_url() {
        let url = "https://nvd.nist.gov/vuln/detail/CVE-2023-12345";
        let cve = ReportAggregator::extract_cve_from_string(url);
        assert_eq!(cve, Some("CVE-2023-12345".to_string()));
    }

    #[test]
    fn test_extract_cve_from_text() {
        let text = "This affects CVE-2024-99999 in the codebase";
        let cve = ReportAggregator::extract_cve_from_string(text);
        assert_eq!(cve, Some("CVE-2024-99999".to_string()));
    }

    #[test]
    fn test_extract_cve_not_found() {
        let cve = ReportAggregator::extract_cve_from_string("GHSA-1234-5678-90ab");
        assert_eq!(cve, None);
    }

    #[test]
    fn test_extract_cve_ids_from_advisory() {
        let advisory = create_advisory(
            "CVE-2023-12345",
            Some("Test vulnerability"),
            Some(vec!["CVE-2023-54321"]),
            Some(vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-99999"]),
        );

        let cves = ReportAggregator::extract_cve_ids(&advisory);
        assert_eq!(cves.len(), 3);
        assert!(cves.contains("CVE-2023-12345"));
        assert!(cves.contains("CVE-2023-54321"));
        assert!(cves.contains("CVE-2023-99999"));
    }

    #[test]
    fn test_no_duplication_same_id() {
        let advisory = create_advisory("CVE-2023-12345", Some("Test"), None, None);
        let advisories = vec![advisory.clone(), advisory];

        let result = ReportAggregator::aggregate(advisories);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "CVE-2023-12345");
    }

    #[test]
    fn test_merge_with_aliases() {
        let ghsa_advisory = create_advisory(
            "GHSA-1234-5678-90ab",
            Some("GHSA Description"),
            Some(vec!["CVE-2023-12345"]),
            None,
        );

        let nvd_advisory = create_advisory(
            "CVE-2023-12345",
            Some("NVD Description"),
            None,
            Some(vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-12345"]),
        );

        let advisories = vec![ghsa_advisory, nvd_advisory];
        let result = ReportAggregator::aggregate(advisories);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "GHSA-1234-5678-90ab");
        // Should have both aliases
        let aliases = result[0].aliases.as_ref().unwrap();
        assert!(aliases.contains(&"CVE-2023-12345".to_string()));
    }

    #[test]
    fn test_merge_cross_source_cves() {
        // Simulate GHSA source reporting CVE
        let ghsa_advisory = create_advisory(
            "GHSA-xxxx-xxxx-xxxx",
            Some("GHSA Report"),
            Some(vec!["CVE-2023-11111"]),
            None,
        );

        // Simulate NVD source reporting same CVE
        let nvd_advisory = create_advisory("CVE-2023-11111", Some("NVD Report"), None, None);

        // Simulate OSV source reporting same CVE with different ID
        let osv_advisory = create_advisory(
            "OSV-2023-1234",
            Some("OSV Report"),
            Some(vec!["CVE-2023-11111"]),
            None,
        );

        let advisories = vec![ghsa_advisory, nvd_advisory, osv_advisory];
        let result = ReportAggregator::aggregate(advisories);

        // All three should be merged into one
        assert_eq!(
            result.len(),
            1,
            "Expected all three to be merged into one advisory"
        );

        // Should have all three IDs represented
        let aliases = result[0].aliases.as_ref().unwrap();
        assert!(
            aliases.contains(&"CVE-2023-11111".to_string()) || result[0].id == "CVE-2023-11111"
        );
    }

    #[test]
    fn test_merge_references() {
        let advisory1 = Advisory {
            id: "CVE-2023-12345".to_string(),
            summary: None,
            details: None,
            affected: vec![],
            references: vec![Reference {
                reference_type: ReferenceType::Web,
                url: "https://example.com/1".to_string(),
            }],
            published: None,
            modified: None,
            aliases: None,
            database_specific: None,
            enrichment: None,
        };

        let advisory2 = Advisory {
            id: "CVE-2023-12345".to_string(),
            summary: None,
            details: None,
            affected: vec![],
            references: vec![Reference {
                reference_type: ReferenceType::Web,
                url: "https://example.com/2".to_string(),
            }],
            published: None,
            modified: None,
            aliases: None,
            database_specific: None,
            enrichment: None,
        };

        let advisories = vec![advisory1, advisory2];
        let result = ReportAggregator::aggregate(advisories);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].references.len(), 2);
    }

    #[test]
    fn test_merge_details_prefer_longer() {
        let advisory1 = create_advisory("CVE-2023-12345", None, None, None);
        let mut advisory2 = create_advisory("CVE-2023-12345", None, None, None);
        advisory2.details =
            Some("This is a very detailed description of the vulnerability".to_string());

        let advisories = vec![advisory1, advisory2];
        let result = ReportAggregator::aggregate(advisories);

        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0].details,
            Some("This is a very detailed description of the vulnerability".to_string())
        );
    }

    #[test]
    fn test_merge_enrichment_data() {
        let mut advisory1 = create_advisory("CVE-2023-12345", None, None, None);
        advisory1.enrichment = Some(Enrichment {
            epss_score: Some(0.5),
            epss_percentile: Some(0.6),
            epss_date: None,
            is_kev: false,
            kev_due_date: None,
            kev_date_added: None,
            kev_ransomware: None,
            cvss_v3_score: Some(7.5),
            cvss_v3_severity: None,
        });

        let mut advisory2 = create_advisory("CVE-2023-12345", None, None, None);
        advisory2.enrichment = Some(Enrichment {
            epss_score: Some(0.7), // Higher score
            epss_percentile: Some(0.8),
            epss_date: None,
            is_kev: true,
            kev_due_date: None,
            kev_date_added: None,
            kev_ransomware: None,
            cvss_v3_score: Some(6.0), // Lower score
            cvss_v3_severity: None,
        });

        let advisories = vec![advisory1, advisory2];
        let result = ReportAggregator::aggregate(advisories);

        assert_eq!(result.len(), 1);
        let enrichment = result[0].enrichment.as_ref().unwrap();
        // Should prefer higher EPSS score
        assert_eq!(enrichment.epss_score, Some(0.7));
        // Should have KEV flag set to true (OR logic)
        assert!(enrichment.is_kev);
        // Should prefer higher CVSS score
        assert_eq!(enrichment.cvss_v3_score, Some(7.5));
    }

    #[test]
    fn test_different_cves_no_merge() {
        let advisory1 = create_advisory("CVE-2023-11111", Some("Vuln 1"), None, None);
        let advisory2 = create_advisory("CVE-2023-22222", Some("Vuln 2"), None, None);

        let advisories = vec![advisory1, advisory2];
        let result = ReportAggregator::aggregate(advisories);

        // Should remain separate
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_complex_cross_source_scenario() {
        // Simulate real-world scenario with multiple sources reporting same vulnerability

        // GHSA from GitHub source
        let ghsa = create_advisory(
            "GHSA-1234-5678-90ab",
            Some("Improper validation in library X"),
            Some(vec!["CVE-2024-1234"]),
            Some(vec!["https://github.com/advisories/GHSA-1234-5678-90ab"]),
        );

        // NVD from NVD source
        let nvd = create_advisory(
            "CVE-2024-1234",
            Some("Library X improper validation vulnerability"),
            None,
            Some(vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]),
        );

        // OSV from OSV source
        let osv = create_advisory(
            "OSV-2024-5678",
            Some("A validation flaw in X"),
            Some(vec!["CVE-2024-1234", "GHSA-1234-5678-90ab"]),
            None,
        );

        let advisories = vec![ghsa, nvd, osv];
        let result = ReportAggregator::aggregate(advisories);

        // All should be merged into single advisory
        assert_eq!(
            result.len(),
            1,
            "Expected all sources to be merged into one"
        );

        let merged = &result[0];
        let aliases = merged.aliases.as_ref().unwrap();

        // Should have references to all source IDs
        assert!(aliases.len() >= 2, "Expected multiple aliases");
    }

    #[test]
    fn test_cve_extraction_with_extended_numbers() {
        // CVEs can have more than 4 digits in the sequential part
        let cve = ReportAggregator::extract_cve_from_string("CVE-2024-123456789");
        assert_eq!(cve, Some("CVE-2024-123456789".to_string()));
    }

    #[test]
    fn test_empty_advisory_list() {
        let advisories = vec![];
        let result = ReportAggregator::aggregate(advisories);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_single_advisory() {
        let advisory = create_advisory("CVE-2023-12345", Some("Test"), None, None);
        let advisories = vec![advisory];
        let result = ReportAggregator::aggregate(advisories);

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, "CVE-2023-12345");
    }

    #[test]
    fn test_affected_packages_merged() {
        let advisory1 = create_advisory("CVE-2023-12345", None, None, None);
        let mut advisory2 = create_advisory("CVE-2023-12345", None, None, None);

        // Add a different affected package to advisory2
        advisory2.affected.push(Affected {
            package: Package {
                ecosystem: "npm".to_string(),
                name: "another-package".to_string(),
                purl: None,
            },
            ranges: vec![],
            versions: vec![],
            ecosystem_specific: None,
            database_specific: None,
        });

        let advisories = vec![advisory1, advisory2];
        let result = ReportAggregator::aggregate(advisories);

        assert_eq!(result.len(), 1);
        // advisory1 has 1 affected (from create_advisory), advisory2 has 2 affected
        // After merge, total should be 3
        assert_eq!(result[0].affected.len(), 3);
    }

    #[test]
    fn test_no_duplicate_references() {
        let advisory1 = Advisory {
            id: "CVE-2023-12345".to_string(),
            summary: None,
            details: None,
            affected: vec![],
            references: vec![Reference {
                reference_type: ReferenceType::Web,
                url: "https://example.com/advisory".to_string(),
            }],
            published: None,
            modified: None,
            aliases: None,
            database_specific: None,
            enrichment: None,
        };

        let advisory2 = Advisory {
            id: "CVE-2023-12345".to_string(),
            summary: None,
            details: None,
            affected: vec![],
            references: vec![Reference {
                reference_type: ReferenceType::Web,
                url: "https://example.com/advisory".to_string(), // Same URL
            }],
            published: None,
            modified: None,
            aliases: None,
            database_specific: None,
            enrichment: None,
        };

        let advisories = vec![advisory1, advisory2];
        let result = ReportAggregator::aggregate(advisories);

        assert_eq!(result.len(), 1);
        // Should have only one reference, not duplicated
        assert_eq!(result[0].references.len(), 1);
    }

    #[test]
    fn test_aiohttp_real_world_scenario() {
        // Test the real-world case: multiple vulnerabilities for aiohttp package

        let vuln1 = create_advisory(
            "CVE-PYSEC-2023-251",
            Some("HTTP request smuggling via HTTP method"),
            None,
            None,
        );

        let vuln2 = create_advisory(
            "CVE-PYSEC-2023-120",
            Some("Request smuggling via llhttp"),
            None,
            None,
        );

        let vuln3 = create_advisory(
            "CVE-PYSEC-2021-76",
            Some("Open redirect vulnerability"),
            None,
            None,
        );

        let advisories = vec![vuln1, vuln2, vuln3];
        let result = ReportAggregator::aggregate(advisories);

        // Should remain as 3 separate advisories since they are different CVEs
        assert_eq!(result.len(), 3);
    }
}
