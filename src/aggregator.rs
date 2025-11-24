//! Advisory aggregation and deduplication.
//!
//! This module merges advisories from multiple sources based on their aliases
//! (e.g., a GHSA advisory and its corresponding CVE are merged into one).

use crate::models::{Advisory, Enrichment};
use std::collections::{HashMap, HashSet};

/// Aggregator for merging and deduplicating advisories.
pub struct ReportAggregator;

impl ReportAggregator {
    /// Aggregate advisories by merging duplicates based on aliases.
    ///
    /// When multiple advisories refer to the same vulnerability (via aliases),
    /// they are merged into a single advisory with combined information.
    pub fn aggregate(advisories: Vec<Advisory>) -> Vec<Advisory> {
        let mut deduplicated: HashMap<String, Advisory> = HashMap::new();
        let mut alias_map: HashMap<String, String> = HashMap::new();

        // First pass: Index all advisories by ID and build alias map
        for advisory in &advisories {
            if let Some(aliases) = &advisory.aliases {
                for alias in aliases {
                    alias_map.insert(alias.clone(), advisory.id.clone());
                }
            }
        }

        // Second pass: Merge
        for advisory in advisories {
            // Determine the "canonical" ID
            let canonical_id = alias_map
                .get(&advisory.id)
                .cloned()
                .unwrap_or_else(|| advisory.id.clone());

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
        if let Some(d) = &source.details {
            if target.details.is_none() || d.len() > target.details.as_ref().unwrap().len() {
                target.details = Some(d.clone());
            }
        }

        // Merge summary (prefer longer)
        if let Some(s) = &source.summary {
            if target.summary.is_none() || s.len() > target.summary.as_ref().unwrap().len() {
                target.summary = Some(s.clone());
            }
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
        if let Some(score) = source.epss_score {
            if enrichment.epss_score.map(|s| score > s).unwrap_or(true) {
                enrichment.epss_score = Some(score);
                enrichment.epss_percentile = source.epss_percentile;
                enrichment.epss_date = source.epss_date;
            }
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
        if let Some(score) = source.cvss_v3_score {
            if enrichment.cvss_v3_score.map(|s| score > s).unwrap_or(true) {
                enrichment.cvss_v3_score = Some(score);
                enrichment.cvss_v3_severity = source.cvss_v3_severity;
            }
        }
    }
}
