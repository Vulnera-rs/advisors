use crate::models::Advisory;
use std::collections::{HashMap, HashSet};

pub struct ReportAggregator;

impl ReportAggregator {
    pub fn aggregate(advisories: Vec<Advisory>) -> Vec<Advisory> {
        let mut deduplicated: HashMap<String, Advisory> = HashMap::new();
        let mut alias_map: HashMap<String, String> = HashMap::new();

        // First pass: Index all advisories by ID and build alias map
        for advisory in &advisories {
            // If this ID is already an alias for something else, we should know?
            // But we are building the map now.

            if let Some(aliases) = &advisory.aliases {
                for alias in aliases {
                    alias_map.insert(alias.clone(), advisory.id.clone());
                }
            }
        }

        // Second pass: Merge
        for advisory in advisories {
            // Determine the "canonical" ID
            // If this advisory's ID is an alias for another advisory in our set, use that one.
            // But wait, if we have GHSA-1 and CVE-1. GHSA-1 aliases CVE-1.
            // alias_map: CVE-1 -> GHSA-1.
            // When processing CVE-1: canonical = GHSA-1.
            // When processing GHSA-1: canonical = GHSA-1.

            let canonical_id = alias_map
                .get(&advisory.id)
                .cloned()
                .unwrap_or(advisory.id.clone());

            match deduplicated.get_mut(&canonical_id) {
                Some(existing) => {
                    Self::merge(existing, advisory);
                }
                None => {
                    // If we are inserting a record that is actually an alias target (e.g. CVE-1 mapped to GHSA-1),
                    // but we haven't inserted GHSA-1 yet?
                    // The order matters.
                    // If we process CVE-1 first, alias_map says it belongs to GHSA-1.
                    // We insert into deduplicated under "GHSA-1".
                    // But "existing" is empty. So we insert CVE-1 as the base for GHSA-1?
                    // That's fine, we will merge GHSA-1 into it later.
                    // BUT we must ensure the ID is updated to canonical if we do that.

                    let mut new_entry = advisory;
                    new_entry.id = canonical_id.clone();
                    deduplicated.insert(canonical_id, new_entry);
                }
            }
        }

        deduplicated.into_values().collect()
    }

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
        // (Ideally we would dedupe affected packages too, but that's complex)

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
    }
}
