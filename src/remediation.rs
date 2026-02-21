//! Safe version remediation analysis.
//!
//! This module provides functionality to suggest safe versions when vulnerabilities
//! are detected, including the nearest safe version (minimal upgrade) and the
//! latest safe version, along with upgrade impact classification.

use crate::models::{Advisory, Affected, Event, RangeType};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Upgrade impact classification based on semantic versioning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpgradeImpact {
    /// Patch version change (x.y.Z) - bug fixes only (e.g., 1.0.0 -> 1.0.1).
    Patch,
    /// Minor version change (x.Y.z) - new features, backward compatible   (e.g., 1.0.0 -> 1.1.0).
    Minor,
    /// Major version change (X.y.z) - breaking changes (e.g., 1.0.0 -> 2.0.0).
    Major,
}

impl std::fmt::Display for UpgradeImpact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Patch => write!(f, "patch"),
            Self::Minor => write!(f, "minor"),
            Self::Major => write!(f, "major"),
        }
    }
}

/// Remediation suggestion for a vulnerable package.
///
/// Contains information about safe versions the user can upgrade to
/// in order to resolve vulnerabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Remediation {
    /// Package ecosystem (e.g., "npm", "pypi").
    pub ecosystem: String,
    /// Package name.
    pub package: String,
    /// Current vulnerable version.
    pub current_version: String,
    /// Nearest safe version (minimal upgrade from current).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nearest_safe: Option<String>,
    /// Latest safe version available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_safe: Option<String>,
    /// Impact classification of upgrading to nearest_safe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_impact: Option<UpgradeImpact>,
    /// List of vulnerability IDs affecting the current version.
    pub vulnerabilities: Vec<String>,
}

impl Remediation {
    /// Create a new remediation with basic information.
    pub fn new(
        ecosystem: impl Into<String>,
        package: impl Into<String>,
        current_version: impl Into<String>,
    ) -> Self {
        Self {
            ecosystem: ecosystem.into(),
            package: package.into(),
            current_version: current_version.into(),
            nearest_safe: None,
            latest_safe: None,
            upgrade_impact: None,
            vulnerabilities: Vec::new(),
        }
    }

    /// Add a vulnerability ID to the list.
    pub fn add_vulnerability(&mut self, id: impl Into<String>) {
        self.vulnerabilities.push(id.into());
    }

    /// Set the nearest safe version and compute upgrade impact.
    pub fn set_nearest_safe(&mut self, version: impl Into<String>) {
        let version = version.into();
        self.upgrade_impact = classify_upgrade_impact(&self.current_version, &version);
        self.nearest_safe = Some(version);
    }

    /// Set the latest safe version.
    pub fn set_latest_safe(&mut self, version: impl Into<String>) {
        self.latest_safe = Some(version.into());
    }
}

/// Extract all fixed versions from advisories for a specific package.
///
/// Scans the advisory's affected packages and extracts versions from
/// `Event::Fixed` entries in the version ranges.
pub fn extract_fixed_versions(
    advisories: &[Advisory],
    ecosystem: &str,
    package: &str,
) -> Vec<String> {
    let mut fixed_versions = Vec::new();
    let _ecosystem_lower = ecosystem.to_lowercase();

    for advisory in advisories {
        for affected in &advisory.affected {
            if !matches_package(affected, ecosystem, package) {
                continue;
            }

            for range in &affected.ranges {
                // Only extract from Semver and Ecosystem ranges
                if matches!(range.range_type, RangeType::Git) {
                    continue;
                }

                for event in &range.events {
                    if let Event::Fixed(version) = event
                        && !fixed_versions.contains(version)
                    {
                        fixed_versions.push(version.clone());
                    }
                }
            }
        }
    }

    fixed_versions
}

/// Find the nearest safe version that is greater than or equal to the current version.
///
/// Returns the minimum version from `candidates` that is >= `current`.
pub fn find_nearest_safe(current: &str, candidates: &[String]) -> Option<String> {
    let current_parsed = parse_version(current)?;

    let mut valid: Vec<_> = candidates
        .iter()
        .filter_map(|v| {
            let parsed = parse_version(v)?;
            if compare_versions(&parsed, &current_parsed) != Ordering::Less {
                Some((v.clone(), parsed))
            } else {
                None
            }
        })
        .collect();

    // Sort by version and pick the smallest
    valid.sort_by(|a, b| compare_versions(&a.1, &b.1));
    valid.first().map(|(v, _)| v.clone())
}

/// Find the latest (highest) safe version from candidates.
pub fn find_latest_safe(candidates: &[String]) -> Option<String> {
    let mut parsed: Vec<_> = candidates
        .iter()
        .filter_map(|v| {
            let parsed = parse_version(v)?;
            Some((v.clone(), parsed))
        })
        .collect();

    parsed.sort_by(|a, b| compare_versions(&b.1, &a.1)); // Descending
    parsed.first().map(|(v, _)| v.clone())
}

/// Classify the upgrade impact between two versions.
///
/// Uses semantic versioning rules:
/// - Major: X changes (breaking changes)
/// - Minor: Y changes (new features)
/// - Patch: Z changes (bug fixes)
pub fn classify_upgrade_impact(current: &str, target: &str) -> Option<UpgradeImpact> {
    let current_parts = parse_version(current)?;
    let target_parts = parse_version(target)?;

    let current_major = current_parts.first().copied().unwrap_or(0);
    let current_minor = current_parts.get(1).copied().unwrap_or(0);

    let target_major = target_parts.first().copied().unwrap_or(0);
    let target_minor = target_parts.get(1).copied().unwrap_or(0);

    if target_major != current_major {
        Some(UpgradeImpact::Major)
    } else if target_minor != current_minor {
        Some(UpgradeImpact::Minor)
    } else {
        Some(UpgradeImpact::Patch)
    }
}

/// Filter versions to only include those not affected by any advisory.
///
/// A version is considered safe if it does not match any affected range
/// in the provided advisories.
pub fn filter_safe_versions(
    all_versions: &[String],
    advisories: &[Advisory],
    ecosystem: &str,
    package: &str,
    version_matcher: impl Fn(&str, &[Event]) -> bool,
) -> Vec<String> {
    all_versions
        .iter()
        .filter(|version| {
            !advisories.iter().any(|advisory| {
                advisory.affected.iter().any(|affected| {
                    if !matches_package(affected, ecosystem, package) {
                        return false;
                    }

                    // Check explicit versions
                    if affected.versions.contains(version) {
                        return true;
                    }

                    // Check ranges
                    affected.ranges.iter().any(|range| {
                        matches!(range.range_type, RangeType::Semver | RangeType::Ecosystem)
                            && version_matcher(version, &range.events)
                    })
                })
            })
        })
        .cloned()
        .collect()
}

/// Build a complete remediation suggestion from advisories.
pub fn build_remediation(
    ecosystem: &str,
    package: &str,
    current_version: &str,
    advisories: &[Advisory],
    available_versions: Option<&[String]>,
    version_matcher: impl Fn(&str, &[Event]) -> bool,
) -> Remediation {
    let mut remediation = Remediation::new(ecosystem, package, current_version);

    // Add vulnerability IDs
    for advisory in advisories {
        remediation.add_vulnerability(&advisory.id);
    }

    if advisories.is_empty() {
        return remediation;
    }

    // Get fixed versions from advisories
    let mut fixed_versions = extract_fixed_versions(advisories, ecosystem, package);

    // If we have available versions, filter to only safe ones
    if let Some(available) = available_versions {
        let safe_versions =
            filter_safe_versions(available, advisories, ecosystem, package, version_matcher);
        // Merge with fixed versions (fixed versions are definitely safe)
        for v in safe_versions {
            if !fixed_versions.contains(&v) {
                fixed_versions.push(v);
            }
        }
    }

    // Find nearest and latest safe versions
    if let Some(nearest) = find_nearest_safe(current_version, &fixed_versions) {
        remediation.set_nearest_safe(nearest);
    }

    if let Some(latest) = find_latest_safe(&fixed_versions) {
        remediation.set_latest_safe(latest);
    }

    remediation
}

// === Internal helpers ===

/// Check if an affected entry matches the given ecosystem and package.
fn matches_package(affected: &Affected, ecosystem: &str, package: &str) -> bool {
    let affected_eco = affected.package.ecosystem.to_lowercase();
    let target_eco = ecosystem.to_lowercase();
    affected_eco == target_eco && affected.package.name == package
}

/// Parse a version string into numeric components.
fn parse_version(version: &str) -> Option<Vec<u64>> {
    let mut parts = Vec::new();
    for segment in version.split(|c: char| !c.is_ascii_digit()) {
        if segment.is_empty() {
            continue;
        }
        if let Ok(num) = segment.parse::<u64>() {
            parts.push(num);
        }
    }
    if parts.is_empty() { None } else { Some(parts) }
}

/// Compare two parsed version vectors.
fn compare_versions(a: &[u64], b: &[u64]) -> Ordering {
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let ai = a.get(i).copied().unwrap_or(0);
        let bi = b.get(i).copied().unwrap_or(0);
        match ai.cmp(&bi) {
            Ordering::Equal => continue,
            ord => return ord,
        }
    }
    Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Package, Range};

    fn create_test_advisory(
        id: &str,
        package: &str,
        ecosystem: &str,
        events: Vec<Event>,
    ) -> Advisory {
        Advisory {
            id: id.to_string(),
            summary: Some("Test vulnerability".to_string()),
            details: None,
            affected: vec![Affected {
                package: Package {
                    ecosystem: ecosystem.to_string(),
                    name: package.to_string(),
                    purl: None,
                },
                ranges: vec![Range {
                    range_type: RangeType::Semver,
                    events,
                    repo: None,
                }],
                versions: vec![],
                ecosystem_specific: None,
                database_specific: None,
            }],
            references: vec![],
            published: None,
            modified: None,
            aliases: None,
            database_specific: None,
            enrichment: None,
        }
    }

    #[test]
    fn test_classify_patch_upgrade() {
        assert_eq!(
            classify_upgrade_impact("1.0.0", "1.0.1"),
            Some(UpgradeImpact::Patch)
        );
        assert_eq!(
            classify_upgrade_impact("2.5.3", "2.5.10"),
            Some(UpgradeImpact::Patch)
        );
    }

    #[test]
    fn test_classify_minor_upgrade() {
        assert_eq!(
            classify_upgrade_impact("1.0.0", "1.1.0"),
            Some(UpgradeImpact::Minor)
        );
        assert_eq!(
            classify_upgrade_impact("1.0.5", "1.2.0"),
            Some(UpgradeImpact::Minor)
        );
    }

    #[test]
    fn test_classify_major_upgrade() {
        assert_eq!(
            classify_upgrade_impact("1.0.0", "2.0.0"),
            Some(UpgradeImpact::Major)
        );
        assert_eq!(
            classify_upgrade_impact("1.5.3", "3.0.0"),
            Some(UpgradeImpact::Major)
        );
    }

    #[test]
    fn test_find_nearest_safe_exact() {
        let candidates = vec![
            "1.0.0".to_string(),
            "1.0.5".to_string(),
            "1.1.0".to_string(),
            "2.0.0".to_string(),
        ];

        // Should find 1.0.5 as nearest >= 1.0.3
        assert_eq!(
            find_nearest_safe("1.0.3", &candidates),
            Some("1.0.5".to_string())
        );

        // Should find exact match
        assert_eq!(
            find_nearest_safe("1.0.0", &candidates),
            Some("1.0.0".to_string())
        );
    }

    #[test]
    fn test_find_nearest_safe_none() {
        let candidates = vec!["1.0.0".to_string()];

        // Current is higher than all candidates
        assert_eq!(find_nearest_safe("2.0.0", &candidates), None);
    }

    #[test]
    fn test_find_latest_safe() {
        let candidates = vec![
            "1.0.0".to_string(),
            "2.5.0".to_string(),
            "1.5.0".to_string(),
        ];

        assert_eq!(find_latest_safe(&candidates), Some("2.5.0".to_string()));
    }

    #[test]
    fn test_extract_fixed_versions() {
        let advisories = vec![
            create_test_advisory(
                "CVE-2021-12345",
                "lodash",
                "npm",
                vec![
                    Event::Introduced("0".to_string()),
                    Event::Fixed("4.17.21".to_string()),
                ],
            ),
            create_test_advisory(
                "CVE-2020-54321",
                "lodash",
                "npm",
                vec![
                    Event::Introduced("0".to_string()),
                    Event::Fixed("4.17.20".to_string()),
                ],
            ),
        ];

        let fixed = extract_fixed_versions(&advisories, "npm", "lodash");
        assert!(fixed.contains(&"4.17.21".to_string()));
        assert!(fixed.contains(&"4.17.20".to_string()));
    }

    #[test]
    fn test_build_remediation_with_fixed_versions() {
        let advisories = vec![create_test_advisory(
            "CVE-2021-12345",
            "lodash",
            "npm",
            vec![
                Event::Introduced("0".to_string()),
                Event::Fixed("4.17.21".to_string()),
            ],
        )];

        let remediation = build_remediation(
            "npm",
            "lodash",
            "4.17.20",
            &advisories,
            None,
            |_, _| false, // Not used when no available_versions
        );

        assert_eq!(remediation.nearest_safe, Some("4.17.21".to_string()));
        assert_eq!(remediation.latest_safe, Some("4.17.21".to_string()));
        assert_eq!(remediation.upgrade_impact, Some(UpgradeImpact::Patch));
        assert_eq!(remediation.vulnerabilities, vec!["CVE-2021-12345"]);
    }

    #[test]
    fn test_upgrade_impact_display() {
        assert_eq!(UpgradeImpact::Patch.to_string(), "patch");
        assert_eq!(UpgradeImpact::Minor.to_string(), "minor");
        assert_eq!(UpgradeImpact::Major.to_string(), "major");
    }

    #[test]
    fn test_parse_complex_version() {
        // Should handle versions like "1.2.3-beta.1"
        assert_eq!(parse_version("1.2.3-beta.1"), Some(vec![1, 2, 3, 1]));
        assert_eq!(parse_version("2.0.0-rc.2"), Some(vec![2, 0, 0, 2]));
    }
}
