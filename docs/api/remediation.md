# Remediation API

The Remediation API provides safe version recommendations when vulnerabilities are detected.

## Types

### UpgradeImpact

Classification of the upgrade's impact based on semantic versioning.

```rust
pub enum UpgradeImpact {
    Patch,  // x.y.Z - Bug fixes only
    Minor,  // x.Y.z - New features, backward compatible
    Major,  // X.y.z - Breaking changes
}
```

### Remediation

A remediation suggestion for a vulnerable package.

```rust
pub struct Remediation {
    pub ecosystem: String,
    pub package: String,
    pub current_version: String,
    pub nearest_safe: Option<String>,    // Minimal upgrade
    pub latest_safe: Option<String>,     // Latest safe version
    pub upgrade_impact: Option<UpgradeImpact>,
    pub vulnerabilities: Vec<String>,    // CVE/GHSA IDs
}
```

## Methods

### suggest_remediation

Get remediation suggestions using advisory data only.

```rust
let remediation = manager.suggest_remediation("npm", "lodash", "4.17.20").await?;

if let Some(nearest) = &remediation.nearest_safe {
    println!("Upgrade to {} ({:?} impact)", nearest, remediation.upgrade_impact);
}
```

### suggest_remediation_with_registry

Enhanced version that fetches all available versions from package registries.

```rust
use vulnera_advisor::PackageRegistry;

let registry = PackageRegistry::new();
let remediation = manager
    .suggest_remediation_with_registry("npm", "lodash", "4.17.20", &registry)
    .await?;
```

## Helper Functions

### classify_upgrade_impact

Classify the impact of upgrading between two versions.

```rust
use vulnera_advisor::classify_upgrade_impact;

let impact = classify_upgrade_impact("1.0.0", "1.0.1"); // Patch
let impact = classify_upgrade_impact("1.0.0", "1.1.0"); // Minor
let impact = classify_upgrade_impact("1.0.0", "2.0.0"); // Major
```

### build_remediation

Build a complete remediation from advisories.

```rust
use vulnera_advisor::build_remediation;

let remediation = build_remediation(
    "npm",
    "lodash",
    "4.17.20",
    &advisories,
    Some(&available_versions),
    |v, events| version_matcher(v, events),
);
```

## JSON Response Format

When serialized, a `Remediation` produces:

```json
{
  "ecosystem": "npm",
  "package": "lodash",
  "current_version": "4.17.20",
  "nearest_safe": "4.17.21",
  "latest_safe": "4.17.21",
  "upgrade_impact": "patch",
  "vulnerabilities": ["CVE-2021-23337", "GHSA-xxxx-xxxx-xxxx"]
}
```

## Upgrade Impact Classification

| Impact | Version Change | Description |
|--------|---------------|-------------|
| `patch` | x.y.**Z** | Bug fixes only |
| `minor` | x.**Y**.z | New features, backward compatible |
| `major` | **X**.y.z | Breaking changes |
