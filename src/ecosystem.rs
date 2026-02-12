//! Shared ecosystem and package-name normalization helpers.

/// Normalize ecosystem aliases to canonical names used internally.
///
/// Canonical values:
/// - npm
/// - pypi
/// - maven
/// - cargo
/// - go
/// - packagist
/// - rubygems
/// - nuget
pub fn canonicalize_ecosystem(ecosystem: &str) -> Option<&'static str> {
    match ecosystem.trim().to_ascii_lowercase().as_str() {
        "npm" => Some("npm"),
        "pypi" | "python" | "pip" => Some("pypi"),
        "maven" | "java" => Some("maven"),
        "cargo" | "rust" | "crates.io" => Some("cargo"),
        "go" | "golang" => Some("go"),
        "packagist" | "composer" | "php" => Some("packagist"),
        "rubygems" | "ruby" | "gem" | "bundler" => Some("rubygems"),
        "nuget" | "dotnet" | ".net" => Some("nuget"),
        _ => None,
    }
}

/// Normalize a package name for stable matching/indexing.
pub fn normalize_package_name(ecosystem: &str, package_name: &str) -> String {
    let package_name = package_name.trim();
    if package_name.is_empty() {
        return String::new();
    }

    match canonicalize_ecosystem(ecosystem) {
        Some("go") => package_name.to_string(),
        Some(_) => package_name.to_ascii_lowercase(),
        None => package_name.to_string(),
    }
}

/// Normalize ecosystem + package pair used in cache/index keys.
pub fn normalize_package_key(ecosystem: &str, package_name: &str) -> (String, String) {
    let eco = canonicalize_ecosystem(ecosystem)
        .unwrap_or(ecosystem)
        .to_ascii_lowercase();
    let pkg = normalize_package_name(&eco, package_name);
    (eco, pkg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_ecosystem_aliases() {
        assert_eq!(canonicalize_ecosystem("PyPI"), Some("pypi"));
        assert_eq!(canonicalize_ecosystem("crates.io"), Some("cargo"));
        assert_eq!(canonicalize_ecosystem("composer"), Some("packagist"));
        assert_eq!(canonicalize_ecosystem("gem"), Some("rubygems"));
        assert_eq!(canonicalize_ecosystem("unknown"), None);
    }

    #[test]
    fn test_normalize_package_name() {
        assert_eq!(normalize_package_name("npm", " Lodash "), "lodash");
        assert_eq!(normalize_package_name("pypi", "Requests"), "requests");
        assert_eq!(normalize_package_name("go", "golang.org/x/Mod"), "golang.org/x/Mod");
    }
}
