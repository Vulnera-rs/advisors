//! Package URL (PURL) builder and parser.
//!
//! Provides a convenient way to construct and parse Package URLs
//! following the [PURL specification](https://github.com/package-url/purl-spec).
//!
//! # Example
//!
//! ```rust
//! use vulnera_advisors::Purl;
//!
//! // Simple PURL
//! let purl = Purl::new("npm", "lodash")
//!     .with_version("4.17.20")
//!     .to_string();
//! assert_eq!(purl, "pkg:npm/lodash@4.17.20");
//!
//! // Maven with namespace (groupId)
//! let purl = Purl::new("maven", "spring-core")
//!     .with_namespace("org.springframework")
//!     .with_version("5.3.9")
//!     .to_string();
//! assert_eq!(purl, "pkg:maven/org.springframework/spring-core@5.3.9");
//! ```

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

/// Known valid PURL ecosystem types.
///
/// This list includes all ecosystems supported by OSS Index and other
/// vulnerability databases.
pub const KNOWN_ECOSYSTEMS: &[&str] = &[
    "cargo",     // Rust crates
    "cocoapods", // iOS/macOS CocoaPods
    "composer",  // PHP Composer
    "conan",     // C/C++ Conan
    "conda",     // Conda packages
    "cran",      // R packages
    "deb",       // Debian packages
    "gem",       // Ruby gems
    "generic",   // Generic packages
    "github",    // GitHub repositories
    "golang",    // Go modules
    "hex",       // Erlang/Elixir Hex
    "maven",     // Java Maven
    "npm",       // Node.js npm
    "nuget",     // .NET NuGet
    "pub",       // Dart/Flutter pub
    "pypi",      // Python PyPI
    "rpm",       // RPM packages
    "swift",     // Swift packages
];

/// Ecosystem name mappings from common names to PURL types.
/// Some ecosystems use different names in PURL vs common usage.
const ECOSYSTEM_MAPPINGS: &[(&str, &str)] = &[
    ("crates.io", "cargo"),
    ("PyPI", "pypi"),
    ("RubyGems", "gem"),
    ("Go", "golang"),
    ("Packagist", "composer"),
    ("NuGet", "nuget"),
    ("Hex", "hex"),
    ("Pub", "pub"),
];

/// Error returned when PURL validation fails.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PurlError {
    /// The ecosystem/type is not recognized.
    #[error("Unknown ecosystem '{0}'. Known ecosystems: cargo, npm, pypi, maven, etc.")]
    UnknownEcosystem(String),

    /// The PURL string format is invalid.
    #[error("Invalid PURL format: {0}")]
    InvalidFormat(String),

    /// The package name is empty or invalid.
    #[error("Invalid package name: {0}")]
    InvalidName(String),
}

/// A Package URL builder for creating valid PURL strings.
///
/// PURLs are a standardized way to identify software packages across
/// different ecosystems. This struct provides a builder pattern for
/// constructing valid PURL strings.
///
/// # Format
///
/// ```text
/// pkg:type/namespace/name@version?qualifiers#subpath
/// ```
///
/// - **type** (required): Package ecosystem (npm, maven, pypi, etc.)
/// - **namespace** (optional): Package scope/group (e.g., Maven groupId, npm scope)
/// - **name** (required): Package name
/// - **version** (optional): Specific version
///
/// # Example
///
/// ```rust
/// use vulnera_advisors::Purl;
///
/// // Scoped npm package
/// let purl = Purl::new("npm", "core")
///     .with_namespace("@angular")
///     .with_version("12.0.0")
///     .to_string();
/// assert_eq!(purl, "pkg:npm/%40angular/core@12.0.0");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Purl {
    /// Package type (ecosystem).
    pub purl_type: String,
    /// Optional namespace (e.g., Maven groupId, npm scope).
    pub namespace: Option<String>,
    /// Package name.
    pub name: String,
    /// Optional version.
    pub version: Option<String>,
}

impl Purl {
    /// Create a new PURL with the given ecosystem and package name.
    ///
    /// The ecosystem is automatically mapped to the correct PURL type
    /// (e.g., "crates.io" → "cargo", "PyPI" → "pypi").
    ///
    /// # Arguments
    ///
    /// * `ecosystem` - The package ecosystem (e.g., "npm", "crates.io", "PyPI")
    /// * `name` - The package name
    ///
    /// # Example
    ///
    /// ```rust
    /// use vulnera_advisors::Purl;
    ///
    /// let purl = Purl::new("crates.io", "serde");
    /// assert_eq!(purl.purl_type, "cargo");
    /// ```
    pub fn new(ecosystem: impl Into<String>, name: impl Into<String>) -> Self {
        let eco = ecosystem.into();
        let purl_type = Self::map_ecosystem(&eco);

        Self {
            purl_type,
            namespace: None,
            name: name.into(),
            version: None,
        }
    }

    /// Create a new PURL with validation.
    ///
    /// Returns an error if the ecosystem is not in the known list.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vulnera_advisors::Purl;
    ///
    /// // Valid ecosystem
    /// let purl = Purl::new_validated("npm", "lodash").unwrap();
    ///
    /// // Invalid ecosystem
    /// let result = Purl::new_validated("invalid", "package");
    /// assert!(result.is_err());
    /// ```
    pub fn new_validated(
        ecosystem: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, PurlError> {
        let eco = ecosystem.into();
        let name = name.into();

        if name.is_empty() {
            return Err(PurlError::InvalidName(
                "Package name cannot be empty".into(),
            ));
        }

        let purl_type = Self::map_ecosystem(&eco);

        if !Self::is_known_ecosystem(&purl_type) {
            return Err(PurlError::UnknownEcosystem(eco));
        }

        Ok(Self {
            purl_type,
            namespace: None,
            name,
            version: None,
        })
    }

    /// Check if an ecosystem type is in the known list.
    pub fn is_known_ecosystem(purl_type: &str) -> bool {
        KNOWN_ECOSYSTEMS.contains(&purl_type.to_lowercase().as_str())
    }

    /// Add a namespace (e.g., Maven groupId, npm scope like "@angular").
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Add a version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Map common ecosystem names to PURL types.
    fn map_ecosystem(ecosystem: &str) -> String {
        for (from, to) in ECOSYSTEM_MAPPINGS {
            if ecosystem.eq_ignore_ascii_case(from) {
                return to.to_string();
            }
        }
        ecosystem.to_lowercase()
    }

    /// URL-encode special characters in PURL components.
    fn encode_component(s: &str) -> String {
        s.replace('@', "%40")
            .replace('/', "%2F")
            .replace('?', "%3F")
            .replace('#', "%23")
    }

    /// URL-decode PURL components.
    fn decode_component(s: &str) -> String {
        s.replace("%40", "@")
            .replace("%2F", "/")
            .replace("%3F", "?")
            .replace("%23", "#")
    }

    /// Parse a PURL string into a Purl struct.
    ///
    /// # Example
    ///
    /// ```rust
    /// use vulnera_advisors::Purl;
    ///
    /// let purl = Purl::parse("pkg:npm/lodash@4.17.20").unwrap();
    /// assert_eq!(purl.purl_type, "npm");
    /// assert_eq!(purl.name, "lodash");
    /// assert_eq!(purl.version, Some("4.17.20".to_string()));
    /// ```
    pub fn parse(s: &str) -> Result<Self, PurlError> {
        let s = s
            .strip_prefix("pkg:")
            .ok_or_else(|| PurlError::InvalidFormat("PURL must start with 'pkg:'".into()))?;

        // Split type from rest
        let (purl_type, rest) = s
            .split_once('/')
            .ok_or_else(|| PurlError::InvalidFormat("Missing '/' after type".into()))?;

        if purl_type.is_empty() {
            return Err(PurlError::InvalidFormat("Empty PURL type".into()));
        }

        // Remove qualifiers and subpath for now (everything after ? or #)
        let rest = rest.split('?').next().unwrap_or(rest);
        let rest = rest.split('#').next().unwrap_or(rest);

        // Handle version
        let (path, version) = if let Some((p, v)) = rest.split_once('@') {
            (p, Some(v.to_string()))
        } else {
            (rest, None)
        };

        // Handle namespace
        let (namespace, name) = if let Some((ns, n)) = path.rsplit_once('/') {
            (Some(Self::decode_component(ns)), Self::decode_component(n))
        } else {
            (None, Self::decode_component(path))
        };

        if name.is_empty() {
            return Err(PurlError::InvalidName(
                "Package name cannot be empty".into(),
            ));
        }

        Ok(Self {
            purl_type: purl_type.to_string(),
            namespace,
            name,
            version,
        })
    }

    /// Get the ecosystem name (reverse mapping from PURL type).
    ///
    /// Returns the common ecosystem name for known mappings,
    /// or the PURL type itself if no mapping exists.
    pub fn ecosystem(&self) -> String {
        // Reverse lookup for common mappings
        for (eco, purl) in ECOSYSTEM_MAPPINGS {
            if self.purl_type.eq_ignore_ascii_case(purl) {
                return eco.to_string();
            }
        }
        self.purl_type.clone()
    }

    /// Generate a hash suitable for use as a cache key.
    ///
    /// This creates a deterministic hash of the PURL for use in
    /// Redis cache keys.
    pub fn cache_key(&self) -> String {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    /// Generate a cache key from a PURL string.
    pub fn cache_key_from_str(purl: &str) -> String {
        let mut hasher = DefaultHasher::new();
        purl.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

impl fmt::Display for Purl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "pkg:{}/", self.purl_type)?;

        if let Some(ns) = &self.namespace {
            write!(f, "{}/", Self::encode_component(ns))?;
        }

        write!(f, "{}", self.name)?;

        if let Some(v) = &self.version {
            write!(f, "@{}", v)?;
        }

        Ok(())
    }
}

/// Create a PURL from ecosystem, name, and version.
///
/// This is a convenience function for creating PURLs without importing
/// the `Purl` struct directly.
///
/// # Example
///
/// ```rust
/// use vulnera_advisors::purl::purl;
///
/// let p = purl("npm", "lodash", "4.17.20");
/// assert_eq!(p.to_string(), "pkg:npm/lodash@4.17.20");
/// ```
pub fn purl(ecosystem: &str, name: &str, version: &str) -> Purl {
    Purl::new(ecosystem, name).with_version(version)
}

/// Create multiple PURLs from a list of (ecosystem, name, version) tuples.
///
/// # Example
///
/// ```rust
/// use vulnera_advisors::purl::purls_from_packages;
///
/// let purls = purls_from_packages(&[
///     ("npm", "lodash", "4.17.20"),
///     ("cargo", "serde", "1.0.130"),
/// ]);
/// assert_eq!(purls.len(), 2);
/// ```
pub fn purls_from_packages(packages: &[(&str, &str, &str)]) -> Vec<Purl> {
    packages
        .iter()
        .map(|(eco, name, ver)| Purl::new(*eco, *name).with_version(*ver))
        .collect()
}

/// Convert a list of PURLs to a vector of string references.
///
/// Useful for passing to OSS Index queries.
pub fn purls_to_strings(purls: &[Purl]) -> Vec<String> {
    purls.iter().map(|p| p.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_purl() {
        let purl = Purl::new("npm", "lodash").with_version("4.17.20");
        assert_eq!(purl.to_string(), "pkg:npm/lodash@4.17.20");
    }

    #[test]
    fn test_ecosystem_mapping() {
        let purl = Purl::new("crates.io", "serde").with_version("1.0.130");
        assert_eq!(purl.to_string(), "pkg:cargo/serde@1.0.130");

        let purl = Purl::new("PyPI", "requests");
        assert_eq!(purl.to_string(), "pkg:pypi/requests");

        let purl = Purl::new("RubyGems", "rails");
        assert_eq!(purl.to_string(), "pkg:gem/rails");
    }

    #[test]
    fn test_maven_with_namespace() {
        let purl = Purl::new("maven", "spring-core")
            .with_namespace("org.springframework")
            .with_version("5.3.9");
        assert_eq!(
            purl.to_string(),
            "pkg:maven/org.springframework/spring-core@5.3.9"
        );
    }

    #[test]
    fn test_npm_scoped() {
        let purl = Purl::new("npm", "core")
            .with_namespace("@angular")
            .with_version("12.0.0");
        assert_eq!(purl.to_string(), "pkg:npm/%40angular/core@12.0.0");
    }

    #[test]
    fn test_parse_simple() {
        let purl = Purl::parse("pkg:npm/lodash@4.17.20").unwrap();
        assert_eq!(purl.purl_type, "npm");
        assert_eq!(purl.name, "lodash");
        assert_eq!(purl.version, Some("4.17.20".to_string()));
        assert_eq!(purl.namespace, None);
    }

    #[test]
    fn test_parse_with_namespace() {
        let purl = Purl::parse("pkg:maven/org.springframework/spring-core@5.3.9").unwrap();
        assert_eq!(purl.purl_type, "maven");
        assert_eq!(purl.namespace, Some("org.springframework".to_string()));
        assert_eq!(purl.name, "spring-core");
        assert_eq!(purl.version, Some("5.3.9".to_string()));
    }

    #[test]
    fn test_parse_scoped_npm() {
        let purl = Purl::parse("pkg:npm/%40angular/core@12.0.0").unwrap();
        assert_eq!(purl.namespace, Some("@angular".to_string()));
        assert_eq!(purl.name, "core");
    }

    #[test]
    fn test_roundtrip() {
        let original = "pkg:npm/lodash@4.17.20";
        let purl = Purl::parse(original).unwrap();
        assert_eq!(purl.to_string(), original);

        let original = "pkg:maven/org.springframework/spring-core@5.3.9";
        let purl = Purl::parse(original).unwrap();
        assert_eq!(purl.to_string(), original);
    }

    #[test]
    fn test_validation() {
        // Valid ecosystem
        assert!(Purl::new_validated("npm", "lodash").is_ok());
        assert!(Purl::new_validated("crates.io", "serde").is_ok());
        assert!(Purl::new_validated("cargo", "serde").is_ok());

        // Invalid ecosystem
        assert!(Purl::new_validated("invalid_eco", "package").is_err());

        // Empty name
        assert!(Purl::new_validated("npm", "").is_err());
    }

    #[test]
    fn test_ecosystem_reverse_mapping() {
        let purl = Purl::new("cargo", "serde");
        assert_eq!(purl.ecosystem(), "crates.io");

        let purl = Purl::new("pypi", "requests");
        assert_eq!(purl.ecosystem(), "PyPI");
    }

    #[test]
    fn test_cache_key() {
        let purl1 = Purl::new("npm", "lodash").with_version("4.17.20");
        let purl2 = Purl::new("npm", "lodash").with_version("4.17.20");
        let purl3 = Purl::new("npm", "lodash").with_version("4.17.21");

        assert_eq!(purl1.cache_key(), purl2.cache_key());
        assert_ne!(purl1.cache_key(), purl3.cache_key());
    }

    #[test]
    fn test_purls_from_packages() {
        let purls =
            purls_from_packages(&[("npm", "lodash", "4.17.20"), ("cargo", "serde", "1.0.130")]);

        assert_eq!(purls.len(), 2);
        assert_eq!(purls[0].to_string(), "pkg:npm/lodash@4.17.20");
        assert_eq!(purls[1].to_string(), "pkg:cargo/serde@1.0.130");
    }

    #[test]
    fn test_known_ecosystems() {
        assert!(Purl::is_known_ecosystem("npm"));
        assert!(Purl::is_known_ecosystem("cargo"));
        assert!(Purl::is_known_ecosystem("pypi"));
        assert!(Purl::is_known_ecosystem("NPM")); // Case insensitive
        assert!(!Purl::is_known_ecosystem("unknown"));
    }
}
