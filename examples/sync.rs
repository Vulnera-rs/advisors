//! Example demonstrating how to sync advisories from all sources.
//!
//! Run with:
//! ```bash
//! REDIS_URL=redis://localhost:6379 cargo run --example sync
//! ```

use std::time::{Duration, Instant};
use tokio::time::timeout;

use vulnera_advisor::{Config, VulnerabilityManager};

/// Timeout for the entire sync operation (20 minutes)
/// GHSA alone can take 10-15 minutes for a full sync (~29k advisories)
const SYNC_TIMEOUT: Duration = Duration::from_secs(1200);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    // Load configuration from environment
    let config = Config::from_env()?;

    // Initialize logging (hold the guard until the end of main!)
    let _guard = vulnera_advisor::logging::init_logging(&config);

    println!("=== Vulnera Advisors Sync Test ===\n");
    println!("Redis URL: {}", config.redis_url);
    println!(
        "GHSA Token: {}",
        if config.ghsa_token.is_some() {
            "✓ configured"
        } else {
            "✗ not set"
        }
    );
    println!(
        "NVD API Key: {}",
        if config.nvd_api_key.is_some() {
            "✓ configured"
        } else {
            "✗ not set (rate limited)"
        }
    );
    println!();

    // Create manager with all sources for comprehensive testing
    let mut builder = VulnerabilityManager::builder()
        .redis_url(&config.redis_url)
        // OSV ecosystems - comprehensive coverage
        .with_osv(vec![
            "npm".to_string(),
            "PyPI".to_string(),
            "crates.io".to_string(),
            "Go".to_string(),
            "Maven".to_string(),
            "RubyGems".to_string(),
            "NuGet".to_string(),
            "Packagist".to_string(),
            "Hex".to_string(),
            "Pub".to_string(),
            "SwiftURL".to_string(),
            "Linux".to_string(),
            "Debian".to_string(),
            "Alpine".to_string(),
            "Rocky Linux".to_string(),
            "AlmaLinux".to_string(),
        ]);

    // Add GHSA if token available
    if let Some(token) = &config.ghsa_token {
        println!("Adding GHSA source...");
        builder = builder.with_ghsa(token.clone());
    }

    // Add NVD (works without API key, just slower)
    println!("Adding NVD source...");
    builder = builder.with_nvd(config.nvd_api_key.clone());

    let manager = builder.build()?;

    // Run health check
    println!("\nRunning health check...");
    match manager.health_check().await {
        Ok(status) => {
            println!(
                "✓ Redis connected: {} (latency: {}ms, {} advisories stored)",
                status.connected, status.latency_ms, status.advisory_count
            );
        }
        Err(e) => {
            eprintln!("✗ Health check failed: {}", e);
            return Err(e.into());
        }
    }

    // Run sync with timeout
    println!("\nStarting sync (timeout: {}s)...", SYNC_TIMEOUT.as_secs());
    println!("Sources:");
    println!("  - OSV: npm, PyPI, crates.io, Go, Maven, RubyGems, NuGet, Packagist,");
    println!("         Hex, Pub, SwiftURL, Linux, Debian, Alpine, Rocky Linux, AlmaLinux");
    println!("  - NVD: National Vulnerability Database");
    if config.ghsa_token.is_some() {
        println!("  - GHSA: GitHub Security Advisories");
    }
    println!();

    let start = Instant::now();

    match timeout(SYNC_TIMEOUT, manager.sync_all()).await {
        Ok(Ok(stats)) => {
            println!(
                "\n✓ Sync completed in {:.1}s",
                start.elapsed().as_secs_f64()
            );
            println!("  Sources attempted: {}", stats.total_sources);
            println!("  Sources successful: {}", stats.successful_sources);
            println!("  Sources failed: {}", stats.failed_sources);
            println!("  Total advisories: {}", stats.total_advisories_synced);
            if !stats.errors.is_empty() {
                println!("  Errors:");
                for (source, error) in &stats.errors {
                    println!("    - {}: {}", source, error);
                }
            }
        }
        Ok(Err(e)) => {
            eprintln!(
                "\n✗ Sync error after {:.1}s: {}",
                start.elapsed().as_secs_f64(),
                e
            );
        }
        Err(_) => {
            eprintln!("\n✗ Sync timed out after {}s", SYNC_TIMEOUT.as_secs());
            eprintln!("  Try running with fewer ecosystems or check network connectivity");
        }
    }

    // Check final stats
    if let Ok(status) = manager.health_check().await {
        println!("\nFinal stats: {} advisories stored", status.advisory_count);
    }

    // Test queries for various ecosystems
    println!("\n=== Testing Queries ===\n");

    let test_packages = [
        ("npm", "lodash"),
        ("npm", "express"),
        ("PyPI", "requests"),
        ("PyPI", "django"),
        ("crates.io", "tokio"),
        ("crates.io", "serde"),
        ("Go", "golang.org/x/crypto"),
        ("Go", "github.com/gin-gonic/gin"),
        ("Maven", "org.apache.logging.log4j:log4j-core"),
        ("RubyGems", "rails"),
        ("NuGet", "Newtonsoft.Json"),
        ("Packagist", "symfony/symfony"),
    ];

    for (ecosystem, package) in test_packages {
        match manager.query(ecosystem, package).await {
            Ok(advisories) => {
                if advisories.is_empty() {
                    println!("  {}/{}: no advisories", ecosystem, package);
                } else {
                    println!(
                        "  {}/{}: {} advisories",
                        ecosystem,
                        package,
                        advisories.len()
                    );
                    if let Some(first) = advisories.first() {
                        println!(
                            "    └─ {}: {}",
                            first.id,
                            first
                                .summary
                                .as_deref()
                                .or(first.details.as_deref())
                                .map(|s| if s.len() > 60 {
                                    format!("{}...", &s[..60])
                                } else {
                                    s.to_string()
                                })
                                .unwrap_or_else(|| "No description".to_string())
                        );
                    }
                }
            }
            Err(e) => {
                println!("  {}/{}: error - {}", ecosystem, package, e);
            }
        }
    }

    println!("\n=== Sync Complete ===");
    Ok(())
}
