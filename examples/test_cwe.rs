//! Example: Test CWE filtering functionality
//!
//! Run with: cargo run --example test_cwe

use vulnera_advisor::{MatchOptions, Severity};

fn main() {
    println!("=== CWE Filtering Test ===\n");

    // Test 1: Default options (no CWE filter)
    let default_opts = MatchOptions::default();
    println!("1. Default options:");
    println!("   cwe_ids: {:?}", default_opts.cwe_ids);
    println!("   kev_only: {}", default_opts.kev_only);
    println!();

    // Test 2: Filter for XSS vulnerabilities (CWE-79)
    let xss_opts = MatchOptions::with_cwes(vec!["CWE-79".to_string()]);
    println!("2. XSS filter (CWE-79):");
    println!("   cwe_ids: {:?}", xss_opts.cwe_ids);
    println!("   include_enrichment: {}", xss_opts.include_enrichment);
    println!();

    // Test 3: Filter for multiple injection vulnerabilities
    let injection_opts = MatchOptions::with_cwes(vec![
        "CWE-79".to_string(),  // XSS
        "CWE-89".to_string(),  // SQL Injection
        "CWE-78".to_string(),  // OS Command Injection
    ]);
    println!("3. Injection filter (CWE-79, CWE-89, CWE-78):");
    println!("   cwe_ids: {:?}", injection_opts.cwe_ids);
    println!();

    // Test 4: Combined filters (CWE + Severity + KEV)
    let critical_xss = MatchOptions {
        cwe_ids: Some(vec!["CWE-79".to_string()]),
        min_severity: Some(Severity::High),
        kev_only: true,
        include_enrichment: true,
        ..Default::default()
    };
    println!("4. Critical XSS (High severity + KEV):");
    println!("   cwe_ids: {:?}", critical_xss.cwe_ids);
    println!("   min_severity: {:?}", critical_xss.min_severity);
    println!("   kev_only: {}", critical_xss.kev_only);
    println!();

    // Test 5: OWASP Top 10 related CWEs
    let owasp_top10 = MatchOptions::with_cwes(vec![
        "CWE-79".to_string(),   // A03: Injection (XSS)
        "CWE-89".to_string(),   // A03: Injection (SQLi)
        "CWE-287".to_string(),  // A07: Identification and Authentication Failures
        "CWE-352".to_string(),  // A01: Broken Access Control (CSRF)
        "CWE-611".to_string(),  // A05: Security Misconfiguration (XXE)
        "CWE-502".to_string(),  // A08: Software and Data Integrity Failures
    ]);
    println!("5. OWASP Top 10 related CWEs:");
    println!("   cwe_ids: {:?}", owasp_top10.cwe_ids);
    println!();

    println!("=== All tests completed ===");
    println!("\nTo use with VulnerabilityManager:");
    println!("  let manager = VulnerabilityManager::new(config).await?;");
    println!("  let options = MatchOptions::with_cwes(vec![\"CWE-79\".to_string()]);");
    println!("  let xss_vulns = manager.matches_with_options(\"npm\", \"pkg\", \"1.0.0\", &options).await?;");
}
