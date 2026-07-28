//! Diff-Based Scan — compare current findings against a previous scan baseline.
//! Highlights NEW findings (regressions) and RESOLVED findings (fixes).
//! Usage: kobra -t target --diff-baseline previous_results.json

use crate::types::{Finding, Severity};
use serde_json;
use std::collections::HashSet;
use std::fs;

/// A unique key for a finding (used for diffing)
fn finding_key(f: &Finding) -> String {
    format!(
        "{}|{}|{}|{}",
        f.category,
        f.target,
        f.param.as_deref().unwrap_or(""),
        f.payload.as_deref().unwrap_or("")
    )
}

/// Diff result between two scans
#[derive(Debug)]
pub struct DiffResult {
    /// Findings present in current but NOT in baseline (new/regressions)
    pub new_findings: Vec<Finding>,
    /// Findings present in baseline but NOT in current (resolved/fixed)
    pub resolved: Vec<Finding>,
    /// Findings present in both (unchanged)
    pub unchanged: Vec<Finding>,
}

/// Compare current findings against a baseline
pub fn diff_findings(current: &[Finding], baseline: &[Finding]) -> DiffResult {
    let baseline_keys: HashSet<String> = baseline.iter().map(finding_key).collect();
    let current_keys: HashSet<String> = current.iter().map(finding_key).collect();

    let new_findings: Vec<Finding> = current
        .iter()
        .filter(|f| !baseline_keys.contains(&finding_key(f)))
        .cloned()
        .collect();

    let resolved: Vec<Finding> = baseline
        .iter()
        .filter(|f| !current_keys.contains(&finding_key(f)))
        .cloned()
        .collect();

    let unchanged: Vec<Finding> = current
        .iter()
        .filter(|f| baseline_keys.contains(&finding_key(f)))
        .cloned()
        .collect();

    DiffResult {
        new_findings,
        resolved,
        unchanged,
    }
}

/// Load baseline findings from a JSON file (KOBRA output format)
pub fn load_baseline(path: &str) -> Vec<Finding> {
    match fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => vec![],
    }
}

/// Print diff summary to stdout
pub fn print_diff(result: &DiffResult) {
    println!("\n\x1b[96m╔══════════════════════════════════════╗\x1b[0m");
    println!("\x1b[96m║   📊 DIFF-BASED SCAN RESULTS        ║\x1b[0m");
    println!("\x1b[96m╚══════════════════════════════════════╝\x1b[0m\n");

    if !result.new_findings.is_empty() {
        println!("\x1b[91m🆕 NEW FINDINGS ({}):\x1b[0m", result.new_findings.len());
        for f in &result.new_findings {
            println!(
                "   {} [{}] {} — {}",
                severity_icon(&f.severity),
                f.severity.as_str(),
                f.title,
                f.target
            );
        }
        println!();
    }

    if !result.resolved.is_empty() {
        println!("\x1b[92m✅ RESOLVED ({}):\x1b[0m", result.resolved.len());
        for f in &result.resolved {
            println!(
                "   ✓ [{}] {} — {}",
                f.severity.as_str(),
                f.title,
                f.target
            );
        }
        println!();
    }

    println!(
        "\x1b[93m📋 UNCHANGED: {} findings\x1b[0m",
        result.unchanged.len()
    );
    println!(
        "\x1b[96m📈 SUMMARY: {} new | {} resolved | {} unchanged\x1b[0m\n",
        result.new_findings.len(),
        result.resolved.len(),
        result.unchanged.len()
    );
}

fn severity_icon(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
        Severity::Info => "⚪",
    }
}

/// Generate findings from diff (new findings get a DIFF category marker)
pub fn diff_to_findings(result: &DiffResult) -> Vec<Finding> {
    let mut out = Vec::new();

    for f in &result.new_findings {
        let mut nf = f.clone();
        nf.category = format!("DIFF-NEW/{}", nf.category);
        nf.note = Some(format!(
            "NEW since last scan. {}",
            f.note.as_deref().unwrap_or("")
        ));
        out.push(nf);
    }

    for f in &result.resolved {
        out.push(
            Finding::new(Severity::Info, "DIFF-RESOLVED", &format!("RESOLVED: {}", f.title), &f.target)
                .with_evidence(&format!("Was: [{}] {}", f.severity.as_str(), f.category))
                .with_confidence(95),
        );
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(cat: &str, target: &str) -> Finding {
        Finding::new(Severity::High, cat, "test", target)
    }

    #[test]
    fn diff_detects_new() {
        let baseline = vec![f("XSS", "https://a.com")];
        let current = vec![f("XSS", "https://a.com"), f("SQLi", "https://a.com")];
        let result = diff_findings(&current, &baseline);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.new_findings[0].category, "SQLi");
        assert_eq!(result.unchanged.len(), 1);
        assert_eq!(result.resolved.len(), 0);
    }

    #[test]
    fn diff_detects_resolved() {
        let baseline = vec![f("XSS", "https://a.com"), f("SQLi", "https://a.com")];
        let current = vec![f("XSS", "https://a.com")];
        let result = diff_findings(&current, &baseline);
        assert_eq!(result.resolved.len(), 1);
        assert_eq!(result.resolved[0].category, "SQLi");
    }

    #[test]
    fn diff_empty_baseline() {
        let current = vec![f("XSS", "https://a.com")];
        let result = diff_findings(&current, &[]);
        assert_eq!(result.new_findings.len(), 1);
        assert_eq!(result.resolved.len(), 0);
    }

    #[test]
    fn diff_identical() {
        let a = vec![f("XSS", "https://a.com")];
        let b = vec![f("XSS", "https://a.com")];
        let result = diff_findings(&a, &b);
        assert_eq!(result.new_findings.len(), 0);
        assert_eq!(result.resolved.len(), 0);
        assert_eq!(result.unchanged.len(), 1);
    }

    #[test]
    fn load_nonexistent_baseline() {
        let v = load_baseline("/nonexistent/file.json");
        assert!(v.is_empty());
    }

    #[test]
    fn diff_to_findings_marks_new() {
        let baseline = vec![];
        let current = vec![f("XSS", "https://a.com")];
        let result = diff_findings(&current, &baseline);
        let findings = diff_to_findings(&result);
        assert!(findings[0].category.starts_with("DIFF-NEW/"));
    }
}
