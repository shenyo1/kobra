use crate::types::Finding;
use std::io::Write;

/// Print findings to stdout (full transparency — nothing hidden) + optionally JSON.
pub fn print_findings(findings: &[Finding], json: bool) {
    if json {
        let j = serde_json::to_string_pretty(findings).unwrap_or_default();
        println!("{}", j);
        return;
    }
    println!("\n{}", "=".repeat(70));
    println!(" KOBRA RESULTS — {} finding(s) shown (full disclosure)", findings.len());
    println!("{}", "=".repeat(70));
    let order = |s: &Finding| match s.severity {
        crate::types::Severity::Critical => 0,
        crate::types::Severity::High => 1,
        crate::types::Severity::Medium => 2,
        crate::types::Severity::Low => 3,
        crate::types::Severity::Info => 4,
    };
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(order);
    for f in &sorted {
        let c = f.severity.color();
        println!(
            "{}{}[{}]{} — {}",
            c, f.severity.as_str(), f.category, "\x1b[0m", f.title
        );
        println!("    target : {}", f.target);
        if let Some(p) = &f.param { println!("    param  : {}", p); }
        if let Some(p) = &f.payload { println!("    payload: {}", p); }
        if let Some(e) = &f.evidence { println!("    evidence: {}", e); }
        if let Some(n) = &f.note { println!("    note   : {}", n); }
        println!("    conf   : {}%", f.confidence);
        println!();
    }
    // Summary counts (also shown, no hiding of low/info).
    let mut counts = std::collections::HashMap::new();
    for f in findings { *counts.entry(f.severity.as_str()).or_insert(0) += 1; }
    println!("{}", "-".repeat(70));
    println!(" SUMMARY: {:?}", counts);
    println!("{}", "=".repeat(70));
}

/// Write findings to a file (markdown or json).
pub fn write_report(findings: &[Finding], path: &str) {
    if let Some(ext) = path.split('.').last() {
        if ext == "json" {
            let _ = std::fs::write(path, serde_json::to_string_pretty(findings).unwrap_or_default());
            return;
        }
    }
    let mut s = String::from("# KOBRA Report\n\n");
    for f in findings {
        s.push_str(&format!("## [{}] {}\n- **Target**: {}\n", f.severity.as_str(), f.title, f.target));
        if let Some(p) = &f.param { s.push_str(&format!("- **Param**: {}\n", p)); }
        if let Some(p) = &f.payload { s.push_str(&format!("- **Payload**: `{}`\n", p)); }
        if let Some(e) = &f.evidence { s.push_str(&format!("- **Evidence**: {}\n", e)); }
        s.push_str(&format!("- **Confidence**: {}%\n\n", f.confidence));
    }
    let _ = std::fs::File::create(path).and_then(|mut fp| fp.write_all(s.as_bytes()));
}
