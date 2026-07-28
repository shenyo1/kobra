//! Output Resilience — incremental write per module completion.
//! Writes findings to JSON Lines (.jsonl) as each module finishes.
//! If KOBRA crashes or gets killed, partial results are preserved.

use crate::types::Finding;
use std::fs;
use std::io::Write;

/// Write a finding incrementally to a JSON Lines file.
/// Each line is a complete JSON Finding object.
/// File is opened/closed per write (safe for concurrent access).
pub fn append_finding(path: &str, f: &Finding) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let json = serde_json::to_string(f).unwrap_or_default();
    writeln!(file, "{}", json)?;
    Ok(())
}

/// Read all findings from a JSON Lines file.
pub fn read_findings(path: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            if let Ok(f) = serde_json::from_str::<Finding>(line) {
                out.push(f);
            }
        }
    }
    out
}

/// Write multiple findings at once (for module completion).
pub fn append_findings(path: &str, findings: &[Finding]) -> std::io::Result<()> {
    for f in findings {
        append_finding(path, f)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;
    #[test]
    fn append_and_read() {
        let path = "/tmp/kobra_resilience_test.jsonl";
        let _ = fs::remove_file(path);
        let f1 = Finding::new(Severity::High, "TEST", "Test Finding", "https://x.com/");
        append_finding(path, &f1).unwrap();
        let f2 = Finding::new(Severity::Low, "TEST2", "Another", "https://y.com/");
        append_finding(path, &f2).unwrap();
        let loaded = read_findings(path);
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].severity, Severity::High);
        fs::remove_file(path).ok();
    }
}
