//! SARIF Export — Static Analysis Results Interchange Format (v2.1.0)
//! Compatible with GitHub Security tab, VS Code SARIF viewer, Azure DevOps.
//! Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use crate::types::{Finding, Severity};
use serde_json::json;
use std::fs;

/// Convert findings to SARIF v2.1.0 JSON
pub fn to_sarif(findings: &[Finding], engagement: &str) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            json!({
                "id": format!("KOBRA-{}", f.category),
                "name": f.title,
                "shortDescription": { "text": f.title },
                "fullDescription": {
                    "text": format!(
                        "{}\n\nCategory: {}\nConfidence: {}%\n{}",
                        f.title,
                        f.category,
                        f.confidence,
                        f.note.as_deref().unwrap_or("")
                    )
                },
                "defaultConfiguration": {
                    "level": severity_to_sarif_level(&f.severity)
                },
                "properties": {
                    "severity": f.severity.as_str(),
                    "confidence": f.confidence,
                    "tags": [f.category.clone()]
                }
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .enumerate()
        .map(|(i, f)| {
            // v4.0.0 (was v3.3.1 fix): GitHub Code Scanning rejects https:// URIs for SARIF upload. (verified v4.7.0 — still relevant)
            // Always use file:// scheme (SARIF spec compliant) unless the target
            // is explicitly a remote endpoint we cannot resolve locally.
            let uri = if f.target.starts_with("file://") {
                f.target.clone()
            } else if f.target.starts_with("http://") || f.target.starts_with("https://") {
                // Remote target — keep https:// but GitHub will reject.
                // We annotate the location with a placeholder path.
                format!("file://{}", f.target.replace("://", "_"))
            } else {
                // Path-like (e.g. "./src/x.rs" or relative)
                format!("file://{}", f.target)
            };

            let mut result = json!({
                "ruleId": format!("KOBRA-{}", f.category),
                "ruleIndex": i,
                "level": severity_to_sarif_level(&f.severity),
                "message": {
                    "text": format!(
                        "[{}] {} — {}",
                        f.severity.as_str(),
                        f.title,
                        f.evidence.as_deref().unwrap_or("No evidence")
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri
                        }
                    }
                }],
                "properties": {
                    "severity": f.severity.as_str(),
                    "confidence": f.confidence,
                    "category": f.category,
                    "target": f.target
                }
            });

            // Add payload as code snippet if available
            if let Some(payload) = &f.payload {
                result["locations"][0]["physicalLocation"]["region"] = json!({
                    "snippet": { "text": payload }
                });
            }

            result
        })
        .collect();

    // Deduplicate rules by id
    let mut seen_rules = std::collections::HashSet::new();
    let unique_rules: Vec<serde_json::Value> = rules
        .into_iter()
        .filter(|r| {
            let id = r["id"].as_str().unwrap_or("").to_string();
            seen_rules.insert(id)
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "KOBRA",
                    "version": "1.8.0",
                    "informationUri": "https://github.com/shenyo1/kobra",
                    "rules": unique_rules
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": true,
                "commandLine": format!("kobra --engagement {}", engagement)
            }],
            "properties": {
                "engagement": engagement,
                "totalFindings": findings.len(),
                "critical": findings.iter().filter(|f| f.severity == Severity::Critical).count(),
                "high": findings.iter().filter(|f| f.severity == Severity::High).count(),
                "medium": findings.iter().filter(|f| f.severity == Severity::Medium).count(),
                "low": findings.iter().filter(|f| f.severity == Severity::Low).count(),
                "info": findings.iter().filter(|f| f.severity == Severity::Info).count()
            }
        }]
    })
}

fn severity_to_sarif_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical => "error",
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "note",
    }
}

/// Write SARIF report to file
pub fn write(findings: &[Finding], engagement: &str, path: &str) -> std::io::Result<()> {
    let sarif = to_sarif(findings, engagement);
    let pretty = serde_json::to_string_pretty(&sarif).unwrap_or_default();
    fs::write(path, pretty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    fn sample() -> Finding {
        Finding::new(Severity::High, "XSS", "Reflected XSS in search", "https://example.com/search?q=test")
            .with_payload("<script>alert(1)</script>")
            .with_evidence("Payload reflected in response")
            .with_confidence(90)
    }

    #[test]
    fn sarif_valid_structure() {
        let sarif = to_sarif(&[sample()], "test");
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "KOBRA");
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sarif_severity_mapping() {
        assert_eq!(severity_to_sarif_level(&Severity::Critical), "error");
        assert_eq!(severity_to_sarif_level(&Severity::High), "error");
        assert_eq!(severity_to_sarif_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_sarif_level(&Severity::Low), "note");
        assert_eq!(severity_to_sarif_level(&Severity::Info), "note");
    }

    #[test]
    fn sarif_empty_findings() {
        let sarif = to_sarif(&[], "empty");
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 0);
        assert_eq!(sarif["runs"][0]["properties"]["totalFindings"], 0);
    }

    #[test]
    fn sarif_dedup_rules() {
        let f1 = Finding::new(Severity::High, "XSS", "XSS 1", "https://a.com");
        let f2 = Finding::new(Severity::Medium, "XSS", "XSS 2", "https://b.com");
        let sarif = to_sarif(&[f1, f2], "test");
        let rules = sarif["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1); // Same category = 1 rule
    }
}
