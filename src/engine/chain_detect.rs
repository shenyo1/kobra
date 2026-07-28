//! Chain Detection — cross-module correlation engine.
//! Mendeteksi chains: XSS + Authflow = ATO, SSRF + RCE = RCE via SSRF, etc.
//! Dibutuhkan hasil dari ALL module scan, lalu di-post-process.

use crate::types::{Finding, Severity};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AttackChain {
    pub name: String,
    pub severity: Severity,
    pub steps: Vec<String>,
    pub findings: Vec<Finding>,
    pub description: String,
    pub confidence: u8,
}

/// Post-process all findings and detect attack chains.
pub fn detect_chains(all: &[Finding]) -> Vec<AttackChain> {
    let mut chains = Vec::new();

    let by_cat: HashMap<&str, Vec<&Finding>> = all.iter().fold(HashMap::new(), |mut acc, f| {
        acc.entry(f.category.as_str()).or_default().push(f);
        acc
    });

    // Chain 1: XSS + Authflow = ATO (session hijack via XSS + auth bypass)
    let has_xss = by_cat.contains_key("XSS");
    let has_authflow = by_cat.contains_key("AUTH-FLOW") || by_cat.contains_key("AUTH");
    if has_xss && has_authflow {
        let xss_findings: Vec<Finding> = by_cat.get("XSS").unwrap().iter()
            .filter(|f| f.severity >= Severity::Medium)
            .map(|f| (*f).clone()).collect();
        let auth_findings: Vec<Finding> = by_cat.get("AUTH-FLOW").or_else(|| by_cat.get("AUTH"))
            .unwrap().iter()
            .map(|f| (*f).clone()).collect();
        let mut f = xss_findings.clone();
        f.extend(auth_findings);
        chains.push(AttackChain {
            name: "XSS → ATO Chain".to_string(),
            severity: Severity::Critical,
            steps: vec![
                "XSS on target allows session token theft".to_string(),
                "Authflow bypass allows account takeover".to_string(),
                "Combined: XSS steals session → Authflow bypasses reset → Full ATO".to_string(),
            ],
            findings: f,
            description: "XSS vulnerability combined with auth flow bypass enables full account takeover without user interaction.".to_string(),
            confidence: 85,
        });
    }

    // Chain 2: SSRF + RCE = RCE via SSRF (SSRF to internal service + RCE)
    let has_ssrf = by_cat.contains_key("SSRF");
    let has_rce = by_cat.contains_key("RCE");
    if has_ssrf && has_rce {
        let ssrf_f: Vec<Finding> = by_cat.get("SSRF").unwrap().iter()
            .filter(|f| f.severity >= Severity::Medium)
            .map(|f| (*f).clone()).collect();
        let rce_f: Vec<Finding> = by_cat.get("RCE").unwrap().iter()
            .filter(|f| f.severity >= Severity::Medium)
            .map(|f| (*f).clone()).collect();
        let mut f = ssrf_f.clone();
        f.extend(rce_f);
        chains.push(AttackChain {
            name: "SSRF → RCE Chain".to_string(),
            severity: Severity::Critical,
            steps: vec![
                "SSRF allows access to internal services".to_string(),
                "Internal service has RCE vulnerability".to_string(),
                "Combined: External attacker reaches internal service via SSRF → RCE".to_string(),
            ],
            findings: f,
            description: "SSRF to internal network + RCE on internal service = remote code execution from external.".to_string(),
            confidence: 75,
        });
    }

    // Chain 3: JWT bypass + IDOR = Full Account Takeover
    let has_jwt = by_cat.contains_key("JWT");
    let has_idor = by_cat.contains_key("IDOR");
    if has_jwt && has_idor {
        chains.push(AttackChain {
            name: "JWT → IDOR Chain".to_string(),
            severity: Severity::High,
            steps: vec![
                "JWT bypass allows impersonation".to_string(),
                "IDOR allows accessing other users' data".to_string(),
                "Combined: Impersonate any user + access their data".to_string(),
            ],
            findings: vec![],
            description: "JWT authentication bypass combined with IDOR on user data endpoints.".to_string(),
            confidence: 70,
        });
    }

    chains
}
