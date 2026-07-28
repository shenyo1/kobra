//! Markdown report v2 — professional per-engagement deliverable.
//! Includes: executive summary, findings sorted by severity, CVSS, OWASP/CWE refs, PoC.

use crate::types::{Finding, Severity};
use std::fs;

pub fn severity_emoji(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "🔴",
        Severity::High => "🟠",
        Severity::Medium => "🟡",
        Severity::Low => "🔵",
        Severity::Info => "⚪",
    }
}

pub fn cvss_estimate(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "9.5 (Critical)",
        Severity::High => "7.5 (High)",
        Severity::Medium => "5.0 (Medium)",
        Severity::Low => "3.0 (Low)",
        Severity::Info => "0.0 (Info)",
    }
}

pub fn owasp_ref(category: &str) -> &'static str {
    match category {
        "SQLi" => "A03:2021 – Injection",
        "XSS" => "A03:2021 – Injection (XSS)",
        "AUTH" | "AUTHFLOW" | "EMAIL-ATO" => "A07:2021 – Identification and Authentication Failures",
        "SSRF" | "SSRF_OOB" => "A10:2021 – Server-Side Request Forgery",
        "RCE" | "DESER" => "A03:2021 – Injection / A08:2021 – Software and Data Integrity Failures",
        "TRAVERSAL" => "A01:2021 – Broken Access Control (Path Traversal)",
        "MULTITENANT" => "A01:2021 – Broken Access Control",
        "XXE" => "A05:2021 – Security Misconfiguration",
        "CORS" => "A05:2021 – Security Misconfiguration (CORS)",
        "NOSQL" => "A03:2021 – Injection",
        "SSTI" => "A03:2021 – Injection",
        "JWT" => "A02:2021 – Cryptographic Failures / A07:2021 – Authentication",
        "OAUTH" => "A07:2021 – Authentication Failures",
        "DOM-XSS" => "A03:2021 – Injection (DOM-based XSS)",
        "RACE" => "A04:2021 – Insecure Design",
        "TAKEOVER" => "A05:2021 – Security Misconfiguration (Subdomain Takeover)",
        "EXPOSED" => "A05:2021 – Security Misconfiguration (Sensitive Data Exposure)",
        "SOURCEMAP" => "A05:2021 – Security Misconfiguration (Information Disclosure)",
        "SMUGGLE" | "SMUGGLE_V2" => "A05:2021 – Security Misconfiguration (HTTP Smuggling)",
        "PAYMENT" => "A04:2021 – Insecure Design (Payment Logic)",
        "PROTO" => "A08:2021 – Software and Data Integrity Failures (Prototype Pollution)",
        "GRAPHQL" => "A05:2021 – Security Misconfiguration (GraphQL)",
        "WS" => "A07:2021 – Authentication Failures (WebSocket)",
        "WAF" | "HEADER" => "A05:2021 – Security Misconfiguration",
        "RECON" | "INFO" => "A05:2021 – Security Misconfiguration (Information Disclosure)",
        _ => "—",
    }
}

pub fn cwe_ref(category: &str) -> &'static str {
    match category {
        "SQLi" => "CWE-89",
        "XSS" => "CWE-79",
        "AUTH" | "AUTHFLOW" => "CWE-287",
        "SSRF" => "CWE-918",
        "RCE" => "CWE-78",
        "TRAVERSAL" => "CWE-22",
        "MULTITENANT" => "CWE-639",
        "XXE" => "CWE-611",
        "CORS" => "CWE-942",
        "NOSQL" => "CWE-943",
        "SSTI" => "CWE-1336",
        "JWT" => "CWE-347",
        "OAUTH" => "CWE-601",
        "DOM-XSS" => "CWE-79",
        "RACE" => "CWE-362",
        "TAKEOVER" => "CWE-1188",
        "EXPOSED" => "CWE-200",
        "SOURCEMAP" => "CWE-540",
        "SMUGGLE" | "SMUGGLE_V2" => "CWE-444",
        "PAYMENT" => "CWE-840",
        "PROTO" => "CWE-1321",
        "GRAPHQL" => "CWE-200",
        "WS" => "CWE-1385",
        "DESER" => "CWE-502",
        "EMAIL-ATO" => "CWE-287",
        _ => "CWE-1000",
    }
}

pub fn render(findings: &[Finding], engagement: &str) -> String {
    let mut out = String::new();

    out.push_str(&format!("# 🐍 KOBRA Security Assessment — {}\n\n", engagement));
    out.push_str(&format!("_Generated: {}_\n\n", chrono_like_now()));

    let mut by_sev: std::collections::BTreeMap<&'static str, Vec<&Finding>> = Default::default();
    for f in findings {
        by_sev.entry(f.severity.as_str()).or_default().push(f);
    }

    out.push_str("## 📊 Executive Summary\n\n");
    out.push_str("| Severity | Count |\n|---|---|\n");
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
        let n = by_sev.get(sev).map(|v| v.len()).unwrap_or(0);
        out.push_str(&format!("| {} {} | {} |\n", severity_emoji(match_sev(sev)), sev, n));
    }
    out.push_str(&format!("| **TOTAL** | **{}** |\n\n", findings.len()));

    let real = findings.iter().filter(|f| f.severity >= Severity::High).count();
    out.push_str(&format!(
        "**Action required**: {} high+critical findings need triage.\n\n",
        real
    ));

    out.push_str("## 🎯 Findings (sorted by severity)\n\n");
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by_key(|f| match f.severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    });
    for (i, f) in sorted.iter().enumerate() {
        out.push_str(&format!(
            "### {}. {} {} {}\n\n",
            i + 1,
            severity_emoji(f.severity),
            f.severity.as_str(),
            f.title
        ));
        out.push_str(&format!("- **Category**: `{}`\n", f.category));
        out.push_str(&format!("- **Target**: `{}`\n", f.target));
        out.push_str(&format!("- **CVSS**: {}\n", cvss_estimate(f.severity)));
        out.push_str(&format!("- **OWASP**: {}\n", owasp_ref(&f.category)));
        out.push_str(&format!("- **CWE**: {}\n", cwe_ref(&f.category)));
        out.push_str(&format!("- **Confidence**: {}%\n", f.confidence));
        if let Some(p) = &f.param {
            out.push_str(&format!("- **Parameter**: `{}`\n", p));
        }
        if let Some(p) = &f.payload {
            out.push_str(&format!("- **Payload**:\n```\n{}\n```\n", p));
        }
        if let Some(e) = &f.evidence {
            out.push_str(&format!("- **Evidence**:\n```\n{}\n```\n", e));
        }
        if let Some(n) = &f.note {
            out.push_str(&format!("- **Note**: {}\n", n));
        }
        out.push_str(&format!(
            "- **Reproduction**:\n```bash\ncurl -sk -X {} '{}'\n```\n\n",
            method_for(&f.category),
            f.target
        ));
    }
    out
}

pub fn write(findings: &[Finding], engagement: &str, path: &str) -> std::io::Result<()> {
    let md = render(findings, engagement);
    fs::write(path, md)
}

fn match_sev(s: &str) -> Severity {
    match s {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

fn method_for(category: &str) -> &'static str {
    match category {
        "SQLi" | "RCE" | "NOSQL" | "SSTI" | "XXE" | "DESER" | "RACE" => "POST",
        _ => "GET",
    }
}

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{}s since epoch", dur.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    fn sample() -> Finding {
        Finding {
            severity: Severity::High,
            category: "SQLi".into(),
            title: "Boolean SQLi".into(),
            target: "https://x.com/search?q=test".into(),
            param: Some("q".into()),
            payload: Some("' OR 1=1--".into()),
            evidence: Some("DB error leaked".into()),
            confidence: 90,
            note: Some("Verify manually".into()),
            request: None,
            response: None,
        }
    }

    #[test]
    fn render_has_summary() {
        let md = render(&[sample()], "test-engagement");
        assert!(md.contains("# 🐍 KOBRA Security Assessment"));
        assert!(md.contains("## 📊 Executive Summary"));
        assert!(md.contains("HIGH | 1"));
    }

    #[test]
    fn render_has_owasp_cwe() {
        let md = render(&[sample()], "test");
        assert!(md.contains("A03:2021"));
        assert!(md.contains("CWE-89"));
    }

    #[test]
    fn cvss_mapping() {
        assert_eq!(cvss_estimate(Severity::Critical), "9.5 (Critical)");
        assert_eq!(cvss_estimate(Severity::Info), "0.0 (Info)");
    }

    #[test]
    fn emoji_mapping() {
        assert_eq!(severity_emoji(Severity::Critical), "🔴");
        assert_eq!(severity_emoji(Severity::Info), "⚪");
    }

    #[test]
    fn method_mapping() {
        assert_eq!(method_for("SQLi"), "POST");
        assert_eq!(method_for("XSS"), "GET");
    }
}
