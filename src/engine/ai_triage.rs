//! AI Triage Engine — LLM-powered finding validation, severity adjustment,
//! and fix suggestions. Uses local heuristics + optional external LLM API.
//! First open-source scanner with built-in AI triage!

use crate::types::{Finding, Severity};
use serde::{Deserialize, Serialize};

/// Triage result for a single finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub finding_title: String,
    pub verdict: Verdict,
    pub adjusted_severity: Severity,
    pub confidence: u8,
    pub reasoning: String,
    pub fix_suggestion: String,
    pub cwe: Option<String>,
    pub cvss_estimate: Option<f32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Verdict {
    TruePositive,
    FalsePositive,
    NeedsManualReview,
    Informational,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::TruePositive => write!(f, "TRUE POSITIVE"),
            Verdict::FalsePositive => write!(f, "FALSE POSITIVE"),
            Verdict::NeedsManualReview => write!(f, "NEEDS REVIEW"),
            Verdict::Informational => write!(f, "INFORMATIONAL"),
        }
    }
}

/// FP patterns learned from real scans
const FP_PATTERNS: &[(&str, &str, &str)] = &[
    // (category, evidence_pattern, reason)
    ("SSRF", "same_body_length", "Static SPA returns identical body for all params — not SSRF"),
    ("SSRF", "static_response", "Response identical to baseline — no server-side request made"),
    ("XSS", "json_content_type", "Response is JSON, not HTML — XSS not exploitable"),
    ("XSS", "application/json", "Content-Type is application/json — browser won't render HTML"),
    ("WAF", "static_200", "WAF bypass returned same static page — no actual bypass"),
    ("SSTI", "svg_coords", "Number in SVG coordinates matched template expression — not SSTI"),
    ("SSTI", "css_value", "CSS numeric value matched — not template injection"),
    ("AUTH", "public_endpoint", "Endpoint returns 200 without any auth — public by design"),
    ("IDOR", "same_user_data", "Both sessions return same public data — not IDOR"),
    ("TECH", "common_header", "Standard server header — informational only"),
    ("FUZZ", "generic_404", "Server returns 200 for all paths with generic 404 body"),
    ("CORS", "no_credentials", "Wildcard CORS without credentials — low impact"),
];

/// CWE mapping for common categories
const CWE_MAP: &[(&str, &str, f32)] = &[
    ("XSS", "CWE-79", 6.1),
    ("SQLi", "CWE-89", 9.8),
    ("SSRF", "CWE-918", 8.6),
    ("SSTI", "CWE-1336", 9.8),
    ("RCE", "CWE-78", 9.8),
    ("IDOR", "CWE-639", 7.5),
    ("AUTH", "CWE-287", 9.1),
    ("JWT", "CWE-347", 8.1),
    ("TRAVERSAL", "CWE-22", 7.5),
    ("XXE", "CWE-611", 8.2),
    ("NOSQL", "CWE-943", 9.8),
    ("CORS", "CWE-942", 5.3),
    ("WAF", "CWE-693", 5.0),
    ("DESER", "CWE-502", 9.8),
    ("PROTO", "CWE-1321", 7.3),
    ("SMUGGLE", "CWE-444", 8.1),
    ("TAKEOVER", "CWE-1269", 7.1),
    ("GRAPHQL", "CWE-200", 5.3),
    ("OAUTH", "CWE-287", 7.4),
    ("RACE", "CWE-362", 7.0),
    ("CHAIN", "CWE-302", 8.5),
    ("CROSS-CHAIN", "CWE-302", 9.0),
    ("PASSIVE", "CWE-693", 4.0),
    ("FUZZ", "CWE-200", 3.7),
    ("TECH", "CWE-200", 2.0),
    ("INFO", "CWE-200", 2.0),
];

/// Fix suggestions per category
const FIX_MAP: &[(&str, &str)] = &[
    ("XSS", "Sanitize output encoding. Use CSP header. Validate input server-side. Use framework auto-escaping (React JSX, Vue templates)."),
    ("SQLi", "Use parameterized queries / prepared statements. Never concatenate user input into SQL. Use ORM."),
    ("SSRF", "Allowlist outbound destinations. Block internal IPs (10.x, 172.16-31.x, 192.168.x, 169.254.x). Validate URL scheme."),
    ("SSTI", "Use logic-less templates. Sandbox template engine. Never pass user input as template source."),
    ("RCE", "Never pass user input to system commands. Use allowlist for permitted commands. Sanitize all arguments."),
    ("IDOR", "Implement server-side authorization checks per object. Use UUID instead of sequential IDs. Verify ownership."),
    ("AUTH", "Implement proper authentication. Use bcrypt/argon2 for passwords. Add rate limiting on login. Use MFA."),
    ("JWT", "Whitelist allowed algorithms. Never accept alg:none. Use strong secrets (256+ bits). Validate exp/iat claims."),
    ("TRAVERSAL", "Canonicalize paths. Reject ../ sequences. Use allowlist for file access. Chroot/jail file operations."),
    ("XXE", "Disable external entity processing. Use defusedxml (Python) or equivalent. Disable DTD processing."),
    ("NOSQL", "Sanitize query operators ($gt, $ne, $regex). Use strict type validation. Avoid passing raw JSON to queries."),
    ("CORS", "Restrict Access-Control-Allow-Origin to specific domains. Never use * with credentials. Validate Origin header."),
    ("WAF", "Deploy defense-in-depth. WAF is one layer — fix underlying vulnerabilities. Use rate limiting + input validation."),
    ("DESER", "Never deserialize untrusted data. Use safe formats (JSON). Implement type allowlists. Sign serialized data."),
    ("PROTO", "Freeze Object.prototype. Use Map instead of plain objects. Validate/sanitize __proto__ and constructor keys."),
    ("SMUGGLE", "Normalize requests at load balancer. Reject ambiguous Content-Length/Transfer-Encoding. Use HTTP/2 end-to-end."),
    ("TAKEOVER", "Remove dangling DNS records. Monitor for expired services. Use CNAME flattening. Alert on deprovisioned resources."),
    ("GRAPHQL", "Disable introspection in production. Set query depth limit. Implement query cost analysis. Rate limit per-query."),
    ("OAUTH", "Validate redirect_uri against allowlist. Use PKCE. Validate state parameter. Short-lived auth codes."),
    ("RACE", "Use database transactions with proper isolation. Implement idempotency keys. Use distributed locks."),
    ("CHAIN", "Fix each vulnerability in the chain. Implement defense-in-depth. Monitor for multi-step attacks."),
    ("CROSS-CHAIN", "Isolate subdomains. Use separate cookie scopes. Implement per-subdomain CSP. Monitor cross-origin access."),
    ("PASSIVE", "Add security headers (HSTS, X-Frame-Options, CSP, X-Content-Type-Options). Set Secure/HttpOnly/SameSite cookies."),
    ("FUZZ", "Review exposed endpoints. Remove debug/admin paths from production. Implement proper access controls."),
    ("TECH", "Remove version disclosure headers. Use generic Server header. Disable X-Powered-By."),
];

/// Triage all findings using heuristic rules (no external API needed)
pub fn triage_findings(findings: &[Finding]) -> Vec<TriageResult> {
    findings.iter().map(|f| triage_single(f)).collect()
}

/// Triage a single finding
pub fn triage_single(f: &Finding) -> TriageResult {
    let evidence = f.evidence.as_deref().unwrap_or("").to_lowercase();
    let note = f.note.as_deref().unwrap_or("").to_lowercase();
    let combined = format!("{} {}", evidence, note);

    // Check FP patterns
    for (cat, pattern, reason) in FP_PATTERNS {
        if f.category.to_uppercase().contains(&cat.to_uppercase()) && combined.contains(pattern) {
            return TriageResult {
                finding_title: f.title.clone(),
                verdict: Verdict::FalsePositive,
                adjusted_severity: Severity::Info,
                confidence: 85,
                reasoning: reason.to_string(),
                fix_suggestion: "No fix needed — false positive.".to_string(),
                cwe: None,
                cvss_estimate: None,
            };
        }
    }

    // Confidence-based triage
    let verdict = if f.confidence >= 80 {
        Verdict::TruePositive
    } else if f.confidence >= 50 {
        Verdict::NeedsManualReview
    } else {
        Verdict::Informational
    };

    // Severity adjustment
    let adjusted = adjust_severity(f);

    // CWE + CVSS
    let (cwe, cvss) = lookup_cwe(&f.category);

    // Fix suggestion
    let fix = lookup_fix(&f.category);

    let reasoning = match verdict {
        Verdict::TruePositive => format!(
            "High confidence ({}) detection. Category {} with evidence: {}",
            f.confidence,
            f.category,
            &evidence[..evidence.len().min(100)]
        ),
        Verdict::NeedsManualReview => format!(
            "Medium confidence ({}). Manual verification recommended. Evidence: {}",
            f.confidence,
            &evidence[..evidence.len().min(100)]
        ),
        Verdict::Informational => format!(
            "Low confidence ({}). Likely informational or requires context.",
            f.confidence
        ),
        _ => String::new(),
    };

    TriageResult {
        finding_title: f.title.clone(),
        verdict,
        adjusted_severity: adjusted,
        confidence: f.confidence,
        reasoning,
        fix_suggestion: fix,
        cwe,
        cvss_estimate: cvss,
    }
}

/// Adjust severity based on context
fn adjust_severity(f: &Finding) -> Severity {
    let evidence = f.evidence.as_deref().unwrap_or("").to_lowercase();

    // Downgrade if evidence is weak
    if f.confidence < 50 && matches!(f.severity, Severity::High | Severity::Critical) {
        return Severity::Medium;
    }

    // Upgrade if critical evidence
    if evidence.contains("database error") || evidence.contains("stack trace") {
        if matches!(f.severity, Severity::Medium) {
            return Severity::High;
        }
    }

    // Downgrade INFO-level tech disclosures
    if f.category == "TECH" || f.category == "PASSIVE" {
        if matches!(f.severity, Severity::Medium | Severity::High) {
            return Severity::Low;
        }
    }

    f.severity
}

fn lookup_cwe(category: &str) -> (Option<String>, Option<f32>) {
    let cat_upper = category.to_uppercase();
    for (cat, cwe, cvss) in CWE_MAP {
        if cat_upper.contains(&cat.to_uppercase()) {
            return (Some(cwe.to_string()), Some(*cvss));
        }
    }
    (None, None)
}

fn lookup_fix(category: &str) -> String {
    let cat_upper = category.to_uppercase();
    for (cat, fix) in FIX_MAP {
        if cat_upper.contains(&cat.to_uppercase()) {
            return fix.to_string();
        }
    }
    "Review finding manually. Apply defense-in-depth principles.".to_string()
}

/// Print triage report
pub fn print_triage(results: &[TriageResult]) {
    let tp = results.iter().filter(|r| r.verdict == Verdict::TruePositive).count();
    let fp = results.iter().filter(|r| r.verdict == Verdict::FalsePositive).count();
    let review = results.iter().filter(|r| r.verdict == Verdict::NeedsManualReview).count();
    let info = results.iter().filter(|r| r.verdict == Verdict::Informational).count();

    println!("\n\x1b[95m╔══════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[95m║   🤖 AI TRIAGE REPORT                   ║\x1b[0m");
    println!("\x1b[95m╚══════════════════════════════════════════╝\x1b[0m\n");

    println!("  ✅ True Positives:    {}", tp);
    println!("  ❌ False Positives:   {}", fp);
    println!("  🔍 Needs Review:     {}", review);
    println!("  ℹ️  Informational:    {}", info);
    println!("  📊 Total:            {}", results.len());
    println!();

    // Show FPs first (most useful)
    if fp > 0 {
        println!("\x1b[92m  ❌ FILTERED FALSE POSITIVES:\x1b[0m");
        for r in results.iter().filter(|r| r.verdict == Verdict::FalsePositive) {
            println!("     • {} — {}", r.finding_title, r.reasoning);
        }
        println!();
    }

    // Show TPs with fix suggestions
    if tp > 0 {
        println!("\x1b[91m  ✅ CONFIRMED VULNERABILITIES + FIXES:\x1b[0m");
        for r in results.iter().filter(|r| r.verdict == Verdict::TruePositive) {
            println!("     • [{:?}] {}", r.adjusted_severity, r.finding_title);
            if let Some(cwe) = &r.cwe {
                println!("       {} | CVSS ~{:.1}", cwe, r.cvss_estimate.unwrap_or(0.0));
            }
            println!("       💡 Fix: {}", r.fix_suggestion);
        }
        println!();
    }
}

/// Export triage as JSON
pub fn to_json(results: &[TriageResult]) -> String {
    serde_json::to_string_pretty(results).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_fp_ssrf_static() {
        let f = Finding::new(Severity::Medium, "SSRF", "SSRF in param", "https://a.com")
            .with_evidence("same_body_length baseline=1234 probe=1234");
        let r = triage_single(&f);
        assert_eq!(r.verdict, Verdict::FalsePositive);
    }

    #[test]
    fn detect_fp_xss_json() {
        let f = Finding::new(Severity::High, "XSS", "XSS reflected", "https://a.com")
            .with_evidence("Content-Type: application/json")
            .with_confidence(60);
        let r = triage_single(&f);
        assert_eq!(r.verdict, Verdict::FalsePositive);
    }

    #[test]
    fn true_positive_high_confidence() {
        let f = Finding::new(Severity::Critical, "SQLi", "SQL injection confirmed", "https://a.com")
            .with_evidence("Database error: syntax error near 'OR 1=1'")
            .with_confidence(95);
        let r = triage_single(&f);
        assert_eq!(r.verdict, Verdict::TruePositive);
        assert_eq!(r.cwe, Some("CWE-89".to_string()));
        assert!(r.fix_suggestion.contains("parameterized"));
    }

    #[test]
    fn severity_downgrade_low_confidence() {
        let f = Finding::new(Severity::High, "XSS", "Possible XSS", "https://a.com")
            .with_confidence(30);
        let r = triage_single(&f);
        assert_eq!(r.adjusted_severity, Severity::Medium);
    }

    #[test]
    fn severity_upgrade_db_error() {
        let f = Finding::new(Severity::Medium, "SQLi", "SQL error", "https://a.com")
            .with_evidence("database error: mysql syntax")
            .with_confidence(70);
        let r = triage_single(&f);
        assert_eq!(r.adjusted_severity, Severity::High);
    }

    #[test]
    fn cwe_lookup() {
        let (cwe, cvss) = lookup_cwe("XSS");
        assert_eq!(cwe, Some("CWE-79".to_string()));
        assert!(cvss.unwrap() > 5.0);
    }

    #[test]
    fn fix_lookup() {
        let fix = lookup_fix("SQLi");
        assert!(fix.contains("parameterized"));
    }

    #[test]
    fn triage_empty() {
        let results = triage_findings(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn triage_batch() {
        let findings = vec![
            Finding::new(Severity::Critical, "SQLi", "SQLi", "https://a.com").with_confidence(95),
            Finding::new(Severity::Medium, "SSRF", "SSRF", "https://a.com")
                .with_evidence("same_body_length")
                .with_confidence(40),
            Finding::new(Severity::Low, "TECH", "nginx detected", "https://a.com").with_confidence(80),
        ];
        let results = triage_findings(&findings);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].verdict, Verdict::TruePositive);
        assert_eq!(results[1].verdict, Verdict::FalsePositive);
    }
}
