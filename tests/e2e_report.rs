// Integration test - calls render functions directly
use kobra::types::{Finding, Severity};

#[test]
fn e2e_poc_generation() {
    let f = Finding {
        severity: Severity::Critical,
        category: "TAKEOVER".into(),
        title: "Subdomain takeover subdomain.target.com".into(),
        target: "https://sub.target.com/".into(),
        param: None,
        payload: None,
        evidence: Some("GH Pages 404".into()),
        confidence: 95,
        note: Some("Claim subdomain".into()),
        request: None,
        response: None,
    };
    let s = kobra::report::poc::bash_script(&[f], "e2e-test");
    assert!(s.contains("KOBRA PoC bundle"));
    assert!(s.contains("Engagement: e2e-test"));
    assert!(s.contains("curl -sk"));
    assert!(s.contains("sub.target.com"));
}

#[test]
fn e2e_markdown_report() {
    let f = Finding {
        severity: Severity::High,
        category: "SQLi".into(),
        title: "Boolean SQLi at /search".into(),
        target: "https://x.com/search?q=test".into(),
        param: Some("q".into()),
        payload: Some("' OR 1=1--".into()),
        evidence: Some("DB error leaked".into()),
        confidence: 90,
        note: Some("Verify manually".into()),
        request: None,
        response: None,
    };
    let md = kobra::report::markdown_v2::render(&[f], "e2e-md");
    assert!(md.contains("🐍 KOBRA Security Assessment"));
    assert!(md.contains("A03:2021"));
    assert!(md.contains("CWE-89"));
}

#[test]
fn e2e_dashboard_html() {
    let f = Finding {
        severity: Severity::Critical,
        category: "TAKEOVER".into(),
        title: "Critical vuln".into(),
        target: "https://x.com/".into(),
        param: None,
        payload: None,
        evidence: None,
        confidence: 90,
        note: None,
        request: None,
        response: None,
    };
    let html = kobra::report::dashboard::render(&[f], "e2e-html");
    assert!(html.contains("<!DOCTYPE html>"));
    assert!(html.contains("KOBRA"));
    assert!(html.contains(".sev-critical"));
    assert!(html.contains("function filter()"));
}
