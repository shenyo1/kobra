//! JS Bundle Secret/API Key Mining Module — KOBRA enhancement 2026-07-27
//!
//! Inspired by sankavollerei.web.id engagement: API key `planaai` was
//! hardcoded in JS bundle. KOBRA now crawls all JS chunks from the
//! target, parses them, and emits findings for hardcoded secrets.

use crate::types::{Finding, Severity};
use crate::http::HttpClient;
use regex::Regex;
use std::collections::HashSet;

const SECRET_PATTERNS: &[(&str, &str)] = &[
    (r#"apikey=([a-zA-Z0-9_\-]{4,})"#, "Hardcoded API key in URL"),
    (r#"api_key=([a-zA-Z0-9_\-]{4,})"#, "Hardcoded API key in URL"),
    (r#"apikey:\s*['"]([a-zA-Z0-9_\-]{4,})['"]"#, "Hardcoded API key field"),
    (r#"(?:Bearer|bearer)\s+([A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,})"#, "Hardcoded JWT bearer token"),
    (r#"AKIA[0-9A-Z]{16}"#, "AWS Access Key ID"),
    (r#"AIza[0-9A-Za-z\-_]{35}"#, "Google API Key"),
    (r#"sk_live_[0-9a-zA-Z]{24,}"#, "Stripe live secret key"),
    (r#"sk_test_[0-9a-zA-Z]{24,}"#, "Stripe test secret key"),
    (r#"ghp_[0-9a-zA-Z]{36}"#, "GitHub personal access token"),
    (r#"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"#, "Private key embedded"),
    (r#"firebaseConfig\s*=\s*\{[^}]+apiKey['"]?\s*:\s*['"]([A-Za-z0-9\-_]{20,})['"]"#, "Firebase API key"),
    (r#"twilioAccountSid\s*[=:]\s*['"]?(AC[a-z0-9]{32})"#, "Twilio Account SID"),
];

pub async fn scan(http: &HttpClient, target: &str, _mode: crate::types::Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = if target.ends_with('/') { target.to_string() } else { format!("{}/", target) };

    // 1) Get homepage HTML
    let (status, _headers, body, _final_url) = match http.get(&url).await {
        Ok(t) => t,
        Err(_) => return findings,
    };
    if status >= 400 { return findings; }

    // 2) Extract JS chunk URLs
    let js_re = Regex::new(r#"src=["']([^"']+\.js(?:\?[^"']*)?)["']"#).unwrap();
    let mut js_urls = HashSet::new();
    for cap in js_re.captures_iter(&body) {
        if let Some(m) = cap.get(1) {
            let u = m.as_str();
            let full = if u.starts_with("http") { u.to_string() }
                       else if u.starts_with("//") { format!("https:{}", u) }
                       else if u.starts_with('/') { format!("{}{}", target.trim_end_matches('/'), u) }
                       else { format!("{}/{}", target.trim_end_matches('/'), u) };
            js_urls.insert(full);
        }
    }

    // Probe common chunk paths
    let common = [
        "/assets/index.js", "/static/js/main.js", "/_next/static/chunks/main.js",
        "/js/app.js", "/build/bundle.js", "/dist/app.js",
    ];
    for p in common.iter() {
        js_urls.insert(format!("{}{}", target.trim_end_matches('/'), p));
    }

    // 3) Fetch each JS chunk and mine
    let mut seen = HashSet::new();
    for js_url in js_urls.iter() {
        let (js_status, _, js_body, _) = match http.get(js_url).await {
            Ok(t) => t,
            Err(_) => continue,
        };
        if js_status != 200 || js_body.len() < 500 { continue; }

        for (pat, desc) in SECRET_PATTERNS.iter() {
            let re = match Regex::new(pat) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for cap in re.captures_iter(&js_body) {
                let secret = cap.get(1).or_else(|| cap.get(0)).map(|m| m.as_str()).unwrap_or("");
                let lower = secret.to_lowercase();
                if lower.contains("placeholder") || lower.contains("example")
                    || lower.contains("your_") || lower.contains("xxx") || secret.len() < 4 {
                    continue;
                }
                let key = format!("{}-{}", js_url, secret);
                if seen.contains(&key) { continue; }
                seen.insert(key);

                let sev = if desc.contains("JWT") || desc.contains("Private key") || desc.contains("AWS") {
                    Severity::Critical
                } else if desc.contains("Stripe live") {
                    Severity::Critical
                } else if desc.contains("Stripe test") || desc.contains("Firebase") || desc.contains("Google") {
                    Severity::High
                } else {
                    Severity::High
                };

                let snippet: String = secret.chars().take(20).collect();
                let mut finding = Finding::new(
                    sev,
                    "js_secret_mine",
                    desc,
                    target,
                )
                .with_payload(&format!("Pattern matched: {}", pat))
                .with_evidence(&format!(
                    "Snippet '{}...' found in JS chunk {} (size: {} bytes)",
                    snippet, js_url, js_body.len()
                ))
                .with_note("Move secret server-side. Use OAuth or per-user scoped keys. Rotate immediately if exposed.");
                finding = finding.with_response(js_url);
                findings.push(finding);
            }
        }
    }

    findings
}