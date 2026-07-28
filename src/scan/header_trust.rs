//! Header Trust detector — finds endpoints that read & trust IP-spoofing headers.
//! Real finding example: `CF-Connecting-IP: 127.0.0.1` → 403 "DNS points to prohibited IP"
//! proves the server processes this header. Indicates SSRF protection that can be
//! bypassed if attacker controls the header (e.g., via X-Forwarded-Host injection).

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use std::collections::HashMap;

/// Headers that spoof client IP. If server responds DIFFERENTLY based on these,
/// server is reading them (potential header-trust vulnerability).
const IP_SPOOF_HEADERS: &[(&str, &str)] = &[
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("True-Client-IP", "127.0.0.1"),
    ("CF-Connecting-IP", "127.0.0.1"),
    ("X-Original-IP", "127.0.0.1"),
    ("X-Client-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("X-Remote-Addr", "127.0.0.1"),
    ("Forwarded", "for=127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
];

pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    if mode == Mode::Stealth {
        return findings;
    }
    // Get baseline (no spoof headers)
    let baseline = match http.get(target).await {
        Ok((st, _h, body, _f)) => (st, body.len()),
        Err(_) => return findings,
    };

    for (header, value) in IP_SPOOF_HEADERS {
        let mut h = HashMap::new();
        h.insert(header.to_string(), value.to_string());
        if let Ok((st, _h2, body, _f)) = http.fetch(target, reqwest::Method::GET, None, Some(h)).await {
            // Server responded differently — header is being read
            let differs = st != baseline.0 || body.len() != baseline.1;
            if differs {
                let sev = if st == 403 || st == 500 { Severity::Medium } else { Severity::Low };
                let title = if header.contains("CF-Connecting-IP") && st == 403 {
                    format!("CF-Connecting-IP header trusted (403 on internal IP — SSRF protection spoofable)")
                } else if st == 200 && body.len() != baseline.1 {
                    format!("{} header trusted (response differs — potential auth/IP bypass)", header)
                } else {
                    format!("{} header affects response (read by server)", header)
                };
                findings.push(Finding {
                    severity: sev,
                    category: "HEADER-TRUST".into(),
                    title,
                    target: target.to_string(),
                    param: Some(header.to_string()),
                    payload: Some(format!("{}: {}", header, value)),
                    evidence: Some(format!("baseline={}/{}b probe={}/{}b", baseline.0, baseline.1, st, body.len())),
                    confidence: 75,
                    note: Some("CWE-345. Server reads client-supplied IP header. Verify if attacker can spoof via SSRF chain (X-Forwarded-Host injection, header smuggling).".into()),
                    request: None,
                    response: None,
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_list_count() {
        assert!(IP_SPOOF_HEADERS.len() >= 10);
    }
    #[test]
    fn cf_connecting_ip_present() {
        assert!(IP_SPOOF_HEADERS.iter().any(|(h, _)| *h == "CF-Connecting-IP"));
    }
}
