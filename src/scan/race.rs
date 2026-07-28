//! Race Condition engine (TOCTOU).
//! Fire N requests; flag if response indicates state mutation >1 times.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};

/// Endpoints that often have race condition bugs.
const RACE_INTERESTING: &[&str] = &[
    "/api/v1/coupon/apply",
    "/api/v1/payment/charge",
    "/api/v1/withdraw",
    "/api/v1/transfer",
    "/api/v1/vote",
    "/api/v1/like",
    "/api/v1/redeem",
    "/api/v1/promo",
    "/api/transfer",
    "/api/withdraw",
    "/api/coupon",
    "/api/redeem",
];

/// Run N requests against `endpoint`. Ponytail: serial (HttpClient not Clone).
/// Still useful — many race bugs trigger with rapid serial calls.
pub async fn race_request(
    http: &HttpClient,
    endpoint: &str,
    n: usize,
    body: Option<&str>,
) -> Vec<(u16, String)> {
    let mut results = Vec::with_capacity(n);
    let body_owned: Option<String> = body.map(|s| s.to_string());
    for _ in 0..n {
        match http.fetch(endpoint, reqwest::Method::POST, body_owned.as_deref(), None).await {
            Ok((st, _h, body, _f)) => results.push((st, body)),
            Err(_) => results.push((0, String::new())),
        }
    }
    results
}

/// Detect race: success_body appears >= 2 times when should appear at most once.
pub fn detect_double_spend(responses: &[(u16, String)]) -> Option<usize> {
    let success_bodies: Vec<&str> = responses
        .iter()
        .filter(|(s, _)| *s == 200 || *s == 201)
        .map(|(_, b)| b.as_str())
        .collect();
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for b in &success_bodies {
        *counts.entry(b).or_insert(0) += 1;
    }
    counts.values().find(|&&c| c >= 2).copied()
}

pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    if mode == Mode::Stealth {
        return findings;
    }
    let base = normalize_base(target);
    let n = if mode == Mode::Crazy { 20 } else { 10 };
    for path in RACE_INTERESTING {
        let url = format!("{}{}", base, path);
        let probe_body = r#"{"code":"RACE_TEST_K0BRA","amount":1,"to":"self"}"#;
        let responses = race_request(http, &url, n, Some(probe_body)).await;
        if let Some(count) = detect_double_spend(&responses) {
            findings.push(Finding {
                severity: Severity::High,
                category: "RACE".into(),
                title: format!("Race condition at {} ({} successful identical responses)", path, count),
                target: url,
                param: None,
                payload: Some(probe_body.to_string()),
                evidence: Some(format!("{} requests, {} success-dups", n, count)),
                confidence: 60,
                note: Some("Server allowed concurrent state mutations. May enable double-spend / double-redeem.".into()),
                request: None,
                response: None,
            });
        }
    }
    findings
}

fn normalize_base(url: &str) -> String {
    if let Some(idx) = url.find('?') {
        url[..idx].to_string()
    } else if let Some(idx) = url.find('#') {
        url[..idx].to_string()
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detect_double_spend_positive() {
        let r = vec![
            (200, r#"{"ok":true,"balance":100}"#.to_string()),
            (200, r#"{"ok":true,"balance":100}"#.to_string()),
        ];
        assert_eq!(detect_double_spend(&r), Some(2));
    }
    #[test]
    fn detect_double_spend_negative() {
        let r = vec![
            (200, r#"{"ok":true,"balance":100}"#.to_string()),
            (409, r#"{"error":"conflict"}"#.to_string()),
        ];
        assert_eq!(detect_double_spend(&r), None);
    }
    #[test]
    fn detect_double_spend_partial() {
        let r = vec![
            (200, r#"{"ok":1}"#.to_string()),
            (200, r#"{"ok":1}"#.to_string()),
            (200, r#"{"ok":2}"#.to_string()),
        ];
        assert_eq!(detect_double_spend(&r), Some(2));
    }
    #[test]
    fn normalize_strips_query() {
        assert_eq!(normalize_base("https://x.com/api?a=1"), "https://x.com/api");
    }
}
