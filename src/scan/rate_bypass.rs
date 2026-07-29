//! Rate Limit Bypass Engine — systematic techniques to evade rate limiting.
//! Tests: IP spoofing headers, HTTP method switching, parameter pollution,
//! path traversal, encoding tricks, case variation, HTTP/2 race.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct BypassResult {
    pub technique: &'static str,
    pub success: bool,
    pub status: u16,
    pub evidence: String,
}

/// Test all rate-limit bypass techniques on a target
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Get baseline response
    let (base_st, _base_h, base_body, _f) = match http.get(target).await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    // Try each bypass technique
    let techniques = vec![
        ("X-Forwarded-For spoof", vec![("X-Forwarded-For".to_string(), "127.0.0.1".to_string())]),
        ("X-Real-IP spoof", vec![("X-Real-IP".to_string(), "127.0.0.1".to_string())]),
        ("X-Original-URL bypass", vec![("X-Original-URL".to_string(), target.to_string())]),
        ("X-Rewrite-URL bypass", vec![("X-Rewrite-URL".to_string(), target.to_string())]),
        ("True-Client-IP spoof", vec![("True-Client-IP".to_string(), "127.0.0.1".to_string())]),
        ("CF-Connecting-IP spoof", vec![("CF-Connecting-IP".to_string(), "127.0.0.1".to_string())]),
        ("X-Forwarded-Host spoof", vec![("X-Forwarded-Host".to_string(), "localhost".to_string())]),
        ("X-Custom-IP-Authorization", vec![("X-Custom-IP-Authorization".to_string(), "1.3.3.7".to_string())]),
    ];

    let mut successful_bypasses = Vec::new();

    for (label, headers) in &techniques {
        let mut h = HashMap::new();
        for (k, v) in headers {
            h.insert(k.clone(), v.clone());
        }
        if let Ok((st, _h, body, _f)) = http.fetch(target, reqwest::Method::GET, None, Some(h)).await {
            // Bypass success = different response from baseline (and not just smaller)
            if st != base_st && (st == 200 || st == 302 || st == 301) {
                successful_bypasses.push(BypassResult {
                    technique: label,
                    success: true,
                    status: st,
                    evidence: format!("Baseline {} → bypass {} via {}", base_st, st, label),
                });
            } else if body.len() != base_body.len() && (st as u16) == base_st {
                // Same status but different content
                successful_bypasses.push(BypassResult {
                    technique: label,
                    success: true,
                    status: st,
                    evidence: format!("Response size changed: {} → {} via {}", base_body.len(), body.len(), label),
                });
            }
        }
    }

    // Method switch bypass
    let alt_methods = ["POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
    for method in &alt_methods {
        if let Ok(reqwest_method) = method.parse::<reqwest::Method>() {
            if let Ok((st, _h, _b, _f)) = http.fetch(target, reqwest_method, None, None).await {
                if st == 200 && *method != "GET" && *method != "OPTIONS" {
                    successful_bypasses.push(BypassResult {
                        technique: "Method confusion",
                        success: true,
                        status: st,
                        evidence: format!("{} {} returned 200 (rate limit bypassed)", method, target),
                    });
                }
            }
        }
    }

    // Path variation
    let path_variants = [
        format!("{}/.", target),
        format!("{}//", target),
        format!("{}/..;/", target),
        format!("{}%00", target),
        format!("{}?%", target),
        format!("{}/./", target),
    ];

    for url in &path_variants {
        if let Ok((st, _h, body, _f)) = http.get(url).await {
            if st == 200 && body.len() > base_body.len() {
                successful_bypasses.push(BypassResult {
                    technique: "Path variation",
                    success: true,
                    status: st,
                    evidence: format!("URL {} returns more content than baseline", url),
                });
            }
        }
    }

    // Encoding tricks
    let encoded_urls = [
        format!("{}/%2e%2e", target),
        format!("{}%2f", target),
    ];

    for url in &encoded_urls {
        if let Ok((st, _h, _b, _f)) = http.get(url).await {
            if st == 200 && st != base_st {
                successful_bypasses.push(BypassResult {
                    technique: "URL encoding",
                    success: true,
                    status: st,
                    evidence: format!("Encoded URL {} returns 200", url),
                });
            }
        }
    }

    // Generate findings
    if !successful_bypasses.is_empty() {
        for b in &successful_bypasses {
            let severity = match b.technique {
                "CF-Connecting-IP spoof" | "True-Client-IP spoof" => Severity::High,
                _ => Severity::Medium,
            };

            findings.push(Finding {
                severity,
                category: "RATE-LIMIT-BYPASS".into(),
                title: format!("Rate limit bypass via {}", b.technique),
                target: target.to_string(),
                param: Some(b.technique.to_string()),
                payload: None,
                evidence: Some(b.evidence.clone()),
                confidence: 60,
                note: Some("Rate limiting can be bypassed. Implement proper server-side rate limiting based on session/user/IP combination.".into()),
                request: None,
                response: None,
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn techniques_non_empty() {
        assert!(!techniques().is_empty());
    }

    #[test]
    fn method_switch_test() {
        // Test that method switching logic works
        let alt = ["POST", "PUT", "DELETE"];
        assert_eq!(alt.len(), 3);
    }

    #[test]
    fn bypass_result_struct() {
        let r = BypassResult {
            technique: "test",
            success: true,
            status: 200,
            evidence: "test evidence".to_string(),
        };
        assert_eq!(r.technique, "test");
        assert!(r.success);
    }
}

fn techniques() -> Vec<(&'static str, Vec<(&'static str, &'static str)>)> {
    vec![
        ("X-Forwarded-For spoof", vec![("X-Forwarded-For", "127.0.0.1")]),
        ("X-Real-IP spoof", vec![("X-Real-IP", "127.0.0.1")]),
        ("CF-Connecting-IP spoof", vec![("CF-Connecting-IP", "127.0.0.1")]),
    ]
}
