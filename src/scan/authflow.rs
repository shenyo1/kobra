use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// Auth-flow / magic-link attacker surface (pre-auth, non-destructive).
/// Tests for: email parameter tampering in OTP send, response-leaked OTP/token,
/// and open redirect in login `redirect` param (account takeover vectors).
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/');

    // Endpoints commonly handling magic-link / OTP.
    let endpoints = vec!["/send-code", "/api/send-code", "/login", "/api/login",
                         "/auth/login", "/otp/send", "/api/otp", "/auth/send-otp",
                         "/api/v1/auth/login"];

    for ep in endpoints {
        let url = format!("{}{}", base, ep);
        // 1) Email tampering: can we request a code for a VICTIM email?
        let body_victim = serde_json::json!({"email":"victim@sumopod.com"}).to_string();
        if let Ok((st, _h, resp, _f)) = http.fetch(&url, reqwest::Method::POST,
                Some(&body_victim), Some(std_header())).await {
            let rl = resp.to_lowercase();
            // Signs of a real OTP-send flow responding to arbitrary email:
            if st == 200 && (rl.contains("code sent") || rl.contains("otp") || rl.contains("magic") || rl.contains("link sent") || rl.contains("email sent")) {
                out.push(Finding::new(Severity::High, "AUTH", "Magic-link/OTP endpoint accepts arbitrary victim email (pre-auth ATO vector)", &url)
                    .with_payload(&format!("POST {} {{email:victim@sumopod.com}}", ep))
                    .with_evidence("server acknowledged OTP send for non-owned email")
                    .with_confidence(65));
            }
            // 2) Token/OTP leaked in response body (critical leak)
            if st == 200 && (rl.contains("\"otp\"") || rl.contains("\"code\"") || rl.contains("\"token\"") && rl.contains("1234") || rl.contains("verification")) {
                out.push(Finding::new(Severity::Critical, "AUTH", "Possible OTP/token leaked in response (pre-auth account takeover)", &url)
                    .with_payload(&format!("POST {} -> inspect response", ep))
                    .with_evidence("response contains token/otp-like field")
                    .with_confidence(55));
            }
        }
    }

    // 3) Open redirect in login `redirect` param (phishing / token theft)
    let redir_targets = vec!["https://evil.com", "//evil.com", "https://sumopod.com.evil.com"];
    for rt in redir_targets {
        let url = format!("{}/login?redirect={}", base, rt);
        if let Ok((st, h, _b, _f)) = http.get(&url).await {
            let loc = h.to_lowercase();
            if st == 302 && loc.contains("location:") && (loc.contains("evil.com")) {
                out.push(Finding::new(Severity::Medium, "AUTH", "Open redirect in login redirect param", &url)
                    .with_payload(&format!("redirect={}", rt))
                    .with_evidence("302 Location points to attacker domain")
                    .with_confidence(75));
            }
        }
    }

    Ok(out)
}

fn std_header() -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    m.insert("Content-Type".to_string(), "application/json".to_string());
    m
}
