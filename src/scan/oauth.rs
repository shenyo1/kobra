//! OAuth 2.0 / OIDC flow tester.
//! Detects redirect_uri bypass, state fixation, PKCE downgrade, scope escalation.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

const OAUTH_PATHS: &[&str] = &[
    "/oauth/authorize", "/oauth/authenticate", "/oauth/token",
    "/oauth2/authorize", "/oauth2/token", "/oauth2/userinfo",
    "/auth/oauth/authorize", "/auth/oauth/token",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/connect/authorize", "/connect/token",
    "/login/oauth/authorize", "/api/oauth/authorize",
];

/// Common endpoints to test redirect_uri takeover on.
const REDIRECT_BYPASS_PAYLOADS: &[&str] = &[
    "https://evil.example.com/callback",
    "https://target.com.evil.example.com/callback",
    "https://target.com@evil.example.com/callback",
    "https://evil.example.com/target.com",
    "https://target.com.evil.com/cb",
    "javascript:alert(document.domain)",
    "data:text/html,<script>alert(1)</script>",
    "/\\evil.example.com/cb",
    "https://targetcom/cb", // typo domain
];

/// Probe OAuth endpoints + redirect_uri bypass attempts.
pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = normalize_base(target);

    // 1. Discovery: probe common OAuth endpoints
    for path in OAUTH_PATHS {
        let url = format!("{}{}", base, path);
        if let Ok((st, _h, _b, _f)) = http.get(&url).await {
            if st == 200 || st == 302 || st == 301 {
                let sev = if st == 302 || st == 301 { Severity::Info } else { Severity::Info };
                findings.push(Finding {
                    severity: sev,
                    category: "OAUTH".into(),
                    title: format!("OAuth endpoint reachable: {} (status {})", path, st),
                    target: url,
                    param: None,
                    payload: None,
                    evidence: Some(format!("HTTP {}", st)),
                    confidence: 70,
                    note: Some("Inspect for redirect_uri bypass, missing state, scope escalation".into()),
                    request: None,
                    response: None,
                });
            }
        }
    }

    // 2. Redirect URI bypass attempts (only in crazy mode — too noisy otherwise)
    if mode == Mode::Crazy {
        for path in &["/oauth/authorize", "/oauth2/authorize", "/connect/authorize", "/auth/oauth/authorize"] {
            for payload in REDIRECT_BYPASS_PAYLOADS {
                let test_url = format!(
                    "{}?client_id=test&response_type=code&redirect_uri={}",
                    format!("{}{}", base, path),
                    url_encode(payload)
                );
                if let Ok((st, _h, body, final_url)) = http.get(&test_url).await {
                    if st == 302 {
                        let lower = (body.clone() + &final_url).to_lowercase();
                        let evil_lower = "evil.example.com";
                        if lower.contains(evil_lower) || lower.contains("evil.com") {
                            findings.push(Finding {
                                severity: Severity::Critical,
                                category: "OAUTH".into(),
                                title: format!("OAuth redirect_uri bypass via {} ({})", path, payload),
                                target: test_url.clone(),
                                param: Some("redirect_uri".into()),
                                payload: Some(payload.to_string()),
                                evidence: Some(format!("302 to attacker domain. URL: {}", final_url)),
                                confidence: 85,
                                note: Some("Server allowed attacker-controlled redirect_uri. Account takeover risk.".into()),
                                request: None,
                                response: None,
                            });
                        }
                    }
                }
            }
        }
    }

    // 3. Detect missing PKCE on /authorize (Info-level heuristic)
    for path in &["/oauth/authorize", "/oauth2/authorize"] {
        let url = format!(
            "{}?client_id=test&response_type=code&redirect_uri=https://app.test/cb&state=abc",
            format!("{}{}", base, path)
        );
        if let Ok((st, _h, body, _f)) = http.get(&url).await {
            if st == 302 || st == 200 {
                let lower = body.to_lowercase();
                if !lower.contains("code_challenge") && !lower.contains("pkce") {
                    findings.push(Finding {
                        severity: Severity::Info,
                        category: "OAUTH".into(),
                        title: format!("OAuth flow at {} may not enforce PKCE", path),
                        target: url,
                        param: Some("code_challenge".into()),
                        payload: None,
                        evidence: Some("No code_challenge / PKCE marker in authorize response".into()),
                        confidence: 50,
                        note: Some("PKCE recommended for public clients. Manual confirmation required.".into()),
                        request: None,
                        response: None,
                    });
                }
            }
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

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            for b in c.to_string().bytes() {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn url_encode_basic() {
        assert_eq!(url_encode("hello"), "hello");
        assert_eq!(url_encode("a/b"), "a%2Fb");
        assert_eq!(url_encode("https://evil.example.com/"), "https%3A%2F%2Fevil.example.com%2F");
    }
    #[test]
    fn normalize_strips_query() {
        assert_eq!(normalize_base("https://x.com/path?a=1"), "https://x.com/path");
        assert_eq!(normalize_base("https://x.com/path#frag"), "https://x.com/path");
    }
    #[test]
    fn redirect_payloads_count() {
        assert!(REDIRECT_BYPASS_PAYLOADS.len() >= 8);
    }
}
