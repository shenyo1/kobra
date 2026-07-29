//! Auth flow detector (Lesson 2 fix v4.4.0).
//! Lesson: KOBRA v4.3.0 only handles JWT token auth. Many real apps use
//! Basic Auth, Session cookies, OAuth, 2FA, etc. Fix: detect auth flow type
//! and emit appropriate probes.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};

#[derive(Debug, Clone, PartialEq)]
pub enum AuthFlow {
    JwtBearer,           // Bearer eyJ... (v4.3.0)
    SessionCookie,       // Set-Cookie: session=...; HttpOnly
    BasicAuth,           // Authorization: Basic base64(user:pass)
    OAuth2Code,          // /oauth/authorize?code=...&state=...
    ApiKey,              // X-API-Key: sk-...
    Unknown,
}

/// Classify auth flow from response headers + body.
pub fn classify_auth_flow(headers: &str, body: &str) -> AuthFlow {
    let h_l = headers.to_lowercase();
    let b_l = body.to_lowercase();

    if h_l.contains("set-cookie:") && (h_l.contains("session") || h_l.contains("sid") || h_l.contains("phpsessid")) {
        return AuthFlow::SessionCookie;
    }
    if h_l.contains("www-authenticate: basic") {
        return AuthFlow::BasicAuth;
    }
    if h_l.contains("www-authenticate: bearer") {
        return AuthFlow::JwtBearer;
    }
    if body.contains("Bearer ") && body.contains("eyJ") {
        return AuthFlow::JwtBearer;
    }
    // JWT body detection (anon Bearer-style API)
    if body.contains("eyJ") && (body.contains("\"token\"") || body.contains("\"access_token\"")) {
        return AuthFlow::JwtBearer;
    }
    if body.contains("oauth/authorize") || body.contains("?code=") && body.contains("&state=") {
        return AuthFlow::OAuth2Code;
    }
    if body.contains("x-api-key") || body.contains("api_key") {
        return AuthFlow::ApiKey;
    }
    AuthFlow::Unknown
}

/// Probe target for auth endpoints.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Parse base URL: strip path/query to root (Lesson 2 v4.4.0 fix)
    let base = {
        let u = target.trim_end_matches('/');
        let (proto, rest) = if u.contains("://") {
            let idx = u.find("://").unwrap();
            (u[..idx + 3].to_string(), u[idx + 3..].to_string())
        } else {
            ("https://".to_string(), u.to_string())
        };
        let path_start = rest.find('/').unwrap_or(rest.len());
        format!("{}{}", proto, &rest[..path_start])
    };

    // Probe common auth endpoints
    let auth_paths = [
        ("/login", "Generic login"),
        ("/api/login", "API login"),
        ("/auth/login", "Auth endpoint"),
        ("/api/auth/login", "API auth"),
        ("/api/v1/auth/login", "v1 auth"),
        ("/api/v2/auth/login", "v2 auth"),
        ("/oauth/token", "OAuth token"),
        ("/oauth/authorize", "OAuth authorize"),
        ("/oauth/device/code", "OAuth device-code"),
        ("/api/oauth/token", "API OAuth"),
        ("/sso/login", "SSO login"),
        ("/rest/v1/rpc/login", "Supabase RPC login"),
        ("/auth/v1/token", "Supabase GoTrue"),
        ("/.well-known/openid-configuration", "OIDC discovery"),
    ];

    for (path, desc) in auth_paths {
        let url = format!("{}{}", base, path);
        if let Ok((status, headers, body, _f)) = http.get(&url).await {
            let flow = classify_auth_flow(&headers, &body);
            if flow != AuthFlow::Unknown || status != 404 {
                findings.push(Finding {
                    severity: Severity::Info,
                    category: "AUTH-FLOW".into(),
                    title: format!("Auth endpoint: {} ({})", path, desc),
                    target: url.clone(),
                    param: None,
                    payload: None,
                    evidence: Some(format!(
                        "Endpoint {} status={} flow={:?}. Auth-aware probing available.",
                        url, status, flow
                    )),
                    confidence: 60,
                    note: Some("Lesson 2 fix v4.4.0: Auth flow detection.".into()),
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
    fn detect_jwt_bearer() {
        let body = r#"{"token": "eyJhbGciOi..."}"#;
        assert_eq!(classify_auth_flow("", body), AuthFlow::JwtBearer);
    }

    #[test]
    fn detect_session_cookie() {
        let h = "Set-Cookie: session=abc123; HttpOnly; Path=/
";
        assert_eq!(classify_auth_flow(h, ""), AuthFlow::SessionCookie);
    }

    #[test]
    fn detect_basic_auth() {
        let h = "WWW-Authenticate: Basic realm=\"API\"";
        assert_eq!(classify_auth_flow(h, ""), AuthFlow::BasicAuth);
    }

    #[test]
    fn detect_bearer_challenge() {
        let h = "WWW-Authenticate: Bearer realm=\"API\"";
        assert_eq!(classify_auth_flow(h, ""), AuthFlow::JwtBearer);
    }

    #[test]
    fn detect_oauth_code_flow() {
        let body = "Redirect to https://example.com/oauth/authorize?code=abc&state=xyz";
        assert_eq!(classify_auth_flow("", body), AuthFlow::OAuth2Code);
    }

    #[test]
    fn detect_api_key_in_body() {
        let body = r#"{"error": "Invalid x-api-key"}"#;
        assert_eq!(classify_auth_flow("", body), AuthFlow::ApiKey);
    }

    #[test]
    fn unknown_for_clean_response() {
        assert_eq!(classify_auth_flow("", "Hello World"), AuthFlow::Unknown);
    }
}
