use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

/// Email-only-login Mass ATO detector.
///
/// Pattern discovered in wibuku.app:
///   - POST /login with `{"email": "any@any"}` -> returns a session/token.
///   - No password, no OTP, no email verification — just "trust me bro, you are who
///     you say you are" if you know (or guess) an address.
///   - Trivial to weaponize into a Mass ATO: enumerate emails -> receive session per
///     request -> hijack every account on the platform.
///
/// Heuristics (we never assume — we test):
///   1. Send TWO distinct random emails; if both 200 + both share a "session" or
///      "token" (or other auth-ish) field of similar shape, the endpoint is almost
///      certainly handing out auth tokens to arbitrary inputs.
///   2. Negative control: send `notanemail`. If THAT gets rejected (4xx / error
///      shape) while the random emails get 200, validation exists -> report
///      confidence drops. If `notanemail` ALSO gets a token, validation is dead ->
///      report confidence goes UP (caller is willing to hand out tokens to
///      non-email-shaped strings, which is even worse).
///   3. JSON shape similarity: same set of top-level keys between the two random
///      emails is a strong signal. If the bodies diverge wildly (one is a session,
///      one is an error) the endpoint is doing lookup-then-decide properly.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/');

    // Endpoints we expect to carry an email-only login flow.
    let endpoints = vec![
        "/login",
        "/api/login",
        "/auth/login",
        "/api/auth/login",
        "/api/v1/login",
        "/api/v1/auth/login",
        "/signin",
        "/api/signin",
        "/session",
        "/api/session",
        "/authenticate",
    ];

    for ep in endpoints {
        let url = format!("{}{}", base, ep);

        // Three test payloads: two valid-shape random emails, one invalid-format junk.
        let id1 = unique_id();
        let id2 = unique_id();
        let body_r1 = serde_json::json!({"email": format!("kobra_probe_{}@example.com", id1)})
            .to_string();
        let body_r2 = serde_json::json!({"email": format!("kobra_probe_{}@example.com", id2)})
            .to_string();
        let body_bad = serde_json::json!({"email": "notanemail"}).to_string();

        let headers = json_headers();

        // Send all three in parallel — they're independent.
        let f_r1 = http.fetch(&url, reqwest::Method::POST, Some(&body_r1), Some(headers.clone()));
        let f_r2 = http.fetch(&url, reqwest::Method::POST, Some(&body_r2), Some(headers.clone()));
        let f_bad = http.fetch(&url, reqwest::Method::POST, Some(&body_bad), Some(headers.clone()));

        let (r1, r2, rb) = tokio::join!(f_r1, f_r2, f_bad);

        let (s1, _h1, b1, _u1) = match r1 {
            Ok(t) => t,
            Err(_) => continue, // endpoint not reachable -> skip
        };
        let (s2, _h2, b2, _u2) = match r2 {
            Ok(t) => t,
            Err(_) => continue,
        };
        let (sb, _hb, bb, _ub) = match rb {
            Ok(t) => t,
            Err(_) => continue,
        };

        let j1 = parse_json_safe(&b1);
        let j2 = parse_json_safe(&b2);
        let jb = parse_json_safe(&bb);

        let k1 = top_level_keys(&j1);
        let k2 = top_level_keys(&j2);
        let kb = top_level_keys(&jb);

        // Both successful + same shape + contains an auth-shaped field?
        let same_shape = k1 == k2 && !k1.is_empty();
        let has_auth_field_r1 = has_auth_field(&j1);
        let has_auth_field_r2 = has_auth_field(&j2);
        let both_have_auth = has_auth_field_r1 && has_auth_field_r2;

        // Negative control scoring.
        let bad_rejected = sb >= 400 || !jb.is_object() || kb != k1;
        let bad_same_shape = kb == k1;
        let bad_has_auth = has_auth_field(&jb);

        // 1. Strongest signal: both random emails get a token AND the junk email
        //    ALSO gets a token (or same shape) -> the endpoint doesn't even check
        //    that the input is an email. Pure ATO gold.
        if s1 == 200 && s2 == 200 && both_have_auth && (bad_has_auth || bad_same_shape) {
            out.push(
                Finding::new(
                    Severity::Critical,
                    "AUTH",
                    "Potential Mass Account Takeover via Email-Only Login (no validation)",
                    &url,
                )
                .with_payload(&format!(
                    "POST {} {{\"email\":\"kobra_probe_*@example.com\"}} AND {{\"email\":\"notanemail\"}}",
                    ep
                ))
                .with_evidence(&format!(
                    "Both random emails AND malformed 'notanemail' returned session/token. random1={}B random2={}B junk={}B",
                    b1.len(),
                    b2.len(),
                    bb.len()
                ))
                .with_request(&format!(
                    "POST {} HTTP/1.1\nContent-Type: application/json\n\n{}\n\n{}\n\n{}",
                    url, body_r1, body_r2, body_bad
                ))
                .with_response(&format!(
                    "random1: HTTP {}\n{}\n---\nrandom2: HTTP {}\n{}\n---\njunk: HTTP {}\n{}",
                    s1, truncate(&b1, 600), s2, truncate(&b2, 600), sb, truncate(&bb, 600)
                ))
                .with_confidence(95)
                .with_note("Server issues session/token to ANY email-shaped input AND non-email input — high-confidence Mass ATO primitive."),
            );
            continue;
        }

        // 2. The wibuku.app pattern: two distinct random emails get the SAME-shape
        //    success response with a session/token, while junk is rejected.
        //    -> endpoint trusts that the email exists if it looks like one, returns
        //    auth tokens for arbitrary unknown addresses.
        if s1 == 200 && s2 == 200 && same_shape && both_have_auth && bad_rejected {
            out.push(
                Finding::new(
                    Severity::Critical,
                    "AUTH",
                    "Potential Mass Account Takeover via Email-Only Login",
                    &url,
                )
                .with_payload(&format!(
                    "POST {} {{\"email\":\"<random>@example.com\"}} — both responses identical",
                    ep
                ))
                .with_evidence(&format!(
                    "Two distinct random emails returned same-shape JSON with session/token ({}B vs {}B). Malformed email was rejected (status {}).",
                    b1.len(),
                    b2.len(),
                    sb
                ))
                .with_request(&format!(
                    "POST {} HTTP/1.1\nContent-Type: application/json\n\n{}\n\n{}",
                    url, body_r1, body_r2
                ))
                .with_response(&format!(
                    "random1: HTTP {}\n{}\n---\nrandom2: HTTP {}\n{}",
                    s1, truncate(&b1, 600), s2, truncate(&b2, 600)
                ))
                .with_confidence(90)
                .with_note("If attacker enumerates real user emails, they get a valid session for each — confirm by testing one known account."),
            );
            continue;
        }

        // 3. Weaker signal: same shape but we can't see an explicit auth field.
        //    Could still be ATO if the field is named unusually (e.g. "jwt",
        //    "access_token", "remember_me"). Heuristic — flag as High with
        //    lower confidence.
        if s1 == 200 && s2 == 200 && same_shape && !both_have_auth && bad_rejected {
            // Look for ANY non-trivial string value > 16 chars that could be a token.
            let looks_like_token = has_long_string_value(&j1) && has_long_string_value(&j2);
            if looks_like_token {
                out.push(
                    Finding::new(
                        Severity::High,
                        "AUTH",
                        "Email-only login returns identical opaque tokens for arbitrary emails (suspect Mass ATO)",
                        &url,
                    )
                    .with_payload(&format!(
                        "POST {} {{\"email\":\"<random>@example.com\"}}",
                        ep
                    ))
                    .with_evidence(&format!(
                        "Both responses share top-level keys {:?} and contain a long opaque value — possible session/token.",
                        k1
                    ))
                    .with_response(&format!(
                        "random1 (HTTP {}): {}\nrandom2 (HTTP {}): {}",
                        s1,
                        truncate(&b1, 400),
                        s2,
                        truncate(&b2, 400)
                    ))
                    .with_confidence(70)
                    .with_note("Manual review required — verify one response token against a known account."),
                );
            }
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn json_headers() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("Content-Type".to_string(), "application/json".to_string());
    m.insert("Accept".to_string(), "application/json".to_string());
    m
}

/// Cheap unique-ish ID without pulling in `rand` (which isn't already a dep).
fn unique_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Mix with address-of-stack to avoid same-ns collisions across calls in a loop.
    let stack_hint = (&nanos as *const _) as usize as u64;
    nanos as u64 ^ stack_hint ^ 0x9E3779B97F4A7C15
}

fn parse_json_safe(body: &str) -> Value {
    // Trim BOM/whitespace, then try parse.
    let trimmed = body.trim_start_matches('\u{feff}').trim();
    serde_json::from_str(trimmed).unwrap_or(Value::Null)
}

fn top_level_keys(v: &Value) -> Vec<String> {
    match v {
        Value::Object(m) => {
            let mut ks: Vec<String> = m.keys().cloned().collect();
            ks.sort();
            ks
        }
        _ => Vec::new(),
    }
}

/// Detects common auth-token field names anywhere in the (shallow) JSON tree.
fn has_auth_field(v: &Value) -> bool {
    const NAMES: &[&str] = &[
        "session",
        "session_id",
        "sessionid",
        "token",
        "access_token",
        "accessToken",
        "refresh_token",
        "refreshToken",
        "auth",
        "authorization",
        "jwt",
        "bearer",
        "remember",
        "remember_me",
        "rememberMe",
        "cookie",
        "set-cookie",
        "setCookie",
        "sid",
        "user",
        "user_id",
        "userId",
        "account",
        "logged_in",
        "loggedIn",
        "isAuthenticated",
    ];
    if let Value::Object(m) = v {
        for k in m.keys() {
            let kl = k.to_lowercase();
            for n in NAMES {
                if kl == *n {
                    return true;
                }
            }
        }
    }
    false
}

/// True if the JSON has at least one string value >= 16 chars (a plausible token).
fn has_long_string_value(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.values().any(|x| match x {
            Value::String(s) => s.len() >= 16,
            _ => false,
        }),
        _ => false,
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…[truncated {}B]", &s[..max], s.len() - max)
    }
}