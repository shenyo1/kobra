//! Multi-Session IDOR Testing — compare responses between two authenticated
//! sessions to detect Insecure Direct Object References.
//! Requires --auth and --auth2 flags (two different user sessions).

use crate::http::HttpClient;
use crate::types::{Finding, Severity};

/// Common IDOR-susceptible endpoint patterns
const IDOR_PATHS: &[&str] = &[
    "/api/users/1",
    "/api/users/2",
    "/api/user/1",
    "/api/user/2",
    "/api/profile/1",
    "/api/profile/2",
    "/api/account/1",
    "/api/account/2",
    "/api/orders/1",
    "/api/orders/2",
    "/api/order/1",
    "/api/order/2",
    "/api/invoices/1",
    "/api/invoices/2",
    "/api/payments/1",
    "/api/payments/2",
    "/api/settings",
    "/api/me",
    "/api/user/me",
    "/api/profile",
    "/api/v1/users/1",
    "/api/v1/users/2",
    "/api/v1/me",
    "/graphql",
];

/// Compare two HTTP responses for IDOR indicators
fn compare_responses(
    path: &str,
    st1: u16, body1: &str,
    st2: u16, body2: &str,
    target: &str,
) -> Option<Finding> {
    // Both return 200 with similar content = potential IDOR
    if st1 == 200 && st2 == 200 {
        let b1 = body1.trim();
        let b2 = body2.trim();

        // If both return data (not empty, not error page)
        if !b1.is_empty() && !b2.is_empty() && b1.len() > 10 && b2.len() > 10 {
            // Check if responses are structurally similar (same keys, different values)
            let similar = structural_similarity(b1, b2);
            if similar > 0.6 {
                return Some(
                    Finding::new(Severity::High, "IDOR", &format!("Potential IDOR: {} accessible by both sessions", path), target)
                        .with_evidence(&format!("Session A: HTTP {} ({} bytes), Session B: HTTP {} ({} bytes), similarity: {:.0}%", st1, b1.len(), st2, b2.len(), similar * 100.0))
                        .with_note("Both authenticated users can access the same resource. Verify if this is intended.")
                        .with_confidence(65),
                );
            }
        }
    }

    // One returns 200, other returns 403/401 = proper access control (good)
    // One returns 200, other returns 200 with DIFFERENT data = normal (different users)
    None
}

/// Simple structural similarity: compare JSON keys or HTML structure
fn structural_similarity(a: &str, b: &str) -> f64 {
    // Try JSON comparison
    if let (Ok(ja), Ok(jb)) = (
        serde_json::from_str::<serde_json::Value>(a),
        serde_json::from_str::<serde_json::Value>(b),
    ) {
        let keys_a = extract_keys(&ja);
        let keys_b = extract_keys(&jb);
        if keys_a.is_empty() && keys_b.is_empty() {
            return 0.0;
        }
        let intersection: usize = keys_a.iter().filter(|k| keys_b.contains(k)).count();
        let union = keys_a.len().max(keys_b.len());
        if union == 0 { return 0.0; }
        return intersection as f64 / union as f64;
    }

    // Fallback: length-based similarity
    let len_a = a.len() as f64;
    let len_b = b.len() as f64;
    if len_a == 0.0 && len_b == 0.0 { return 1.0; }
    1.0 - ((len_a - len_b).abs() / len_a.max(len_b))
}

fn extract_keys(v: &serde_json::Value) -> Vec<String> {
    let mut keys = Vec::new();
    match v {
        serde_json::Value::Object(map) => {
            for (k, val) in map {
                keys.push(k.clone());
                keys.extend(extract_keys(val));
            }
        }
        serde_json::Value::Array(arr) => {
            if let Some(first) = arr.first() {
                keys.extend(extract_keys(first));
            }
        }
        _ => {}
    }
    keys
}

/// Run IDOR comparison between two authenticated HTTP clients
pub async fn scan(
    http_a: &HttpClient,
    http_b: &HttpClient,
    target: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = target.trim_end_matches('/');

    for path in IDOR_PATHS {
        let url = format!("{}{}", base, path);

        let resp_a = http_a.get(&url).await;
        let resp_b = http_b.get(&url).await;

        if let (Ok((st_a, _h_a, body_a, _f_a)), Ok((st_b, _h_b, body_b, _f_b))) = (resp_a, resp_b) {
            if let Some(finding) = compare_responses(path, st_a, &body_a, st_b, &body_b, target) {
                findings.push(finding);
            }
        }
    }

    // Also test with numeric ID manipulation on discovered endpoints
    // Try /api/users/{id} with sequential IDs
    for base_path in &["/api/users", "/api/user", "/api/orders", "/api/order", "/api/invoices"] {
        for id in 1..=3 {
            let url = format!("{}{}/{}", base, base_path, id);
            let resp_a = http_a.get(&url).await;
            let resp_b = http_b.get(&url).await;

            if let (Ok((st_a, _, body_a, _)), Ok((st_b, _, body_b, _))) = (resp_a, resp_b) {
                if st_a == 200 && st_b == 200 && !body_a.trim().is_empty() && !body_b.trim().is_empty() {
                    let sim = structural_similarity(&body_a, &body_b);
                    if sim > 0.7 && body_a.trim() != body_b.trim() {
                        findings.push(
                            Finding::new(Severity::High, "IDOR", &format!("IDOR: {} accessible with different IDs by both users", url), target)
                                .with_evidence(&format!("Both sessions return HTTP 200 with similar structure ({:.0}% match)", sim * 100.0))
                                .with_confidence(60),
                        );
                    }
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_similarity_identical() {
        let a = r#"{"id": 1, "name": "alice", "email": "a@test.com"}"#;
        let b = r#"{"id": 2, "name": "bob", "email": "b@test.com"}"#;
        let sim = structural_similarity(a, b);
        assert!(sim > 0.9); // Same keys, different values
    }

    #[test]
    fn json_similarity_different() {
        let a = r#"{"id": 1, "name": "alice"}"#;
        let b = r#"{"status": "ok", "count": 5}"#;
        let sim = structural_similarity(a, b);
        assert!(sim < 0.5); // Different keys
    }

    #[test]
    fn idor_paths_non_empty() {
        assert!(IDOR_PATHS.len() > 10);
    }

    #[test]
    fn extract_keys_nested() {
        let v: serde_json::Value = serde_json::json!({"a": {"b": 1}, "c": [1,2]});
        let keys = extract_keys(&v);
        assert!(keys.contains(&"a".to_string()));
        assert!(keys.contains(&"b".to_string()));
        assert!(keys.contains(&"c".to_string()));
    }
}
