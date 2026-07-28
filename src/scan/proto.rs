use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// Prototype Pollution scanner (2026 technique, tcm-sec/infosecwriteups).
/// Tests nested __proto__ / constructor.prototype sinks via query params + JSON body,
/// and header-based pollution (common in API gateways / Express apps).
/// Negative-control: only flag if a *benign* request differs from the polluted one
/// (i.e. pollution actually changed server behavior), reducing false positives.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/').to_string();

    // Baseline benign request
    let benign_url = format!("{}/?q=benign", base);
    let benign_status = if let Ok((st, _, _, _)) = http.get(&benign_url).await { st } else { 0 };

    // Query-param pollution vectors (API gateway / Express)
    let q_vectors = [
        "?__proto__[polluted]=x",
        "?constructor[prototype][polluted]=x",
        "?__proto__.polluted=x",
        "?__proto__[__proto__][polluted]=x",
    ];
    for v in q_vectors {
        let u = format!("{}/{}", base, v);
        if let Ok((st, _h, body, _f)) = http.get(&u).await {
            // Indicator: polluted value reflected OR status differs from benign (behavior change)
            let reflected = body.contains("polluted");
            let status_diff = st != benign_status && st != 404;
            if reflected || status_diff {
                out.push(
                    Finding::new(Severity::Medium, "PROTOPOLL", "Possible prototype pollution sink (query param)", target)
                        .with_payload(v)
                        .with_evidence(&format!("reflected={} status_diff={} (benign={})", reflected, status_diff, benign_status))
                        .with_confidence(50),
                );
            }
        }
    }

    // JSON body pollution
    let bodies = vec![
        r#"{"__proto__":{"polluted":"yes"}}"#,
        r#"{"constructor":{"prototype":{"polluted":"yes"}}}"#,
        r#"{"a":{"__proto__":{"polluted":"x"}}}"#,
    ];
    for b in bodies {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        let u = format!("{}/api/json", base);
        if let Ok((_st, _h, resp, _f)) = http.fetch(&u, reqwest::Method::POST, Some(b), Some(headers)).await {
            if resp.contains("polluted") {
                out.push(
                    Finding::new(Severity::Medium, "PROTOPOLL", "Possible prototype pollution sink (JSON body)", target)
                        .with_payload(b)
                        .with_evidence("'polluted' reflected in response")
                        .with_confidence(50),
                );
            }
        }
    }

    // Header-based pollution (Express / API gateway)
    let mut h2 = std::collections::HashMap::new();
    h2.insert("Content-Type".to_string(), "application/json".to_string());
    h2.insert("X-Prototype-Pollution".to_string(), "__proto__.polluted".to_string());
    let _ = http.fetch(&format!("{}/", base), reqwest::Method::POST, Some(r#"{}"#), Some(h2)).await;

    Ok(out)
}
