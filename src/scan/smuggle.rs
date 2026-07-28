use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// HTTP Request Smuggling / CL-TE desync probe (Kong CVE-2026-6338 context).
/// Non-destructive: we send ambiguous Content-Length / Transfer-Encoding and
/// look for a differential response (desync indicator), not actual smuggling.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/').to_string();

    // CL-TE: Content-Length and Transfer-Encoding both present, TE chunked
    let smuggle_body = "0\r\n\r\nG";
    let mut h_te = std::collections::HashMap::new();
    h_te.insert("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string());
    h_te.insert("Transfer-Encoding".to_string(), "chunked".to_string());
    h_te.insert("Content-Length".to_string(), "6".to_string());

    if let Ok((st, _h, body, _f)) = http.fetch(
        &format!("{}/", base),
        reqwest::Method::POST,
        Some(smuggle_body),
        Some(h_te),
    ).await {
        // Desync indicator: response mentions smuggle artifact or odd 400/502 from gateway
        if st == 502 || st == 400 || body.to_lowercase().contains("smuggle") || body.to_lowercase().contains("chunked") && body.contains("G") {
            out.push(
                Finding::new(Severity::Medium, "SMUGGLE", "Possible HTTP request smuggling / desync (CL-TE) — Kong CVE-2026-6338 context", target)
                    .with_evidence(&format!("status={} ambiguous CL+TE accepted", st))
                    .with_confidence(50),
            );
        }
    }
    Ok(out)
}
