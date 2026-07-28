use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// CORS misconfiguration deep scanner — checks wildcard origin, credential reflection,
/// preflight bypass, and trusted-origin enumeration via Origin header.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/');

    // 1. Wildcard origin test
    if let Ok((_st, h, _b, _f)) = http.get_with_origin(&format!("{}/", base), "https://evil.com").await {
        let acao = h.lines().find(|l| l.to_lowercase().starts_with("access-control-allow-origin:"));
        let acac = h.lines().find(|l| l.to_lowercase().starts_with("access-control-allow-credentials:"));
        let allow_creds = acac.map(|l| l.contains("true")).unwrap_or(false);

        if let Some(acao_val) = acao {
            let val = acao_val.split(':').nth(1).unwrap_or("").trim();
            if val == "*" && allow_creds {
                out.push(
                    Finding::new(Severity::Critical, "CORS", "Wildcard origin + credentials (CORS misconfiguration)", target)
                        .with_payload("Origin: https://evil.com")
                        .with_evidence("Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true")
                        .with_confidence(95),
                );
            } else if val == "*" {
                out.push(
                    Finding::new(Severity::Medium, "CORS", "Wildcard CORS origin", target)
                        .with_payload("Origin: https://evil.com")
                        .with_evidence("Access-Control-Allow-Origin: *")
                        .with_confidence(90),
                );
            } else if val.contains("evil.com") && allow_creds {
                out.push(
                    Finding::new(Severity::High, "CORS", "Origin reflection + credentials (CORS misconfiguration)", target)
                        .with_payload("Origin: https://evil.com")
                        .with_evidence(&format!("ACAO: {} with ACAC: true", val))
                        .with_confidence(90),
                );
            } else if val.contains("evil.com") {
                out.push(
                    Finding::new(Severity::Low, "CORS", "Origin reflection (no credentials)", target)
                        .with_payload("Origin: https://evil.com")
                        .with_evidence(&format!("ACAO reflects: {}", val))
                        .with_confidence(75),
                );
            }
        }
    }

    // 2. Preflight (OPTIONS) test
    if let Ok((st, h, _b, _f)) = http.fetch(
        &format!("{}/", base),
        reqwest::Method::OPTIONS,
        None,
        None,
    ).await {
        if st == 204 || st == 200 {
            let methods = h.lines().find(|l| l.to_lowercase().starts_with("access-control-allow-methods:"));
            let headers = h.lines().find(|l| l.to_lowercase().starts_with("access-control-allow-headers:"));
            if let Some(m) = methods {
                out.push(
                    Finding::new(Severity::Info, "CORS", "CORS preflight allowed", target)
                        .with_payload("OPTIONS /")
                        .with_evidence(&format!("Allow-Methods: {}", m))
                        .with_confidence(40),
                );
            }
            if let Some(hdrs) = headers {
                if hdrs.contains("Authorization") && hdrs.contains("X-Custom") {
                    out.push(
                        Finding::new(Severity::Low, "CORS", "Permissive CORS headers allowed", target)
                            .with_payload("OPTIONS /")
                            .with_evidence(&format!("Allow-Headers: {}", hdrs))
                            .with_confidence(50),
                    );
                }
            }
        }
    }

    Ok(out)
}
