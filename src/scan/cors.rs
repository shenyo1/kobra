use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// CORS misconfiguration scanner. Flags reflect-origin + credentialed wildcard.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let origin = "https://evil.example.com";
    if let Ok((_st, h, _b, _f)) = http.get_with_origin(target, origin).await {
        let acao = h.to_lowercase();
        if acao.contains("access-control-allow-origin: https://evil.example.com") {
            let creds = acao.contains("access-control-allow-credentials: true");
            let sev = if creds { Severity::High } else { Severity::Medium };
            out.push(Finding::new(sev, "CORS", "Reflective CORS allowed origin (poisoned by attacker origin)", target)
                .with_payload(&format!("Origin: {}", origin))
                .with_evidence(if creds { "reflects origin AND allows credentials" } else { "reflects attacker origin" })
                .with_confidence(80));
        }
    }
    Ok(out)
}
