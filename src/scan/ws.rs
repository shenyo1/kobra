use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// WebSocket misconfiguration: insecure ws:// usage + unauthenticated upgrade attempt.
/// Non-destructive: just flags ws:// (cleartext) and probes /ws /socket endpoints for upgrade.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    // 1) insecure ws:// reference in page
    if let Ok((_st, _h, body, _f)) = http.get(target).await {
        if body.contains("ws://") {
            out.push(Finding::new(Severity::Low, "WS", "Insecure WebSocket (ws://) endpoint referenced", target)
                .with_evidence("page references cleartext ws://")
                .with_confidence(60));
        }
        if body.contains("wss://") && body.to_lowercase().contains("token=") {
            out.push(Finding::new(Severity::Low, "WS", "WebSocket token in URL (may leak via logs/referer)", target)
                .with_evidence("wss:// with token in query string")
                .with_confidence(40));
        }
    }
    // 2) common socket paths accept upgrade?
    let base = target.trim_end_matches('/').to_string();
    for p in ["/ws", "/socket", "/websocket", "/live"] {
        let u = format!("{}{}", base, p);
        if let Ok((st, _h, _b, _f)) = http.get(&u).await {
            if st == 101 || st == 426 {
                out.push(Finding::new(Severity::Medium, "WS", "WebSocket upgrade accepted (verify auth)", &u)
                    .with_payload(p)
                    .with_evidence(&format!("status={}", st))
                    .with_confidence(50));
            }
        }
    }
    Ok(out)
}
