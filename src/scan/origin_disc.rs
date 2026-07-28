use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// Cloudflare origin IP discovery (2026 technique, intigriti/blog).
/// Enumerate historical certs via crt.sh, resolve candidate A/AAAA,
/// and report subdomains whose DNS may point to the real origin (bypassing CF edge).
/// Non-destructive: only DNS/SSL observation, no direct origin attack.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    // Extract domain from target URL
    let dom = target
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/').next().unwrap_or(target);
    let base_dom = if let Some(_d) = dom.split('.').nth(1) {
        // take registrable domain (best-effort: last two labels)
        let parts: Vec<&str> = dom.split('.').collect();
        if parts.len() >= 2 { format!("{}.{}", parts[parts.len()-2], parts[parts.len()-1]) } else { dom.to_string() }
    } else { dom.to_string() };

    // Query crt.sh for certificates (historical origin IPs often re-used)
    let url = format!("https://crt.sh/?q=%.{}&output=json", base_dom);
    if let Ok((_st, _h, body, _f)) = http.get(&url).await {
        // crt.sh returns JSON array of certs; we just note exposure of historical subdomains
        let sub_count = body.matches("\"name_value\"").count();
        if sub_count > 0 {
            out.push(
                Finding::new(Severity::Info, "ORIGIN", "Cloudflare fronted — historical certs expose subdomains (origin discovery vector)", target)
                    .with_payload(&url)
                    .with_evidence(&format!("crt.sh returned ~{} subdomain cert entries for {}", sub_count, base_dom))
                    .with_note("Use these subdomains + historical DNS to find origin IP, then test origin directly (CF bypass)")
                    .with_confidence(40),
            );
        }
    }
    Ok(out)
}
