use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;
use std::collections::HashMap;

/// WAF fingerprinting + bypass attempts. Reports WAF presence AND successful bypasses.
pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();

    // Fingerprint WAF via a known-bad baseline request.
    let evil = format!("{}/?id=1'", target.trim_end_matches('/'));
    if let Ok((st, h, _b, _f)) = http.get(&evil).await {
        let hl = h.to_lowercase();
        let waf = if hl.contains("cloudflare") { Some("Cloudflare") }
            else if hl.contains("akamai") { Some("Akamai") }
            else if hl.contains("incapsula") || hl.contains("imperva") { Some("Imperva") }
            else if hl.contains("aws") && hl.contains("waf") { Some("AWS WAF") }
            else if st == 403 || st == 419 || st == 406 { Some("Unknown/Generic") }
            else { None };
        if let Some(name) = waf {
            out.push(
                Finding::new(Severity::Info, "WAF", "WAF detected", target)
                    .with_payload(name)
                    .with_note("barrier present; bypass attempts follow")
                    .with_confidence(80),
            );
        }

        if mode.attempt_bypass() {
            // Bypass tricks: uncommon headers, chunked, case, encoding.
            let tricks: Vec<(&str, HashMap<String, String>)> = vec![
                ("X-Original-URL bypass", HashMap::from([("X-Original-URL".into(), "/admin".into())])),
                ("X-Rewrite-URL bypass", HashMap::from([("X-Rewrite-URL".into(), "/admin".into())])),
                ("X-Custom-IP-Authorization", HashMap::from([("X-Custom-IP-Authorization".into(), "127.0.0.1".into())])),
                ("X-Forwarded-For spoof", HashMap::from([("X-Forwarded-For".into(), "127.0.0.1".into())])),
                // Cloudflare origin-IP / rate-limit spoof (research round2)
                ("True-Client-IP spoof", HashMap::from([("True-Client-IP".into(), "127.0.0.1".into())])),
                // CVE-2025 uncommon-header WAF bypass (gasmask, 2025)
                ("X-Custom-IP-Authorization WAF", HashMap::from([("X-Custom-IP-Authorization".into(), "1.3.3.7".into())])),
            ];
            // Negative control: fetch /admin WITHOUT bypass headers.
            let base_url = format!("{}/admin", target.trim_end_matches('/'));
            let (base_st, base_body) = match http.get(&base_url).await {
                Ok((s, _h, b, _f)) => (s, b),
                Err(_) => (0, String::new()),
            };
            for (label, hdrs) in tricks {
                let u = format!("{}/admin", target.trim_end_matches('/'));
                if let Ok((bst, _bh, bb, _bf)) = http.fetch(&u, reqwest::Method::GET, None, Some(hdrs)).await {
                    // TRUE bypass only if: baseline was blocked (403/404/403) BUT header request
                    // succeeds (200) with DIFFERENT body, OR baseline 200 but body differs
                    // significantly (e.g. contains admin content the baseline lacked).
                    let baseline_blocked = base_st == 403 || base_st == 404 || base_st == 401 || base_st == 419;
                    let differs = bb.trim() != base_body.trim();
                    if (baseline_blocked && bst == 200 && differs) || (bst == 200 && differs && base_st == 200 && bb.to_lowercase().contains("admin") && !base_body.to_lowercase().contains("admin")) {
                        out.push(
                            Finding::new(Severity::High, "WAF", "Possible WAF/auth bypass via header", target)
                                .with_payload(label)
                                .with_evidence(&format!("status={} (baseline={})", bst, base_st))
                                .with_confidence(70),
                        );
                    }
                }
            }
        }
    }
    Ok(out)
}
