use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// Payment logic / IDOR probe (2026 technique, api-pay P1 program).
/// Non-destructive: we send tampered price / payment_method_id / user_id in a
/// checkout-style request and observe if the server accepts it (indicates
/// missing server-side validation). We do NOT complete real transactions.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/').to_string();

    let endpoints = [
        "/api/payment/checkout", "/api/checkout", "/api/v1/payment",
        "/api/pay", "/api/billing/charge", "/api/order",
    ];

    // Tampering vectors (non-destructive observation only)
    let tamper = [
        ("price_tamper", "{\"price\":0.01,\"currency\":\"USD\"}"),
        ("payment_method_swap", "{\"payment_method_id\":\"pm_other_user_123\",\"amount\":100}"),
        ("user_id_swap", "{\"user_id\":\"victim_id_999\",\"item_id\":\"item_1\"}"),
        ("negative_qty", "{\"quantity\":-1,\"price\":100}"),
        ("mass_assign_role", "{\"role\":\"admin\",\"id\":\"1\"}"),
    ];

    for ep in endpoints {
        let u = format!("{}{}", base, ep);
        for (label, body) in tamper {
            let mut h = std::collections::HashMap::new();
            h.insert("Content-Type".to_string(), "application/json".to_string());
            if let Ok((st, _h, resp, _f)) = http.fetch(&u, reqwest::Method::POST, Some(body), Some(h)).await {
                // If server returns 200 with a "success"/"created"/"order" style body for tampered input,
                // it suggests missing server-side validation (potential IDOR / price tamper).
                let rl = resp.to_lowercase();
                if st == 200 && (rl.contains("success") || rl.contains("created") || rl.contains("order") || rl.contains("payment")) {
                    out.push(
                        Finding::new(Severity::High, "PAYMENT", "Possible payment logic / IDOR (tampered input accepted)", target)
                            .with_param(ep)
                            .with_payload(&format!("{} :: {}", label, body))
                            .with_evidence(&format!("status=200 body suggests acceptance: {}", rl.chars().take(80).collect::<String>()))
                            .with_confidence(70),
                    );
                }
            }
        }
    }
    Ok(out)
}
