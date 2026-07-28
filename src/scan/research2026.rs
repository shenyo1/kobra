use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// 2026 research enrichment (from web/X/GitHub, 2026-07-26):
/// - Cloudflare error diagnostic headers (cf-error-type / cf-error-origin) -> origin disclosure
/// - Magic-link pre-account hijacking probe (GHSA-qq9h-g4jm-xgf3, better-auth)
/// - GraphQL batching attack (rate-limit bypass via alias queries)
pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/').to_string();

    // [1] Cloudflare error diagnostic headers -> origin system leak
    if let Ok((_st, h, _b, _f)) = http.get(&base).await {
        let hl = h.to_lowercase();
        if hl.contains("cf-error-type") || hl.contains("cf-error-origin") {
            // These appear ONLY on CF-generated errors -> reveals origin/infra
            let etype = hl.split("cf-error-type:").nth(1).map(|s| s.split('\r').next().unwrap_or("").split('\n').next().unwrap_or("").trim().to_string()).unwrap_or_default();
            let eorig = hl.split("cf-error-origin:").nth(1).map(|s| s.split('\r').next().unwrap_or("").split('\n').next().unwrap_or("").trim().to_string()).unwrap_or_default();
            out.push(
                Finding::new(Severity::Info, "CLOUDFLARE", "Cloudflare error diagnostic headers leaked", target)
                    .with_payload(&format!("cf-error-type={} cf-error-origin={}", etype, eorig))
                    .with_evidence("CF error headers disclose origin system (Apr 2026 docs)")
                    .with_confidence(60),
            );
        }
        // Kong upstream latency -> internal timing/infra leak
        if hl.contains("x-kong-upstream-latency") || hl.contains("x-kong-proxy-latency") {
            out.push(
                Finding::new(Severity::Low, "KONG", "Kong gateway latency header leaks upstream", target)
                    .with_evidence("X-Kong-Upstream-Latency / X-Kong-Proxy-Latency present")
                    .with_confidence(40),
            );
        }
    }

    // [2] Magic-link pre-account hijacking probe (GHSA-qq9h, non-destructive)
    // Attacker signs up with victim email; if server returns magic-link / token in response
    // (instead of emailing), it's a pre-account hijack ATO.
    if mode.attempt_bypass() {
        for ep in ["/api/auth/sign-up", "/api/signup", "/auth/signup", "/api/auth/magic-link", "/api/magic-link"] {
            let u = format!("{}{}", base, ep);
            let body = r#"{"email":"victim@sumopod.com","callback":"https://evil.test/c"}"#;
            if let Ok((st, _h, resp, _f)) = http.fetch(&u, reqwest::Method::POST, Some(body), Some(std::collections::HashMap::from([("Content-Type".into(), "application/json".into())]))).await {
                let rl = resp.to_lowercase();
                // Indicators the link/token is returned in-body (pre-account hijack)
                if (rl.contains("magic") && (rl.contains("token") || rl.contains("link") || rl.contains("url")))
                   || rl.contains("verification") && rl.contains("token")
                   || st == 200 && (rl.contains("\"token\"") || rl.contains("\"magiclink\"") || rl.contains("\"link\"")) {
                    out.push(
                        Finding::new(Severity::High, "AUTH", "Possible magic-link pre-account hijacking (GHSA-qq9h)", target)
                            .with_param(ep)
                            .with_payload(body)
                            .with_evidence(&format!("status={} response leaks magic-link/token in body", st))
                            .with_confidence(80),
                    );
                }
            }
        }
    }

    // [3] GraphQL batching attack (rate-limit bypass) — probe only, non-destructive
    if mode.attempt_bypass() {
        let gql_url = format!("{}/graphql", base);
        // Send a batch of alias queries; if server accepts array -> batching abuse possible
        let batch = r#"[{"query":"{__typename}","operationName":"a0"},{"query":"{__typename}","operationName":"a1"},{"query":"{__typename}","operationName":"a2"}]"#;
        if let Ok((st, _h, resp, _f)) = http.fetch(&gql_url, reqwest::Method::POST, Some(batch), Some(std::collections::HashMap::from([("Content-Type".into(), "application/json".into())]))).await {
            if st == 200 && (resp.contains("__typename") || resp.contains("data")) {
                out.push(
                    Finding::new(Severity::Medium, "GRAPHQL", "GraphQL batching accepted (rate-limit bypass vector)", target)
                        .with_evidence("server accepted JSON array of queries (batch abuse possible)")
                        .with_confidence(60),
                );
            }
        }
    }

    Ok(out)
}
