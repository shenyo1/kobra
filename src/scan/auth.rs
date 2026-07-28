use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// Auth/access-control checks — missing auth on sensitive paths, weak transport, JWT-ish hints.
/// ALL checks use BODY validation (negative-control) to avoid Cloudflare/Kong catch-all FPs.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/').to_string();
    let paths = [
        "/admin", "/api/admin", "/dashboard", "/api/users", "/.git/config",
        "/api/v1/users", "/admin.php", "/wp-admin", "/config", "/api/debug",
    ];
    for p in paths {
        let u = format!("{}{}", base, p);
        if let Ok((st, h, body, _f)) = http.get(&u).await {
            let hl = h.to_lowercase();
            let bl = body.to_lowercase();
            // Negative control: if response is a Cloudflare/Kong error page, ignore (catch-all FP).
            let is_cf_error = hl.contains("cf-ray") || bl.contains("cloudflare") && bl.contains("ray id");
            let is_kong_error = bl.contains("no route matched") || bl.contains("kong");

            // [.git config] — only flag if body is a REAL git config, not a catch-all 200.
            if p == "/.git/config" {
                if st == 200 && bl.contains("[core]") && !is_cf_error && !is_kong_error {
                    out.push(
                        Finding::new(Severity::High, "AUTH", "Exposed .git directory (source/secret leak)", &u)
                            .with_payload(p)
                            .with_evidence("response body contains [core] git config")
                            .with_confidence(90),
                    );
                }
                continue;
            }

            // [Sensitive path without auth] — only flag if 200 AND not an error page.
            if st == 200 && !is_cf_error && !is_kong_error {
                // Require some indication this is a real app page (not a generic 200 catch-all).
                if !bl.contains("not found") && !bl.contains("404") {
                    out.push(
                        Finding::new(Severity::Medium, "AUTH", "Sensitive path reachable without auth (possible Broken Access Control)", &u)
                            .with_payload(p)
                            .with_confidence(60),
                    );
                }
            }
        }
    }

    // Missing security headers (informational but shown — no hiding).
    if let Ok((_st, h, _b, _f)) = http.get(target).await {
        let hl = h.to_lowercase();
        for want in ["content-security-policy", "x-frame-options", "strict-transport-security", "x-content-type-options"] {
            if !hl.contains(want) {
                out.push(
                    Finding::new(Severity::Low, "HEADERS", "Missing security header", target)
                        .with_payload(want)
                        .with_note("hardening gap")
                        .with_confidence(30),
                );
            }
        }
    }
    Ok(out)
}
