use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;
use std::collections::HashMap;

/// Multi-tenant isolation test (program priority: AI / data leakage across tenants).
/// Sends a请求 with a foreign tenant identifier in common param names; flags if the
/// response differs in a way suggesting cross-tenant data access.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/');

    let tenant_params = ["tenant_id", "tenantId", "org_id", "organization_id",
                          "workspace", "account_id", "tenant", "scope"];

    // Baseline with our (fake) tenant id
    let own = "OWN_TENANT_ABC123";
    let victim = "VICTIM_TENANT_XYZ789";

    for p in tenant_params {
        let base_url = format!("{}/api/data?{}={}", base, p, own);
        let victim_url = format!("{}/api/data?{}={}", base, p, victim);

        if let Ok((_s1, _h1, b1, _f1)) = http.get(&base_url).await {
            if let Ok((s2, _h2, b2, _f2)) = http.get(&victim_url).await {
                // Fix v4.2.0: skip if both responses look like SPA fallback HTML.
                let b1l = b1.to_lowercase();
                let b2l = b2.to_lowercase();
                let is_html_1 = b1l.contains("<html") || b1l.contains("<!doctype");
                let is_html_2 = b2l.contains("<html") || b2l.contains("<!doctype");
                if is_html_1 && is_html_2 && b1 == b2 {
                    continue; // SPA fallback — skip
                }
                // If status ok for victim and body differs significantly AND contains
                // data-looking content, flag potential isolation break.
                if s2 == 200 && b2 != b1 && b2.len() > 20 {
                    // Heuristic: victim response should not equal "not found"/"forbidden"
                    let lb = b2.to_lowercase();
                    if !lb.contains("forbidden") && !lb.contains("unauthorized")
                       && !lb.contains("not found") && !lb.contains("404") {
                        out.push(Finding::new(Severity::High, "MULTITENANT",
                            "Possible cross-tenant data access via tenant param swap", &victim_url)
                            .with_param(p)
                            .with_payload(&format!("{}={}", p, victim))
                            .with_evidence("response for foreign tenant differs from own and returns data")
                            .with_confidence(50));
                    }
                }
                // Explicit forbidden/error leak naming the victim tenant = info
                if s2 != 200 || b2.to_lowercase().contains("forbidden") {
                    out.push(Finding::new(Severity::Info, "MULTITENANT",
                        "Tenant isolation enforced (baseline)", &victim_url)
                        .with_param(p)
                        .with_payload(&format!("{}={}", p, victim))
                        .with_evidence(&format!("status {}", s2))
                        .with_confidence(20));
                }
            }
        }
    }

    // Also try path-based tenant: /tenant/<id>/...
    for t in [own, victim] {
        let u = format!("{}/tenant/{}/dashboard", base, t);
        if let Ok((st, _h, _b, _f)) = http.get(&u).await {
            if st == 200 {
                out.push(Finding::new(Severity::Info, "MULTITENANT",
                    "Tenant path accessible", &u)
                    .with_payload(&format!("/tenant/{}", t))
                    .with_evidence(&format!("status {}", st))
                    .with_confidence(20));
            }
        }
    }

    Ok(out)
}

#[allow(dead_code)]
fn _h() -> HashMap<String, String> { HashMap::new() }
