use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// API endpoint enumeration + OpenAPI/Swagger discovery.
/// Brute-forces common API paths and checks for OpenAPI spec leaks.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/');

    let api_paths = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/swagger.json", "/swagger/v1/swagger.json",
        "/api-docs", "/api/swagger", "/api/openapi.json",
        "/openapi.json", "/api/schema", "/graphql",
        "/.well-known/openid-configuration",
        "/health", "/healthz", "/ready", "/status",
        "/metrics", "/info", "/version",
        "/.env", "/admin", "/api/admin",
    ];

    for path in &api_paths {
        let url = format!("{}{}", base, path);
        if let Ok((st, _h, body, _f)) = http.get(&url).await {
            if st == 200 && !body.is_empty() {
                let lb = body.to_lowercase();
                // OpenAPI/Swagger spec
                if lb.contains("openapi") || lb.contains("swagger") || lb.contains("\"paths\"") {
                    out.push(
                        Finding::new(Severity::High, "API-DISCOVERY", "OpenAPI/Swagger spec exposed", target)
                            .with_payload(&url)
                            .with_evidence("API specification document accessible without auth")
                            .with_confidence(95),
                    );
                } else if path.contains("swagger") || path.contains("openapi") {
                    // Generic swagger/openapi endpoint returning 200
                    out.push(
                        Finding::new(Severity::Medium, "API-DISCOVERY", "API documentation endpoint accessible", target)
                            .with_payload(&url)
                            .with_evidence(&format!("HTTP {} — accessible endpoint", st))
                            .with_confidence(80),
                    );
                } else {
                    out.push(
                        Finding::new(Severity::Low, "API-DISCOVERY", "API endpoint accessible without auth", target)
                            .with_payload(&url)
                            .with_evidence(&format!("HTTP {} — {} bytes", st, body.len()))
                            .with_confidence(60),
                    );
                }
            }
        }
    }

    Ok(out)
}
