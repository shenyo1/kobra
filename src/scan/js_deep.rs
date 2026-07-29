//! JS Deep Analysis — parse webpack/vite/next bundles to extract hidden
//! API routes, internal endpoints, client-side secrets, and route maps.
//! Goes deeper than js_secret_mine (which only does regex for keys).

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use regex::Regex;
use std::collections::HashSet;

/// Extracted JS intelligence
#[derive(Debug, Default)]
pub struct JsIntel {
    pub api_routes: Vec<String>,
    pub internal_paths: Vec<String>,
    pub env_vars: Vec<String>,
    pub framework: Option<String>,
    pub source_maps: Vec<String>,
    pub graphql_endpoints: Vec<String>,
    pub websocket_urls: Vec<String>,
    pub auth_endpoints: Vec<String>,
    pub admin_paths: Vec<String>,
}

/// Main scan: fetch page, find JS bundles, deep-parse each
pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = target.trim_end_matches('/');

    // Fetch main page
    let (_st, _h, body, _f) = match http.get(&format!("{}/", base)).await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    // Detect framework
    let framework = detect_framework(&body);

    // Extract JS bundle URLs
    let js_urls = extract_js_urls(&body, base);

    // Limit based on mode
    let limit = match mode {
        Mode::Stealth => 2,
        Mode::Normal => 5,
        Mode::Crazy => 15,
    };

    let mut all_intel = JsIntel::default();
    all_intel.framework = framework.clone();

    // Parse each JS bundle
    for url in js_urls.iter().take(limit) {
        if let Ok((_jst, _jh, js_body, _jf)) = http.get(url).await {
            let intel = parse_js_bundle(&js_body);
            merge_intel(&mut all_intel, intel);
        }
    }

    // Also parse inline scripts
    let inline_intel = parse_inline_scripts(&body);
    merge_intel(&mut all_intel, inline_intel);

    // Generate findings from intel
    findings.extend(intel_to_findings(&all_intel, target));

    findings
}

/// Detect frontend framework from HTML
fn detect_framework(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    if lower.contains("__next_data__") || lower.contains("_next/static") {
        Some("Next.js".to_string())
    } else if lower.contains("__nuxt") || lower.contains("_nuxt/") {
        Some("Nuxt.js".to_string())
    } else if lower.contains("data-reactroot") || lower.contains("react.production") {
        Some("React".to_string())
    } else if lower.contains("data-v-") || lower.contains("vue.runtime") {
        Some("Vue.js".to_string())
    } else if lower.contains("ng-version") || lower.contains("angular") {
        Some("Angular".to_string())
    } else if lower.contains("svelte-") {
        Some("Svelte".to_string())
    } else if lower.contains("astro-island") {
        Some("Astro".to_string())
    } else if lower.contains("__remixcontext") {
        Some("Remix".to_string())
    } else {
        None
    }
}

/// Extract JS bundle URLs from HTML
fn extract_js_urls(html: &str, base: &str) -> Vec<String> {
    let mut urls = HashSet::new();
    let re = Regex::new(r#"(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']"#).unwrap();

    for cap in re.captures_iter(html) {
        if let Some(src) = cap.get(1) {
            let s = src.as_str().trim();
            if s.starts_with("http") {
                urls.insert(s.to_string());
            } else if s.starts_with('/') {
                urls.insert(format!("{}{}", base, s));
            } else if !s.starts_with("data:") {
                urls.insert(format!("{}/{}", base, s));
            }
        }
    }

    urls.into_iter().collect()
}

/// Deep-parse a JS bundle for hidden intelligence
fn parse_js_bundle(js: &str) -> JsIntel {
    let mut intel = JsIntel::default();

    // API routes: /api/*, /v1/*, /v2/*, /graphql, /rest/*
    let api_re = Regex::new(r#""(/(?:api|v[0-9]+|rest|graphql|internal|admin|auth|oauth|webhook)[^"]*)""#).unwrap();
    for cap in api_re.captures_iter(js) {
        if let Some(m) = cap.get(1) {
            let path = m.as_str();
            if path.len() > 3 && path.len() < 100 {
                if path.contains("admin") || path.contains("internal") {
                    intel.admin_paths.push(path.to_string());
                } else if path.contains("auth") || path.contains("oauth") || path.contains("login") {
                    intel.auth_endpoints.push(path.to_string());
                } else if path.contains("graphql") {
                    intel.graphql_endpoints.push(path.to_string());
                } else {
                    intel.api_routes.push(path.to_string());
                }
            }
        }
    }

    // Internal paths: /_internal, /debug, /metrics, /health, /status
    let internal_re = Regex::new(r#""(/(?:_internal|_debug|_admin|debug|metrics|health|status|actuator|swagger|docs|redoc|openapi)[^"]*)""#).unwrap();
    for cap in internal_re.captures_iter(js) {
        if let Some(m) = cap.get(1) {
            let path = m.as_str();
            if path.len() > 3 && path.len() < 80 {
                intel.internal_paths.push(path.to_string());
            }
        }
    }

    // Environment variables: process.env.*, import.meta.env.*, NEXT_PUBLIC_*
    let env_re = Regex::new(r#"(?:process\.env\.|import\.meta\.env\.)([A-Z_][A-Z0-9_]+)"#).unwrap();
    for cap in env_re.captures_iter(js) {
        if let Some(m) = cap.get(1) {
            let var = m.as_str();
            if var.len() > 3 && var.len() < 50 {
                intel.env_vars.push(var.to_string());
            }
        }
    }
    let next_env_re = Regex::new(r#"(NEXT_PUBLIC_[A-Z_]+)"#).unwrap();
    for cap in next_env_re.captures_iter(js) {
        if let Some(m) = cap.get(1) {
            intel.env_vars.push(m.as_str().to_string());
        }
    }

    // WebSocket URLs: ws://, wss://
    let ws_re = Regex::new(r#"(wss?://[^"'\s]+)"#).unwrap();
    for cap in ws_re.captures_iter(js) {
        if let Some(m) = cap.get(1) {
            intel.websocket_urls.push(m.as_str().to_string());
        }
    }

    // Source map references
    let sm_re = Regex::new(r#"sourceMappingURL\s*=\s*([^\s]+\.map)"#).unwrap();
    for cap in sm_re.captures_iter(js) {
        if let Some(m) = cap.get(1) {
            intel.source_maps.push(m.as_str().to_string());
        }
    }

    // Deduplicate
    intel.api_routes.sort();
    intel.api_routes.dedup();
    intel.internal_paths.sort();
    intel.internal_paths.dedup();
    intel.env_vars.sort();
    intel.env_vars.dedup();
    intel.admin_paths.sort();
    intel.admin_paths.dedup();
    intel.auth_endpoints.sort();
    intel.auth_endpoints.dedup();
    intel.graphql_endpoints.sort();
    intel.graphql_endpoints.dedup();
    intel.websocket_urls.sort();
    intel.websocket_urls.dedup();

    intel
}

/// Parse inline <script> blocks
fn parse_inline_scripts(html: &str) -> JsIntel {
    let mut intel = JsIntel::default();
    let re = Regex::new(r#"<script[^>]*>([\s\S]*?)</script>"#).unwrap();

    for cap in re.captures_iter(html) {
        if let Some(script) = cap.get(1) {
            let content = script.as_str();
            if content.len() > 50 {
                let partial = parse_js_bundle(content);
                merge_intel(&mut intel, partial);
            }
        }
    }

    intel
}

fn merge_intel(target: &mut JsIntel, source: JsIntel) {
    target.api_routes.extend(source.api_routes);
    target.internal_paths.extend(source.internal_paths);
    target.env_vars.extend(source.env_vars);
    target.source_maps.extend(source.source_maps);
    target.graphql_endpoints.extend(source.graphql_endpoints);
    target.websocket_urls.extend(source.websocket_urls);
    target.auth_endpoints.extend(source.auth_endpoints);
    target.admin_paths.extend(source.admin_paths);
}

/// Convert extracted intel to findings
fn intel_to_findings(intel: &JsIntel, target: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Admin/internal paths discovered
    if !intel.admin_paths.is_empty() {
        findings.push(
            Finding::new(Severity::Medium, "JS-DEEP", &format!("{} admin/internal paths found in JS", intel.admin_paths.len()), target)
                .with_evidence(&intel.admin_paths.iter().take(10).cloned().collect::<Vec<_>>().join(", "))
                .with_note("Admin paths exposed in client-side JS — test for access control")
                .with_confidence(70),
        );
    }

    // Internal/debug paths
    if !intel.internal_paths.is_empty() {
        findings.push(
            Finding::new(Severity::Low, "JS-DEEP", &format!("{} internal/debug paths in JS", intel.internal_paths.len()), target)
                .with_evidence(&intel.internal_paths.iter().take(10).cloned().collect::<Vec<_>>().join(", "))
                .with_confidence(60),
        );
    }

    // API routes discovered
    if intel.api_routes.len() > 5 {
        findings.push(
            Finding::new(Severity::Info, "JS-DEEP", &format!("{} API routes discovered in JS bundles", intel.api_routes.len()), target)
                .with_evidence(&intel.api_routes.iter().take(15).cloned().collect::<Vec<_>>().join(", "))
                .with_confidence(65),
        );
    }

    // Environment variables leaked
    let sensitive_envs: Vec<&String> = intel.env_vars.iter()
        .filter(|v| {
            let upper = v.to_uppercase();
            upper.contains("SECRET") || upper.contains("KEY") || upper.contains("TOKEN")
                || upper.contains("PASSWORD") || upper.contains("API") || upper.contains("AUTH")
        })
        .collect();

    if !sensitive_envs.is_empty() {
        findings.push(
            Finding::new(Severity::Medium, "JS-DEEP", &format!("{} sensitive env vars referenced in JS", sensitive_envs.len()), target)
                .with_evidence(&sensitive_envs.iter().take(10).map(|s| s.as_str()).collect::<Vec<_>>().join(", "))
                .with_note("Client-side env vars may leak sensitive config names")
                .with_confidence(55),
        );
    }

    // GraphQL endpoints
    if !intel.graphql_endpoints.is_empty() {
        findings.push(
            Finding::new(Severity::Low, "JS-DEEP", "GraphQL endpoint found in JS", target)
                .with_evidence(&intel.graphql_endpoints.join(", "))
                .with_note("Test introspection: POST {__schema{types{name}}}")
                .with_confidence(75),
        );
    }

    // WebSocket URLs
    if !intel.websocket_urls.is_empty() {
        findings.push(
            Finding::new(Severity::Info, "JS-DEEP", "WebSocket URLs found in JS", target)
                .with_evidence(&intel.websocket_urls.join(", "))
                .with_confidence(70),
        );
    }

    // Source maps available
    if !intel.source_maps.is_empty() {
        findings.push(
            Finding::new(Severity::Medium, "JS-DEEP", "Source maps referenced — may expose full source code", target)
                .with_evidence(&intel.source_maps.join(", "))
                .with_note("Download .map files to get original unminified source code")
                .with_confidence(80),
        );
    }

    // Framework detection
    if let Some(fw) = &intel.framework {
        findings.push(
            Finding::new(Severity::Info, "JS-DEEP", &format!("Framework detected: {}", fw), target)
                .with_confidence(90),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_nextjs() {
        assert_eq!(detect_framework("<script id=\"__NEXT_DATA__\">"), Some("Next.js".to_string()));
    }

    #[test]
    fn detect_react() {
        assert_eq!(detect_framework("<div data-reactroot>"), Some("React".to_string()));
    }

    #[test]
    fn detect_none() {
        assert_eq!(detect_framework("<html><body>hello</body></html>"), None);
    }

    #[test]
    fn extract_js_urls_basic() {
        let html = r#"<script src="/static/app.js"></script><script src="https://cdn.com/lib.js"></script>"#;
        let urls = extract_js_urls(html, "https://example.com");
        assert!(urls.contains(&"https://example.com/static/app.js".to_string()));
        assert!(urls.contains(&"https://cdn.com/lib.js".to_string()));
    }

    #[test]
    fn parse_api_routes() {
        let js = r#"fetch("/api/users/1"); fetch("/v1/orders"); fetch("/graphql");"#;
        let intel = parse_js_bundle(js);
        assert!(!intel.api_routes.is_empty() || !intel.graphql_endpoints.is_empty());
    }

    #[test]
    fn parse_admin_paths() {
        let js = r#"const x = "/admin/dashboard"; const y = "/internal/metrics";"#;
        let intel = parse_js_bundle(js);
        assert!(!intel.admin_paths.is_empty() || !intel.internal_paths.is_empty());
    }

    #[test]
    fn parse_env_vars() {
        let js = r#"process.env.NEXT_PUBLIC_API_KEY; process.env.SECRET_TOKEN; import.meta.env.VITE_API_URL;"#;
        let intel = parse_js_bundle(js);
        assert!(intel.env_vars.len() >= 2);
    }

    #[test]
    fn parse_websocket() {
        let js = r#"const ws = new WebSocket("wss://realtime.example.com/socket");"#;
        let intel = parse_js_bundle(js);
        assert_eq!(intel.websocket_urls.len(), 1);
    }

    #[test]
    fn parse_sourcemap() {
        let js = "var x=1;\n//# sourceMappingURL=app.js.map";
        let intel = parse_js_bundle(js);
        assert_eq!(intel.source_maps.len(), 1);
    }

    #[test]
    fn intel_to_findings_admin() {
        let intel = JsIntel {
            admin_paths: vec!["/admin/users".to_string(), "/admin/settings".to_string()],
            ..Default::default()
        };
        let findings = intel_to_findings(&intel, "https://a.com");
        assert!(findings.iter().any(|f| f.title.contains("admin")));
    }

    #[test]
    fn dedup_works() {
        let js = r#""/api/users"; "/api/users"; "/api/users";"#;
        let intel = parse_js_bundle(js);
        let count = intel.api_routes.iter().filter(|r| *r == "/api/users").count();
        assert!(count <= 1);
    }
}
