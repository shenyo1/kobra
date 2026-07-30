//! Vulnerability scan modules. Each returns ALL findings (no hiding).
//! Aggressive ("crazy") mode multiplies payload counts + triggers bypass attempts.

use crate::http::HttpClient;
use crate::types::{Finding, Mode};
use anyhow::Result;

pub mod xss;
pub mod sqli;
pub mod ssrf;
pub mod auth;
pub mod waf;
pub mod traversal;
pub mod rce;
pub mod graphql;
pub mod proto;
pub mod nosql;
pub mod xxe;
pub mod cors;
pub mod ssti;
pub mod deser;
pub mod ws;
pub mod authflow;   // magic-link / OTP pre-auth ATO
pub mod multitenant; // tenant isolation / cross-tenant leak
pub mod ssrf_oob;   // blind SSRF OOB callback proof
pub mod research2026; // 2026 research enrichment (cf-error, magic-link hijack, graphql batch)
pub mod aioob;      // AI prompt injection / system-prompt disclosure (P1: ai.sumopod.com)
pub mod wordlist;   // wordlist-driven path/param fuzz (v4.7.0)
pub mod repeater;   // Burp-style Repeater/Intruder (v4.7.0)
pub mod graphql_deep; // GraphQL introspection + alias amplification + batch (v4.7.0)
pub mod websocket_v2; // WS handshake probe + frame encode/decode + CSWSH hint (v4.7.0)
pub mod smuggle;    // HTTP request smuggling / CL-TE desync (Kong CVE-2026-6338)
pub mod origin_disc; // Cloudflare origin IP discovery (crt.sh historical certs)
pub mod payment;    // Payment logic / IDOR (price tamper, payment_method_id swap)
pub mod email_ato;  // Email-only-login Mass ATO detector (wibuku.app pattern)
pub mod ip_ban_bypass; // IP ban bypass via header spoofing (sankavollerei.web.id pattern)
pub mod js_secret_mine; // Hardcoded secrets in JS bundles (API keys, JWT, AWS, Stripe)
pub mod jwt;           // JWT exploit (alg:none, weak secret, RS256 confusion)
pub mod oauth;         // OAuth 2.0 / OIDC flow tester (redirect_uri, PKCE, scope)
pub mod dom_xss;       // DOM XSS sink/source detection (static JS analysis)
pub mod race;          // Race condition / TOCTOU engine
pub mod takeover;      // Subdomain takeover (CNAME dangling)
pub mod exposed_files; // Sensitive file exposure (.env, .git, backups)
pub mod source_map;    // Source map leak detection
pub mod smuggle_v2;    // HTTP request smuggling v2 (CL.TE/TE.CL timing)
pub mod cve_2026;      // CVE-specific detection (Log4Shell, Spring4Shell, Fortinet, etc.)
pub mod header_trust;  // IP-spoof header trust detector (CF-Connecting-IP, X-Forwarded-For, etc.)
pub mod parallel;      // Multi-target parallel scanning
pub mod checkpoint;    // Resume from checkpoint after crash
pub mod plugin;        // Hot-load custom scan modules from JSON
pub mod api_discovery; // API endpoint enumeration + OpenAPI/Swagger discovery
pub mod cors_deep;     // CORS deep scanner (wildcard, reflection, preflight)
pub mod headless;      // Headless browser — DOM XSS, SPA crawl, JS execution
pub mod crawler;       // Basic crawler — JS endpoints, sitemap, robots, links
pub mod waf_learn;     // WAF Learning Mode — detect + bypass suggestions
pub mod tech_fingerprint; // Tech fingerprinting — detect frameworks/CMS/servers
pub mod stack_fingerprint; // v4.2.0: Stack fingerprint — SPA/server/API style (fixes generic-payload FP)
pub mod auth_aware;       // v4.3.0: Auth-aware probing — expand paths when --auth configured
pub mod cloudflare_ranges; // v4.4.0: Cloudflare IP detection — filter takeover FPs (Lesson 1)
pub mod ai_gateway;        // v4.4.0: AI gateway detector — LiteLLM/vLLM/OpenAI (Lesson 4)
pub mod dns_pivot;         // v4.4.0: DNS pivot — group subdomains by IP, probe direct origins (Lesson 3)
pub mod auth_flow;        // v4.4.0: Auth flow detector — JWT/cookie/Basic/OAuth/API-key (Lesson 2)
pub mod idor;          // Multi-session IDOR testing — compare two auth sessions
pub mod fuzz;          // Wordlist fuzzing — ffuf-style path + param fuzzing
pub mod passive;       // Passive proxy mode — analyze traffic without active probes
pub mod js_deep;       // JS Deep Analysis — webpack/vite bundle parse, hidden routes
pub mod api_schema_fuzz; // API Schema Fuzzing — OpenAPI auto-generate test cases
pub mod rate_bypass;    // Rate limit bypass engine — IP/method/path/encoding tricks
pub mod postgrest;    // PostgREST / Supabase table disclosure scanner

/// Run all enabled modules against a single URL with a set of parameters.
/// `oob_host` enables blind-SSRF callback testing (your listener/collaborator).
/// `plugins` are hot-loaded JSON plugin modules.
/// `templates` are YAML/JSON template-based checks.
pub async fn run_all(
    http: &HttpClient,
    target: &str,
    params: &[String],
    mode: Mode,
    oob_host: &str,
    plugins: &[crate::scan::plugin::Plugin],
    templates: &[crate::engine::template::Template],
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    // Fix v4.3.0: stack fingerprint FIRST — downstream modules pick stack-aware payloads.
    let stack = stack_fingerprint::fingerprint(http, target).await;
    if !stack.framework_hint.is_empty() {
        eprintln!("[*] stack fingerprint: {}", stack.framework_hint);
    }
    let mut ps: Vec<String> = if params.is_empty() {
        vec!["q".to_string(), "id".to_string(), "search".to_string(), "url".to_string(),
             "file".to_string(), "input".to_string(), "redirect".to_string(), "next".to_string()]
    } else {
        params.to_vec()
    };
    // Always include baseline params so reflection checks run even when caller
    // passes extra (crazy) params.
    for base in ["q","id","search","url","redirect","next"] {
        if !ps.iter().any(|x| x == base) {
            ps.push(base.to_string());
        }
    }

    findings.extend(xss::scan(http, target, &ps, mode).await?);
    findings.extend(sqli::scan(http, target, &ps, mode).await?);
    findings.extend(ssrf::scan(http, target, &ps, mode).await?);
    findings.extend(ssrf_oob::scan(http, target, &ps, mode, oob_host).await?);
    findings.extend(traversal::scan(http, target, &ps, mode).await?);
    findings.extend(rce::scan(http, target, &ps, mode).await?);
    findings.extend(nosql::scan(http, target, &ps, mode).await?);
    findings.extend(ssti::scan(http, target, &ps, mode).await?);
    findings.extend(xxe::scan(http, target, mode).await?);
    findings.extend(auth::scan(http, target, mode).await?);
    findings.extend(authflow::scan(http, target, mode).await?);
    findings.extend(graphql::scan(http, target, mode).await?);
    findings.extend(proto::scan(http, target, mode).await?);
    findings.extend(cors::scan(http, target, mode).await?);
    findings.extend(ws::scan(http, target, mode).await?);
    findings.extend(deser::scan(http, target, mode).await?);
    findings.extend(multitenant::scan(http, target, mode).await?);
    findings.extend(waf::scan(http, target, mode).await?);
    findings.extend(waf_learn::scan(http, target, mode).await);
    findings.extend(tech_fingerprint::scan(http, target, mode).await);
    findings.extend(fuzz::fuzz_paths(http, target, None, mode).await);
    findings.extend(fuzz::fuzz_params(http, target, None, mode).await);
    findings.extend(js_deep::scan(http, target, mode).await);
    findings.extend(api_schema_fuzz::scan(http, target, mode).await);
    findings.extend(research2026::scan(http, target, mode).await?);
    findings.extend(aioob::scan(http, target, mode).await?);
    findings.extend(smuggle::scan(http, target, mode).await?);
    findings.extend(origin_disc::scan(http, target, mode).await?);
    findings.extend(payment::scan(http, target, mode).await?);
    findings.extend(email_ato::scan(http, target, mode).await?);
    findings.extend(ip_ban_bypass::scan(http, target, mode).await);
    findings.extend(js_secret_mine::scan(http, target, mode).await);
    findings.extend(jwt::scan(http, target, mode).await);
    findings.extend(oauth::scan(http, target, mode).await);
    findings.extend(dom_xss::scan(http, target, mode).await);
    findings.extend(race::scan(http, target, mode).await);
    findings.extend(takeover::scan(http, target, mode).await);
    findings.extend(exposed_files::scan(http, target, mode).await);
    findings.extend(source_map::scan(http, target, mode).await);
    findings.extend(smuggle_v2::scan(http, target, mode).await);
    findings.extend(cve_2026::scan(http, target, mode).await);
    findings.extend(header_trust::scan(http, target, mode).await);
    findings.extend(api_discovery::scan(http, target, mode).await?);
    findings.extend(auth_aware::scan(http, target, mode).await);
    findings.extend(ai_gateway::scan(http, target, mode).await);
    findings.extend(dns_pivot::scan(http, target, mode).await);
    findings.extend(auth_flow::scan(http, target, mode).await);
    findings.extend(cors_deep::scan(http, target, mode).await?);
    // Plugin modules
    findings.extend(plugin::scan_with_plugins(http, target, plugins).await);
    // Template-based checks
    findings.extend(crate::engine::template::run_templates(http, target, templates, mode).await);
    // Crawler: discover endpoints + add as findings
    let discovered = crawler::discover_endpoints(http, target, mode).await;
    findings.extend(crawler::findings_from_endpoints(&discovered, target));
    // Feed discovered endpoints into extra params for deeper scan
    for ep in &discovered {
        if let Some(path) = ep.split("://").nth(1).and_then(|p| p.split('/').nth(1)) {
            // Add path segments as potential params
            for segment in path.split('/') {
                if !segment.is_empty() && !ps.contains(&segment.to_string()) && segment.len() < 30 {
                    ps.push(segment.to_string());
                }
            }
        }
    }
    Ok(findings)
}

/// Run headless browser scan (separate because it needs Chrome).
pub async fn run_headless(target: &str, mode: Mode) -> Vec<Finding> {
    headless::scan_dom_xss(target, mode).await
}
