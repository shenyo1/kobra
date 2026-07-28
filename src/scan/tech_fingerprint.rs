//! Tech Fingerprinting — detect frameworks, CMS, servers, JS libs from
//! response headers, HTML patterns, cookies, and JS content.
//! Wappalyzer-style detection without external database.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};

#[derive(Debug, Clone)]
pub struct TechSignature {
    pub name: &'static str,
    pub category: &'static str,
    pub header_pattern: Option<(&'static str, &'static str)>,
    pub html_pattern: Option<&'static str>,
    pub cookie_pattern: Option<&'static str>,
    pub js_pattern: Option<&'static str>,
    pub severity: Severity,
}

const SIGNATURES: &[TechSignature] = &[
    // Web Servers
    TechSignature { name: "nginx", category: "Server", header_pattern: Some(("server", "nginx")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Apache", category: "Server", header_pattern: Some(("server", "apache")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "IIS", category: "Server", header_pattern: Some(("server", "microsoft-iis")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Caddy", category: "Server", header_pattern: Some(("server", "caddy")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "LiteSpeed", category: "Server", header_pattern: Some(("server", "litespeed")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Gunicorn", category: "Server", header_pattern: Some(("server", "gunicorn")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "uvicorn", category: "Server", header_pattern: Some(("server", "uvicorn")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },

    // CDN / WAF
    TechSignature { name: "Cloudflare", category: "CDN/WAF", header_pattern: Some(("server", "cloudflare")), html_pattern: None, cookie_pattern: Some("__cfduid"), js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Akamai", category: "CDN/WAF", header_pattern: Some(("x-akamai-request-id", "")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Vercel", category: "CDN", header_pattern: Some(("server", "vercel")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Netlify", category: "CDN", header_pattern: Some(("server", "netlify")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },

    // Frameworks
    TechSignature { name: "Next.js", category: "Framework", header_pattern: Some(("x-powered-by", "next.js")), html_pattern: Some("__next"), cookie_pattern: None, js_pattern: Some("__NEXT_DATA__"), severity: Severity::Info },
    TechSignature { name: "Nuxt.js", category: "Framework", header_pattern: None, html_pattern: Some("__nuxt"), cookie_pattern: None, js_pattern: Some("__NUXT__"), severity: Severity::Info },
    TechSignature { name: "React", category: "Framework", header_pattern: None, html_pattern: Some("data-reactroot"), cookie_pattern: None, js_pattern: Some("react.production"), severity: Severity::Info },
    TechSignature { name: "Vue.js", category: "Framework", header_pattern: None, html_pattern: Some("data-v-"), cookie_pattern: None, js_pattern: Some("vue.runtime"), severity: Severity::Info },
    TechSignature { name: "Angular", category: "Framework", header_pattern: None, html_pattern: Some("ng-version"), cookie_pattern: None, js_pattern: Some("angular"), severity: Severity::Info },
    TechSignature { name: "Svelte", category: "Framework", header_pattern: None, html_pattern: Some("svelte-"), cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Astro", category: "Framework", header_pattern: None, html_pattern: Some("astro-island"), cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Remix", category: "Framework", header_pattern: None, html_pattern: Some("__remixContext"), cookie_pattern: None, js_pattern: None, severity: Severity::Info },

    // Backend
    TechSignature { name: "Express.js", category: "Backend", header_pattern: Some(("x-powered-by", "express")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "PHP", category: "Backend", header_pattern: Some(("x-powered-by", "php")), html_pattern: None, cookie_pattern: Some("phpsessid"), js_pattern: None, severity: Severity::Info },
    TechSignature { name: "ASP.NET", category: "Backend", header_pattern: Some(("x-powered-by", "asp.net")), html_pattern: None, cookie_pattern: Some("asp.net_sessionid"), js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Django", category: "Backend", header_pattern: None, html_pattern: None, cookie_pattern: Some("csrftoken"), js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Flask", category: "Backend", header_pattern: Some(("server", "werkzeug")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "FastAPI", category: "Backend", header_pattern: None, html_pattern: Some("fastapi"), cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Spring Boot", category: "Backend", header_pattern: None, html_pattern: Some("spring"), cookie_pattern: Some("jsessionid"), js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Ruby on Rails", category: "Backend", header_pattern: Some(("x-powered-by", "phusion")), html_pattern: None, cookie_pattern: Some("_session_id"), js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Laravel", category: "Backend", header_pattern: None, html_pattern: None, cookie_pattern: Some("laravel_session"), js_pattern: None, severity: Severity::Info },

    // CMS
    TechSignature { name: "WordPress", category: "CMS", header_pattern: None, html_pattern: Some("wp-content"), cookie_pattern: Some("wordpress_logged_in"), js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Drupal", category: "CMS", header_pattern: Some(("x-drupal-cache", "")), html_pattern: Some("drupal.settings"), cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Joomla", category: "CMS", header_pattern: None, html_pattern: Some("joomla"), cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Shopify", category: "CMS", header_pattern: Some(("x-shopid", "")), html_pattern: Some("shopify"), cookie_pattern: Some("_shopify"), js_pattern: None, severity: Severity::Info },

    // API / Auth
    TechSignature { name: "GraphQL", category: "API", header_pattern: None, html_pattern: Some("graphql"), cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Supabase", category: "API", header_pattern: None, html_pattern: Some("supabase"), cookie_pattern: None, js_pattern: Some("supabase"), severity: Severity::Info },
    TechSignature { name: "Firebase", category: "API", header_pattern: None, html_pattern: Some("firebase"), cookie_pattern: None, js_pattern: Some("firebase"), severity: Severity::Info },
    TechSignature { name: "Auth0", category: "Auth", header_pattern: None, html_pattern: Some("auth0"), cookie_pattern: None, js_pattern: Some("auth0"), severity: Severity::Info },

    // Security
    TechSignature { name: "ModSecurity", category: "WAF", header_pattern: Some(("server", "modsecurity")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
    TechSignature { name: "Sucuri", category: "WAF", header_pattern: Some(("x-sucuri-id", "")), html_pattern: None, cookie_pattern: None, js_pattern: None, severity: Severity::Info },
];

/// Detect technologies from a target
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut detected: Vec<String> = Vec::new();

    // Fetch main page
    let (st, headers, body, _f) = match http.get(target).await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let headers_lower = headers.to_lowercase();
    let body_lower = body.to_lowercase();

    for sig in SIGNATURES {
        let mut matched = false;

        // Header check
        if let Some((hname, hval)) = sig.header_pattern {
            for line in headers_lower.lines() {
                if line.starts_with(&format!("{}:", hname)) {
                    if hval.is_empty() || line.contains(hval) {
                        matched = true;
                        break;
                    }
                }
            }
        }

        // HTML check
        if !matched {
            if let Some(pat) = sig.html_pattern {
                if body_lower.contains(pat) {
                    matched = true;
                }
            }
        }

        // Cookie check
        if !matched {
            if let Some(pat) = sig.cookie_pattern {
                if headers_lower.contains(pat) {
                    matched = true;
                }
            }
        }

        // JS check (in body for inline scripts)
        if !matched {
            if let Some(pat) = sig.js_pattern {
                if body_lower.contains(pat) {
                    matched = true;
                }
            }
        }

        if matched && !detected.contains(&sig.name.to_string()) {
            detected.push(sig.name.to_string());
        }
    }

    // Report detected technologies
    if !detected.is_empty() {
        findings.push(
            Finding::new(Severity::Info, "TECH", &format!("Detected {} technologies", detected.len()), target)
                .with_evidence(&detected.join(", "))
                .with_confidence(80),
        );

        // Security-relevant findings
        for tech in &detected {
            match tech.as_str() {
                "WordPress" => {
                    findings.push(
                        Finding::new(Severity::Low, "TECH", "WordPress detected — check wp-login.php, xmlrpc.php, wp-json", target)
                            .with_note("Common attack surface: /wp-login.php, /xmlrpc.php, /wp-json/wp/v2/users")
                            .with_confidence(70),
                    );
                }
                "PHP" => {
                    findings.push(
                        Finding::new(Severity::Low, "TECH", "PHP detected — check for exposed phpinfo, .env", target)
                            .with_note("Check /phpinfo.php, /.env, /server-status")
                            .with_confidence(50),
                    );
                }
                "GraphQL" => {
                    findings.push(
                        Finding::new(Severity::Low, "TECH", "GraphQL detected — test introspection", target)
                            .with_note("Try POST /graphql with {__schema{types{name}}}")
                            .with_confidence(60),
                    );
                }
                "Supabase" => {
                    findings.push(
                        Finding::new(Severity::Medium, "TECH", "Supabase detected — check RLS policies + anon key", target)
                            .with_note("Extract anon key from JS, test RLS bypass on REST API")
                            .with_confidence(70),
                    );
                }
                "Express.js" => {
                    findings.push(
                        Finding::new(Severity::Info, "TECH", "Express.js detected — X-Powered-By header leaks framework", target)
                            .with_note("Consider disabling X-Powered-By header")
                            .with_confidence(80),
                    );
                }
                _ => {}
            }
        }
    }

    // Check X-Powered-By disclosure
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("x-powered-by:") {
            findings.push(
                Finding::new(Severity::Low, "TECH", "X-Powered-By header discloses technology", target)
                    .with_evidence(line.trim())
                    .with_note("Remove or obfuscate X-Powered-By header")
                    .with_confidence(90),
            );
            break;
        }
    }

    let _ = st;
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signatures_non_empty() {
        assert!(SIGNATURES.len() > 30);
    }
    #[test]
    fn categories_covered() {
        let cats: Vec<&str> = SIGNATURES.iter().map(|s| s.category).collect();
        assert!(cats.contains(&"Server"));
        assert!(cats.contains(&"Framework"));
        assert!(cats.contains(&"CMS"));
        assert!(cats.contains(&"CDN/WAF"));
    }
}
