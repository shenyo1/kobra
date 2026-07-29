//! DNS Pivot module (Lesson 3 fix v4.4.0).
//! Lesson: KOBRA v4.3.0 scanned sumopod.com but missed ai.sumopod.com (LiteLLM).
//! Both belong to same company but on DIFFERENT IPs/infrastructure.
//! Fix: DNS pivot — discover all subdomains, group by IP, probe each separately.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use std::collections::HashMap;
use std::process::Command;

const SUB_PATTERNS: &[&str] = &[
    "www", "api", "app", "cdn", "staging", "dev", "test",
    "admin", "dashboard", "internal", "private",
    "auth", "login", "oauth", "sso",
    "ai", "ml", "llm", "gpt", "chat", "bot",
    "static", "assets", "media", "img", "images",
    "mail", "smtp", "imap", "webmail",
    "blog", "docs", "help", "support", "status",
    "db", "mysql", "postgres", "redis", "mongo",
    "v1", "v2", "v3", "old", "new", "beta",
    "git", "gitolite", "gitlab", "github",
    "monitor", "grafana", "prometheus",
];

#[derive(Debug, Clone)]
pub struct HostnameGroup {
    pub ip: String,
    pub hosts: Vec<String>,
}

/// Resolve a hostname to A records via dig.
pub fn resolve_a(host: &str) -> Vec<String> {
    let output = Command::new("dig")
        .args(&["+short", host, "A"])
        .output();
    match output {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            s.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
        }
        Err(_) => vec![],
    }
}

/// Enumerate common subdomain patterns + base domain.
pub fn enumerate_subdomains(domain: &str) -> Vec<String> {
    let mut subs = vec![domain.to_string()];
    for p in SUB_PATTERNS {
        subs.push(format!("{}.{}", p, domain));
    }
    subs
}

/// Group subdomains by IP — find infrastructure clusters.
pub async fn pivot(domain: &str) -> Vec<HostnameGroup> {
    let subs = enumerate_subdomains(domain);
    let mut groups: HashMap<String, Vec<String>> = HashMap::new();
    for sub in &subs {
        let ips = resolve_a(sub);
        for ip in ips {
            groups.entry(ip).or_default().push(sub.clone());
        }
    }
    groups.into_iter()
        .map(|(ip, hosts)| HostnameGroup { ip, hosts })
        .collect()
}

pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let domain = target.split("://").nth(1).unwrap_or(target).split('/').next().unwrap_or(target);
    let base_domain = domain.split('.').rev().take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(".");

    // Pivot all subdomains
    let groups = pivot(&base_domain).await;

    // Find DIRECT_ORIGIN clusters (not Cloudflare, not CDN)
    let direct_origins: Vec<HostnameGroup> = groups.into_iter()
        .filter(|g| !crate::scan::cloudflare_ranges::is_cloudflare(&g.ip))
        .collect();

    if !direct_origins.is_empty() {
        findings.push(Finding {
            severity: Severity::Info,
            category: "DNS-PIVOT".into(),
            title: format!("DNS pivot: {} direct-origin clusters for {}", direct_origins.len(), base_domain),
            target: target.to_string(),
            param: None,
            payload: None,
            evidence: Some(format!(
                "Discovered {} infrastructure clusters (NOT behind Cloudflare). Each probed separately.",
                direct_origins.len()
            )),
            confidence: 95,
            note: Some("Lesson 3 fix v4.4.0: DNS pivot reveals hidden infra (e.g., ai.sumopod.com).".into()),
            request: None,
            response: None,
        });
    }

    // For each
 // For each direct-origin cluster, probe the hosts
    for group in &direct_origins {
        for host in &group.hosts {
            if host == &base_domain { continue; }
            let url = format!("https://{}", host);
            if let Ok((_st, headers, body, _f)) = http.get(&url).await {
                let server = headers.lines()
                    .find(|l| l.to_lowercase().starts_with("server:"))
                    .unwrap_or("")
                    .to_string();
                let interesting = server.contains("uvicorn")
                    || server.contains("nginx")
                    || body.contains("api key")
                    || body.contains("API endpoint");
                if interesting {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        category: "DNS-PIVOT".into(),
                        title: format!("Probe direct-origin: {} (server: {})", host, server.trim()),
                        target: url.clone(),
                        param: None,
                        payload: None,
                        evidence: Some(format!(
                            "Subdomain {} resolves to {} (not Cloudflare). Probed independently and got interesting response (server={}).",
                            host, group.ip, server.trim())),
                        confidence: 70,
                        note: Some("Lesson 3 fix v4.4.0: DNS pivot auto-probe.".into()),
                        request: None,
                        response: None,
                    });
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_has_common() {
        let subs = enumerate_subdomains("example.com");
        assert!(subs.contains(&"example.com".to_string()));
        assert!(subs.contains(&"www.example.com".to_string()));
        assert!(subs.contains(&"api.example.com".to_string()));
        assert!(subs.contains(&"admin.example.com".to_string()));
        assert!(subs.contains(&"ai.example.com".to_string()));
    }

    #[test]
    fn enumerate_count() {
        let subs = enumerate_subdomains("example.com");
        // Just verify reasonable count
        assert!(subs.len() >= 40);
    }

    #[test]
    fn resolve_a_localhost() {
        let ips = resolve_a("localhost");
        // localhost may resolve to ::1 or 127.0.0.1
        assert!(ips.is_empty() || ips.iter().any(|i| i.contains("127.0.0.1") || i.contains("::1")));
    }

    #[test]
    fn cloudflare_filter_separates_origins() {
        // Real Sumopod case: separate IPs CF vs origin
        let cf_ip = "104.26.9.76";
        let origin_ip = "103.179.67.242";
        assert!(crate::scan::cloudflare_ranges::is_cloudflare(cf_ip));
        assert!(!crate::scan::cloudflare_ranges::is_cloudflare(origin_ip));
    }
}
