use crate::http::HttpClient;
use crate::types::Finding;
use anyhow::Result;
use std::collections::HashMap;

/// Recon: discover subdomains (crt.sh) + crawl params from a target page.
pub struct Recon<'a> {
    pub http: &'a HttpClient,
}

impl<'a> Recon<'a> {
    pub fn new(http: &'a HttpClient) -> Self {
        Recon { http }
    }

    /// Passive subdomain enumeration via crt.sh certificate transparency.
    pub async fn subdomains(&self, domain: &str) -> Result<Vec<String>> {
        let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
        let mut subs = std::collections::HashSet::new();
        if let Ok((_st, _h, body, _f)) = self.http.get(&url).await {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                if let Some(arr) = v.as_array() {
                    for e in arr {
                        if let Some(name) = e.get("name_value").and_then(|n| n.as_str()) {
                            for part in name.split('\n') {
                                let p = part.trim().to_string();
                                if p.contains(domain) {
                                    subs.insert(p);
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(subs.into_iter().collect())
    }

    /// Crawl a page, extract forms + URLs with query parameters.
    pub async fn discover_params(&self, url: &str) -> Result<Vec<(String, Vec<String>)>> {
        let mut results = Vec::new();
        if let Ok((_st, _h, body, _f)) = self.http.get(url).await {
            // query params from links
            let re = regex::Regex::new(r#"href=["']([^"']+)["']"#).unwrap();
            for cap in re.captures_iter(&body) {
                if let Some(link) = cap.get(1) {
                    let l = link.as_str();
                    if let Ok(u) = url::Url::parse(l) {
                        let q: Vec<String> = u.query_pairs().map(|(k, _)| k.to_string()).collect();
                        if !q.is_empty() {
                            results.push((l.to_string(), q));
                        }
                    } else if l.starts_with('/') {
                        // relative link — skip param extraction for now
                        let abs = format!("{}{}", base_host(url), l);
                        results.push((abs, vec![]));
                    }
                }
            }
            // form inputs
            let fre = regex::Regex::new(r#"<input[^>]*name=["']([^"']+)["'][^>]*>"#).unwrap();
            let mut inputs = Vec::new();
            for cap in fre.captures_iter(&body) {
                if let Some(n) = cap.get(1) {
                    inputs.push(n.as_str().to_string());
                }
            }
            if !inputs.is_empty() {
                results.push((url.to_string(), inputs));
            }
        }
        Ok(results)
    }
}

fn base_host(url: &str) -> String {
    if let Ok(u) = url::Url::parse(url) {
        format!("{}://{}", u.scheme(), u.host_str().unwrap_or(""))
    } else {
        url.to_string()
    }
}

/// Convenience: run full recon and emit informational findings.
pub async fn run_recon(http: &HttpClient, target: &str) -> Result<Vec<Finding>> {
    let recon = Recon::new(http);
    let mut findings = Vec::new();
    if let Ok(subs) = recon.subdomains(target).await {
        for s in &subs {
            findings.push(
                Finding::new(crate::types::Severity::Info, "RECON", "Subdomain discovered", s)
                    .with_note("via crt.sh certificate transparency"),
            );
        }
    }
    if let Ok(params) = recon.discover_params(target).await {
        for (u, ps) in params {
            findings.push(
                Finding::new(crate::types::Severity::Info, "RECON", "Parameters discovered", &u)
                    .with_payload(&ps.join(","))
                    .with_note("crawl-based param discovery"),
            );
        }
    }
    Ok(findings)
}

#[allow(dead_code)]
fn _unused(_: HashMap<String, String>) {}
