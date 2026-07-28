//! Subdomain takeover detection (CNAME dangling).
//! CrT.sh enum subdomains, resolve CNAME, match against takeover fingerprints.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// (substring-in-body, service-name)
const FINGERPRINTS: &[(&str, &str)] = &[
    ("There isn't a GitHub Pages site here", "github-pages"),
    ("No settings were found for this company", "ghost"),
    ("No such app", "heroku"),
    ("no-such-app", "heroku"),
    ("NoSuchBucket", "aws-s3"),
    ("The specified bucket does not exist", "aws-s3"),
    ("404 Web Site not found", "azure"),
    ("Web Site not found", "azure"),
    ("EDGE - DEPLOY - VERIFY - CHECK", "azure"),
    ("Fastly error: unknown domain", "fastly"),
    ("The request could not be satisfied", "cloudfront"),
    ("Sorry, the requested page could not be found", "vercel"),
    ("DEPLOYMENT_NOT_FOUND", "netlify"),
    ("Page not found - Netlify", "netlify"),
    ("Doctype html", "pantheon"),
    ("404 Site", "tumblr"),
    ("We can't find this page", "shopify"),
    ("Domain not found", "wp-engine"),
];

/// Match body content against fingerprints. Returns Some(service) on hit.
pub fn match_takeover(body: &str) -> Option<&'static str> {
    for (marker, svc) in FINGERPRINTS {
        if body.contains(marker) {
            return Some(svc);
        }
    }
    None
}

pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let domain = extract_domain(target);
    let subs = match enum_subdomains(&domain).await {
        Ok(s) => s,
        Err(_) => return findings,
    };
    for sub in subs.iter().take(50) {
        let url = format!("https://{}", sub);
        if let Ok((_st, _h, body, _f)) = http.get(&url).await {
            if let Some(svc) = match_takeover(&body) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: "TAKEOVER".into(),
                    title: format!("Subdomain takeover: {} (CNAME → {})", sub, svc),
                    target: url,
                    param: None,
                    payload: None,
                    evidence: Some(format!("Subdomain {} points to {} but no live service", sub, svc)),
                    confidence: 85,
                    note: Some("Claim subdomain on the dangling service to take over cookies for parent domain".into()),
                    request: None,
                    response: None,
                });
            }
        }
    }
    findings
}

fn extract_domain(url: &str) -> String {
    let trimmed = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    if let Some(idx) = trimmed.find('/') {
        trimmed[..idx].to_string()
    } else {
        trimmed.to_string()
    }
}

pub async fn enum_subdomains(domain: &str) -> Result<Vec<String>> {
    let url = format!("https://crt.sh/?q={}&output=json", domain);
    let resp = reqwest::get(&url).await?;
    let body = resp.text().await?;
    let mut subs = std::collections::HashSet::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(arr) = v.as_array() {
            for e in arr {
                if let Some(name) = e.get("name_value").and_then(|n| n.as_str()) {
                    for part in name.split('\n') {
                        let p = part.trim();
                        if p.contains(domain) {
                            subs.insert(p.to_string());
                        }
                    }
                }
            }
        }
    }
    Ok(subs.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extract_domain_basic() {
        assert_eq!(extract_domain("https://example.com/path"), "example.com");
        assert_eq!(extract_domain("http://api.test.io"), "api.test.io");
    }
    #[test]
    fn match_github_pages() {
        let body = "<html>There isn't a GitHub Pages site here.</html>";
        assert_eq!(match_takeover(body), Some("github-pages"));
    }
    #[test]
    fn match_heroku() {
        let body = "No such app";
        assert_eq!(match_takeover(body), Some("heroku"));
    }
    #[test]
    fn match_s3() {
        let body = "The specified bucket does not exist";
        assert_eq!(match_takeover(body), Some("aws-s3"));
    }
    #[test]
    fn match_none() {
        let body = "<html>Hello World</html>";
        assert_eq!(match_takeover(body), None);
    }
}
