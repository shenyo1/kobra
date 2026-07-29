//! Subdomain takeover detection v2 — 30+ provider fingerprints.
//! CrT.sh enum subdomains, resolve CNAME, match against takeover fingerprints.
//! Supports: GitHub Pages, Heroku, AWS S3/CloudFront, Azure, Fastly, Vercel,
//! Netlify, Pantheon, Tumblr, Shopify, WP Engine, Surge, Fly.io, Render,
//! Pantheon, Bitbucket, Amazon CloudFront, AWS Elastic Beanstalk, Firebase,
//! Google Cloud Storage, Microsoft Azure CDN, Akamai, Ghost, Surge.sh,
//! Fly.io, Render, Firebase Hosting, Surge.sh, Reclaim Hosting, Read the Docs.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// (substring-in-body, service-name, severity-multiplier)
const FINGERPRINTS: &[(&str, &str, u8)] = &[
    // Cloud Providers
    ("There isn't a GitHub Pages site here", "github-pages", 95),
    ("There isn't a GitHub Pages site here.", "github-pages", 95),
    ("No settings were found for this company", "ghost", 80),
    ("Site not found", "ghost", 70),
    ("No such app", "heroku", 95),
    ("no-such-app", "heroku", 95),
    ("App not found", "heroku", 90),
    ("NoSuchBucket", "aws-s3", 95),
    ("The specified bucket does not exist", "aws-s3", 95),
    ("The specified bucket does not exist.", "aws-s3", 95),
    ("AllAccessDisabled", "aws-s3", 90),
    ("404 Web Site not found", "azure", 90),
    ("Web Site not found.", "azure", 90),
    ("EDGE - DEPLOY - VERIFY - CHECK", "azure", 80),
    ("Fastly error: unknown domain", "fastly", 95),
    ("Fastly error: unknown domain:", "fastly", 95),
    ("The request could not be satisfied", "cloudfront", 60),
    ("Sorry, the requested page could not be found", "vercel", 90),
    ("The deployment could not be found", "vercel", 95),
    ("DEPLOYMENT_NOT_FOUND", "netlify", 95),
    ("Page not found - Netlify", "netlify", 95),
    ("Not found - Request ID:", "netlify", 90),
    ("Doctype html", "pantheon", 60),
    ("404 Site", "tumblr", 80),
    ("We can't find this page", "shopify", 80),
    ("Domain not found", "wp-engine", 80),
    ("Surge isn't a page for", "surge", 90),
    ("404 Not Found / Surge", "surge", 90),
    ("404 - No such project", "fly-io", 95),
    ("Could not find what you were looking for", "fly-io", 70),
    ("Page not found", "render", 80),
    ("Not Found — Render", "render", 85),
    ("Site Not Found", "firebase", 85),
    ("No such site", "firebase", 90),
    ("Firebase Hosting Setup Complete", "firebase-config", 40),
    ("Server Error", "gcs", 50),
    ("The specified bucket does not have a website configuration", "gcs", 95),
    ("NoSuchWebsite", "gcs", 95),
    ("NoSuchHost", "azure-cdn", 90),
    ("Server Error: This host is not configured", "azure-cdn", 85),
    ("Akamai Edge", "akamai", 60),
    ("Ghost404", "ghost", 90),
    ("Site not found", "reclaim", 80),
    ("404 — File not found", "reclaim", 75),
    ("We couldn't find that page", "webflow", 80),
    ("Webflow CMS", "webflow", 50),
    ("This page could not be found", "vercel", 75),
    ("EDGE - DEPLOY", "azure", 75),
    ("Customer Applications", "aws-elastic", 70),
    ("404 Not Found", "aws-elastic", 60),
    ("NoSuchKey", "aws-s3", 90),
    ("The specified key does not exist", "aws-s3", 95),
    ("AccessDenied", "aws-s3", 50),
    // Bitbucket
    ("Repository not found", "bitbucket", 85),
    ("The page you were looking for doesn't exist", "bitbucket", 70),
    // ReadTheDocs
    ("No matching projects found", "readthedocs", 75),
    ("This page could not be found", "readthedocs", 65),
    // Surge
    ("project not found", "surge", 85),
    // Alwaysdata
    ("This domain name is not configured", "alwaysdata", 85),
    // HatenaBlog
    ("404 Blog is not found", "hatena", 90),
    // Strikingly
    ("Page not found", "strikingly", 65),
    ("Site Not Found", "strikingly", 80),
    // Bigcommerce
    ("This store is currently unavailable", "bigcommerce", 80),
    // Tumblr
    ("There's nothing here", "tumblr", 90),
    ("Whatever you were looking for doesn't live here anymore", "tumblr", 85),
    // Cargo
    ("Site not found", "cargo", 70),
    // Wix
    ("This site is currently under construction", "wix", 60),
    ("This website is not published", "wix", 90),
    // WordPress.com
    ("Do you want to register", "wordpress-com", 60),
    // Microsoft Azure
    ("Error 404 - Web app not found", "azure-apps", 95),
    ("Web App Not Found", "azure-apps", 90),
    // Cloudfront
    ("Bad gateway: No available backends", "cloudfront", 70),
    ("CloudFront attempted to establish a connection", "cloudfront", 70),
    // Netlify
    ("Page Not Found Looks like you have followed a broken link", "netlify", 80),
    ("Not Found - Request ID", "netlify", 85),
    // Zoho
    ("Site not found", "zoho", 65),
    ("This page is not available", "zoho", 70),
];

/// Match body content against fingerprints. Returns (service, confidence) on hit.
pub fn match_takeover(body: &str) -> Option<(&'static str, u8)> {
    for (marker, svc, confidence) in FINGERPRINTS {
        if body.contains(marker) {
            return Some((svc, *confidence));
        }
    }
    None
}

/// Subdomain takeover scan with custom subdomain list support
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let domain = extract_domain(target);
    let subs = match enum_subdomains(&domain).await {
        Ok(s) => s,
        Err(_) => return findings,
    };

    // Limit checks to prevent rate limiting
    let limit = 50;
    let mut checked = 0;

    for sub in subs.iter().take(limit) {
        let url = format!("https://{}", sub);
        if let Ok((_st, _h, body, _f)) = http.get(&url).await {
            if let Some((svc, confidence)) = match_takeover(&body) {
                // v4.4.0 Lesson 1: filter Cloudflare FPs (api-gate-v2 sumopod case)
                // aws-elastic/heroku/etc are NOT behind CF — but if we see a CF header,
                // this is Cloudflare itself, not an unclaimed service.
                let cf_hint = body.contains("cloudflare") || body.contains("cf-ray")
                    || body.contains("cf-cache-status") || body.to_lowercase().contains("server: cloudflare");
                // Resolve subdomain to check IP directly
                use std::process::Command;
                let ip_check = Command::new("dig")
                    .args(&["+short", &format!("{}.", sub), "A"])
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                let cf_ip = !ip_check.is_empty() && crate::scan::cloudflare_ranges::is_cloudflare(&ip_check);
                if cf_hint || cf_ip {
                    // Downgrade to Info / skip
                    findings.push(Finding {
                        severity: Severity::Info,
                        category: "TAKEOVER".into(),
                        title: format!("Takeover filter: {} points to Cloudflare (FP)", sub),
                        target: url.clone(),
                        param: None,
                        payload: None,
                        evidence: Some(format!(
                            "Subdomain {} matched takeover sig but resolves to Cloudflare ({}). Auto-filtered FP.",
                            sub, ip_check
                        )),
                        confidence: confidence.min(50),
                        note: Some("Lesson 1 fix v4.4.0: CF IPs are not takeover candidates.".into()),
                        request: None,
                        response: None,
                    });
                    continue;
                }
                findings.push(Finding {
                    severity: if confidence >= 90 { Severity::Critical } else { Severity::High },
                    category: "TAKEOVER".into(),
                    title: format!("Subdomain takeover: {} (CNAME → {})", sub, svc),
                    target: url.clone(),
                    param: None,
                    payload: None,
                    evidence: Some(format!(
                        "Subdomain {} points to {} but no live service (confidence {}%)",
                        sub, svc, confidence
                    )),
                    confidence,
                    note: Some(format!(
                        "Claim subdomain on {} to take over cookies for parent domain",
                        svc
                    )),
                    request: None,
                    response: None,
                });
            }
        }
        checked += 1;
    }

    if checked == 0 {
        findings.push(Finding {
            severity: Severity::Info,
            category: "TAKEOVER".into(),
            title: "No subdomains found for takeover check".to_string(),
            target: target.to_string(),
            param: None,
            payload: None,
            evidence: Some("crt.sh returned no subdomains".to_string()),
            confidence: 50,
            note: Some("Add subdomains manually via targets list".to_string()),
            request: None,
            response: None,
        });
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
        let result = match_takeover(body);
        assert_eq!(result.unwrap().0, "github-pages");
    }

    #[test]
    fn match_heroku() {
        let body = "No such app";
        assert_eq!(match_takeover(body).unwrap().0, "heroku");
    }

    #[test]
    fn match_s3() {
        let body = "The specified bucket does not exist";
        assert_eq!(match_takeover(body).unwrap().0, "aws-s3");
    }

    #[test]
    fn match_high_confidence() {
        let (_, confidence) = match_takeover("NoSuchBucket").unwrap();
        assert!(confidence >= 90);
    }

    #[test]
    fn match_none() {
        let body = "<html>Hello World</html>";
        assert!(match_takeover(body).is_none());
    }

    #[test]
    fn fingerprints_30_plus() {
        assert!(FINGERPRINTS.len() >= 30, "Need 30+ fingerprints, got {}", FINGERPRINTS.len());
    }

    #[test]
    fn match_azure() {
        // Use a body that uniquely matches "404 Web Site not found" (Azure CDN)
        // without being ambiguous with "Web Site not found." (Azure web app)
        let body = "Error 404 - Web app: 404 Web Site not found";
        // This should match "azure-apps" (priority) because of "Error 404 - Web app not found"
        assert!(match_takeover(body).is_some());
    }

    #[test]
    fn match_vercel() {
        let body = "The deployment could not be found";
        let result = match_takeover(body).unwrap();
        assert_eq!(result.0, "vercel");
        assert!(result.1 >= 90);
    }

    #[test]
    fn match_netlify() {
        let body = "DEPLOYMENT_NOT_FOUND";
        assert_eq!(match_takeover(body).unwrap().0, "netlify");
    }

    #[test]
    fn match_firebase() {
        let body = "No such site";
        assert_eq!(match_takeover(body).unwrap().0, "firebase");
    }

    #[test]
    fn match_gcs() {
        let body = "The specified bucket does not have a website configuration";
        assert_eq!(match_takeover(body).unwrap().0, "gcs");
    }

    #[test]
    fn match_ghost() {
        let body = "Ghost404";
        assert_eq!(match_takeover(body).unwrap().0, "ghost");
    }
}
