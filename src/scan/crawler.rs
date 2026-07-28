//! Basic Crawler — discovers endpoints from JS bundles, sitemap.xml, robots.txt, links.
//! Feeds discovered endpoints into scan modules for deeper coverage.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use regex::Regex;
use std::collections::HashSet;

/// Discover endpoints from a target URL.
/// Checks: robots.txt, sitemap.xml, JS bundle strings, page links.
pub async fn discover_endpoints(http: &HttpClient, target: &str, mode: Mode) -> Vec<String> {
    let mut endpoints: HashSet<String> = HashSet::new();
    let base = target.trim_end_matches('/').to_string();

    // 1. Check robots.txt
    let robots_url = format!("{}/robots.txt", base);
    if let Ok((st, _h, body, _f)) = http.get(&robots_url).await {
        if st == 200 && !body.is_empty() {
            for line in body.lines() {
                let trimmed = line.trim();
                if trimmed.to_lowercase().starts_with("disallow:") || trimmed.to_lowercase().starts_with("allow:") {
                    if let Some(path) = trimmed.split(':').nth(1) {
                        let p = path.trim().trim_end_matches('/');
                        if !p.is_empty() && p != "/" {
                            endpoints.insert(format!("{}{}", base, p));
                        }
                    }
                }
            }
        }
    }

    // 2. Check sitemap.xml
    let sitemap_url = format!("{}/sitemap.xml", base);
    if let Ok((st, _h, body, _f)) = http.get(&sitemap_url).await {
        if st == 200 && !body.is_empty() {
            // Simple regex to extract URLs from sitemap
            let re = Regex::new(r"<loc>(.*?)</loc>").unwrap();
            for cap in re.captures_iter(&body) {
                if let Some(url) = cap.get(1) {
                    let u = url.as_str().trim().trim_end_matches('/').to_string();
                    if !u.is_empty() {
                        endpoints.insert(u);
                    }
                }
            }
        }
    }

    // 3. Check sitemap index
    let sitemap_idx = format!("{}/sitemap_index.xml", base);
    if let Ok((st, _h, body, _f)) = http.get(&sitemap_idx).await {
        if st == 200 {
            let re = Regex::new(r"<loc>(.*?)</loc>").unwrap();
            for cap in re.captures_iter(&body) {
                if let Some(url) = cap.get(1) {
                    endpoints.insert(url.as_str().trim().to_string());
                }
            }
        }
    }

    // 4. Extract JS bundle URLs from main page
    let main_url = format!("{}/", base);
    if let Ok((st, _h, body, _f)) = http.get(&main_url).await {
        if st == 200 && !body.is_empty() {
            // Extract script src
            let re_script = Regex::new(r#"<script[^>]*src=["']([^"']+)["']"#).unwrap();
            for cap in re_script.captures_iter(&body) {
                if let Some(src) = cap.get(1) {
                    let s = src.as_str().trim();
                    if s.starts_with("http") {
                        endpoints.insert(s.to_string());
                    } else if s.starts_with('/') {
                        endpoints.insert(format!("{}{}", base, s));
                    }
                }
            }

            // Extract href links (internal only)
            let re_link = Regex::new(r#"<a[^>]*href=["']([^"']+)["']"#).unwrap();
            for cap in re_link.captures_iter(&body) {
                if let Some(href) = cap.get(1) {
                    let h = href.as_str().trim();
                    if h.starts_with('/') && !h.starts_with("//") {
                        let clean = h.trim_end_matches('/').to_string();
                        if !clean.is_empty() && clean != "/" {
                            endpoints.insert(format!("{}{}", base, &clean));
                        }
                    } else if h.starts_with(&base) {
                        endpoints.insert(h.trim_end_matches('/').to_string());
                    }
                }
            }
        }
    }

    // 5. Extract API-like patterns from JS (in crazy mode)
    if mode == Mode::Crazy {
        let js_patterns = [
            r#""([^"]*api[^"]*)"#,
            r#""([^"]*/v[0-9]+/[^"]*)"#,
            r#""([^"]*/graphql)"#,
            r#""([^"]*/rest[^"]*)"#,
        ];

        // Fetch main JS bundles
        let main_url = format!("{}/", base);
        if let Ok((st, _h, body, _f)) = http.get(&main_url).await {
            if st == 200 {
                let re_script = Regex::new(r#"<script[^>]*src=["']([^"']+)["']"#).unwrap();
                for cap in re_script.captures_iter(&body) {
                    if let Some(src) = cap.get(1) {
                        let js_url = if src.as_str().starts_with("http") {
                            src.as_str().to_string()
                        } else {
                            format!("{}{}", base, src.as_str())
                        };
                        if let Ok((_jst, _jh, js_body, _jf)) = http.get(&js_url).await {
                            for pat in &js_patterns {
                                let re = Regex::new(pat).unwrap();
                                for m in re.captures_iter(&js_body) {
                                    if let Some(val) = m.get(1) {
                                        let v = val.as_str().trim();
                                        if v.starts_with('/') {
                                            endpoints.insert(format!("{}{}", base, v));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    endpoints.into_iter().collect()
}

/// Generate finding for discovered endpoints
pub fn findings_from_endpoints(endpoints: &[String], target: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    if endpoints.len() > 3 {
        findings.push(
            Finding::new(Severity::Info, "CRAWLER", &format!("Discovered {} endpoints via crawler", endpoints.len()), target)
                .with_evidence(&format!("First 10: {}", endpoints.iter().take(10).cloned().collect::<Vec<_>>().join(", ")))
                .with_confidence(60),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn js_patterns_compiled() {
        let patterns = [
            r#""([^"]*api[^"]*)"#,
            r#""([^"]*/v[0-9]+/[^"]*)"#,
        ];
        for p in &patterns {
            assert!(Regex::new(p).is_ok());
        }
    }
}
