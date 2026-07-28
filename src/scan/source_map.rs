//! Source map leak detection — for every .js discovered, try .js.map.
//! Source maps expose original TypeScript/source with comments, secrets, dead code.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use regex::Regex;

const SOURCE_MAP_MARKER: &str = "//# sourceMappingURL=";
const SOURCES_FIELD: &str = "\"sources\":";

/// Detect if `js` body has a sourceMappingURL.
pub fn has_source_map_ref(js: &str) -> Option<String> {
    let idx = js.find(SOURCE_MAP_MARKER)?;
    let rest = &js[idx + SOURCE_MAP_MARKER.len()..];
    let end = rest.find('\n').unwrap_or(rest.len());
    let map_url = rest[..end].trim().trim_end_matches(';').trim();
    Some(map_url.to_string())
}

/// Extract "sources" array from source map JSON. Returns list of source file paths.
pub fn extract_sources(map_json: &str) -> Vec<String> {
    let mut out = Vec::new();
    let re = Regex::new(r#""sources"\s*:\s*\[([^\]]*)\]"#).unwrap();
    if let Some(cap) = re.captures(map_json) {
        if let Some(m) = cap.get(1) {
            let items = m.as_str();
            let re_str = Regex::new(r#""([^"]+)""#).unwrap();
            for c in re_str.captures_iter(items) {
                if let Some(p) = c.get(1) {
                    out.push(p.as_str().to_string());
                }
            }
        }
    }
    out
}

/// Build candidate source map URLs from a JS path.
pub fn candidate_map_urls(js_url: &str) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!("{}.map", js_url));
    if let Some(idx) = js_url.find('?') {
        out.push(format!("{}.map", &js_url[..idx]));
    }
    out
}

pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Ok((_st, _h, body, _f)) = http.get(target).await {
        let scripts = discover_js_paths(&body, target);
        for script_url in scripts {
            if let Ok((st, _h, js_body, _f)) = http.get(&script_url).await {
                if st != 200 {
                    continue;
                }
                let map_ref = has_source_map_ref(&js_body);
                for map_url in candidate_map_urls(&script_url) {
                    if let Ok((map_st, _h, map_body, _f)) = http.get(&map_url).await {
                        if map_st == 200 && map_body.contains(SOURCES_FIELD) {
                            let sources = extract_sources(&map_body);
                            findings.push(Finding {
                                severity: Severity::Medium,
                                category: "SOURCEMAP".into(),
                                title: format!("Source map exposed: {} ({} sources)", map_url, sources.len()),
                                target: script_url.clone(),
                                param: None,
                                payload: None,
                                evidence: Some(format!(
                                    "map_ref={:?} sources[0..3]={:?}",
                                    map_ref,
                                    sources.iter().take(3).collect::<Vec<_>>()
                                )),
                                confidence: 95,
                                note: Some("Source maps leak original source code with comments, secrets, API keys".into()),
                                request: None,
                                response: None,
                            });
                            break;
                        }
                    }
                }
            }
        }
    }
    findings
}

fn discover_js_paths(html: &str, base: &str) -> Vec<String> {
    let mut out = Vec::new();
    let re = Regex::new(r#"(?:src|href)\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']"#).unwrap();
    for cap in re.captures_iter(html) {
        if let Some(m) = cap.get(1) {
            let url = m.as_str();
            if url.starts_with("http://") || url.starts_with("https://") {
                out.push(url.to_string());
            } else if url.starts_with('/') {
                if let Ok(b) = url::Url::parse(base) {
                    let origin = format!("{}://{}", b.scheme(), b.host_str().unwrap_or(""));
                    out.push(format!("{}{}", origin, url));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn has_ref() {
        let js = "console.log('x');\n//# sourceMappingURL=main.js.map\n";
        assert_eq!(has_source_map_ref(js), Some("main.js.map".to_string()));
    }
    #[test]
    fn no_ref() {
        assert_eq!(has_source_map_ref("var x = 1;"), None);
    }
    #[test]
    fn extract_sources_basic() {
        let json = r#"{"version":3,"sources":["webpack:///./src/index.ts","webpack:///./src/app.ts"],"mappings":""}"#;
        let s = extract_sources(json);
        assert_eq!(s.len(), 2);
        assert!(s[0].contains("index.ts"));
    }
    #[test]
    fn candidate_urls() {
        let v = candidate_map_urls("https://x.com/static/main.js");
        assert!(v.contains(&"https://x.com/static/main.js.map".to_string()));
    }
}
