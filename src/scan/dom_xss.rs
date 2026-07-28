//! DOM XSS sink/source detection via static analysis of JS bundles.
//! Looks for unsafe sinks: innerHTML, document.write, eval, Function(),
//! combined with tainted sources: location.hash, location.search, postMessage, etc.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;
use regex::Regex;

/// Sinks that can execute HTML/script and lead to DOM XSS if fed tainted input.
const SINKS: &[(&str, &str)] = &[
    (r"\.innerHTML\s*=", "innerHTML"),
    (r"\.outerHTML\s*=", "outerHTML"),
    (r"document\.write(?:ln)?\s*\(", "document.write"),
    (r"\beval\s*\(", "eval"),
    (r"\bFunction\s*\(", "Function"),
    (r"setTimeout\s*\(\s*[\x27\x22]", "setTimeout string arg"),
    (r"setInterval\s*\(\s*[\x27\x22]", "setInterval string arg"),
    (r"\.srcdoc\s*=", "iframe srcdoc"),
    (r"new\s+Function", "new Function"),
    (r"insertAdjacentHTML", "insertAdjacentHTML"),
    (r"\.insertAdjacentElement", "insertAdjacentElement"),
];

/// Sources that introduce attacker-controlled data into the DOM.
const SOURCES: &[&str] = &[
    "location.hash",
    "location.search",
    "location.href",
    "document.location",
    "document.referrer",
    "document.URL",
    "window.name",
    "postMessage",
    "localStorage",
    "sessionStorage",
    "URLSearchParams",
    "document.cookie",
];

/// Probe target HTML, discover JS bundles, fetch them, scan sinks/sources.
/// FIX.2: Skip framework internal bundles (astro/next/vue/react router) — these
/// legitimately use innerHTML for SPA navigation, not exploitable without tainted
/// data flow into the specific sink call.
pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Ok((_st, _h, body, _f)) = http.get(target).await {
        let scripts = discover_js_paths(&body, target);
        for path in scripts {
            if let Ok((st, _h, js_body, _f)) = http.get(&path).await {
                if st == 200 {
                    // FIX.2: skip framework internal files
                    if is_framework_internal(&path) {
                        continue;
                    }
                    analyze_js(&path, &js_body, &mut findings);
                }
            }
        }
        // Also skip framework analysis on the main page if it IS a SPA
        if !is_likely_spa(&body) {
            analyze_js(target, &body, &mut findings);
        }
    }
    findings
}

/// Heuristic: framework internal bundles are in /_astro/, /_next/, /__nuxt/, etc.
fn is_framework_internal(path: &str) -> bool {
    let lower = path.to_lowercase();
    let patterns = [
        "/_astro/",
        "/_next/",
        "/__nuxt/",
        "/__remix/",
        "/_svelte/",
        "/_nuxt/",
        "/runtime.",
        "/vendors-",
        "/chunk-",
        "/polyfills-",
        "/framework-",
        "clientrouter",
        "page-transitions",
        "router.",
    ];
    for p in patterns {
        if lower.contains(p) {
            return true;
        }
    }
    false
}

/// Detect SPA — minimal HTML body + large script bundle = SPA framework
fn is_likely_spa(body: &str) -> bool {
    let html_len = body.len();
    let script_count = body.matches("<script").count();
    html_len < 5000 && script_count >= 3
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
                    let scheme = b.scheme();
                    let host = b.host_str().unwrap_or("");
                    let origin = format!("{}://{}", scheme, host);
                    out.push(format!("{}{}", origin, url));
                }
            }
        }
    }
    out
}

fn analyze_js(src: &str, js: &str, findings: &mut Vec<Finding>) {
    let mut found_sinks: Vec<&str> = Vec::new();
    for (pattern, name) in SINKS {
        if Regex::new(pattern).map(|r| r.is_match(js)).unwrap_or(false) {
            found_sinks.push(name);
        }
    }
    if found_sinks.is_empty() {
        return;
    }
    let mut found_sources: Vec<&str> = Vec::new();
    for s in SOURCES {
        if js.contains(s) {
            found_sources.push(s);
        }
    }

    let has_taint = !found_sources.is_empty();
    let sev = if has_taint { Severity::Medium } else { Severity::Info };

    findings.push(Finding {
        severity: sev,
        category: "DOM-XSS".into(),
        title: format!("DOM XSS sinks found: {}", found_sinks.join(", ")),
        target: src.to_string(),
        param: None,
        payload: None,
        evidence: Some(format!(
            "sinks={:?} sources={:?} js_len={}",
            found_sinks, found_sources, js.len()
        )),
        confidence: if has_taint { 70 } else { 40 },
        note: Some(if has_taint {
            "Sinks + tainted sources present. Manual dynamic verification required (e.g. headless browser).".into()
        } else {
            "Dangerous sinks observed. Confirm sources separately.".into()
        }),
        request: None,
        response: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detect_innerHTML() {
        let mut f = Vec::new();
        analyze_js("test.js", "el.innerHTML = userInput;", &mut f);
        assert_eq!(f.len(), 1);
        assert!(f[0].evidence.as_ref().unwrap().contains("innerHTML"));
    }
    #[test]
    fn detect_eval() {
        let mut f = Vec::new();
        analyze_js("test.js", "eval(data);", &mut f);
        assert!(f[0].evidence.as_ref().unwrap().contains("eval"));
    }
    #[test]
    fn safe_code_no_finding() {
        let mut f = Vec::new();
        analyze_js("test.js", "var x = 1 + 2;", &mut f);
        assert!(f.is_empty());
    }
    #[test]
    fn taint_elevation() {
        let mut f = Vec::new();
        analyze_js("test.js", "el.innerHTML = location.hash;", &mut f);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].evidence.as_ref().unwrap().contains("location.hash"));
    }
    #[test]
    fn discover_paths() {
        let html = r#"<script src="/static/main.js"></script><script src="https://cdn.test/bundle.js"></script>"#;
        let paths = discover_js_paths(html, "https://x.com/");
        assert!(paths.iter().any(|p| p.contains("main.js")));
        assert!(paths.iter().any(|p| p.contains("bundle.js")));
    }
}
