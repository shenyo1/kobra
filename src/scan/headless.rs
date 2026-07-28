//! Headless Browser — DOM XSS detection, SPA crawl, JS execution.
//! Uses chromiumoxide (Chrome DevTools Protocol) for browser automation.
//! Optional: falls back gracefully if Chrome is not installed.

use crate::types::{Finding, Mode, Severity};
use futures_util::StreamExt;
use chromiumoxide::browser::{Browser, BrowserConfig};

/// Check if headless browser is available (Chrome/Chromium installed).
pub fn is_available() -> bool {
    std::process::Command::new("which")
        .arg("chromium-browser")
        .arg("||")
        .arg("which")
        .arg("google-chrome")
        .arg("||")
        .arg("which")
        .arg("google-chrome-stable")
        .arg("||")
        .arg("which")
        .arg("chromium")
        .output()
        .ok()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// DOM XSS sink patterns to detect in JS/HTML
const DOM_XSS_SINKS: &[&str] = &[
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write(",
    "document.writeln(",
    "eval(",
    "setTimeout(",
    "setInterval(",
    "new Function(",
    "location.href",
    "location.assign(",
    "location.replace(",
    "srcdoc",
];

/// DOM XSS sources (user input that can flow to sinks)
const DOM_XSS_SOURCES: &[&str] = &[
    "location.hash",
    "location.search",
    "location.pathname",
    "document.URL",
    "document.documentURI",
    "document.referrer",
    "window.name",
    "postMessage",
];

/// Scan a page with headless browser for DOM-based vulnerabilities.
/// Returns findings for DOM XSS sinks/sources.
pub async fn scan_dom_xss(target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !is_available() {
        eprintln!("[browser] Chrome/Chromium not found — skipping headless scan");
        return findings;
    }

    // Launch browser
    let (mut browser, mut handler) = match Browser::launch(
        BrowserConfig::builder()
            .build()
            .expect("BrowserConfig::build"),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[browser] launch error: {}", e);
            return findings;
        }
    };

    let handle = tokio::spawn(async move {
        while let Some(h) = handler.next().await {
            if h.is_err() {
                break;
            }
        }
    });

    // Navigate to target
    let page = match browser.new_page(target).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[browser] navigate error: {}", e);
            let _ = browser.close().await;
            return findings;
        }
    };

    // Wait for page to load
    let _ = tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // 1. Get page content for DOM analysis
    if let Ok(html) = page.content().await {
        let html_lower = html.to_lowercase();

        // Check for DOM XSS sinks in page source
        let mut sink_count = 0;
        for sink in DOM_XSS_SINKS {
            if html_lower.contains(sink) {
                sink_count += 1;
            }
        }

        if sink_count > 0 && mode.attempt_bypass() {
            findings.push(
                Finding::new(
                    Severity::Low,
                    "DOM-XSS",
                    &format!("Potential DOM XSS sinks detected ({} patterns)", sink_count),
                    target,
                )
                .with_evidence(&format!("Found {} DOM XSS sink patterns in page source", sink_count))
                .with_confidence(40),
            );
        }

        // Check for DOM XSS sources
        for src in DOM_XSS_SOURCES {
            if html_lower.contains(src) {
                findings.push(
                    Finding::new(
                        Severity::Info,
                        "DOM-XSS",
                        &format!("DOM XSS source detected: {}", src),
                        target,
                    )
                    .with_evidence(&format!("User-controllable input source: {}", src))
                    .with_confidence(30),
                );
            }
        }
    }

    // 2. Extract all script URLs (SPA route discovery)
    if let Ok(scripts) = page.find_elements("script[src]").await {
        for script in &scripts {
            if let Ok(src) = script.attribute("src").await {
                if let Some(url) = src {
                    if !url.starts_with("data:") && !url.contains("polyfill") {
                        findings.push(
                            Finding::new(
                                Severity::Info,
                                "BROWSER",
                                &format!("Script resource: {}", &url[..url.len().min(60)]),
                                target,
                            )
                            .with_evidence(&format!("SPA/JS script URL: {}", url))
                            .with_confidence(20),
                        );
                    }
                }
            }
        }
    }

    // 3. Try to detect client-side routes (SPA)
    if let Ok(links) = page.find_elements("a[href^='/']").await {
        let mut routes: Vec<String> = Vec::new();
        for link in &links {
            if let Ok(href) = link.attribute("href").await {
                if let Some(path) = href {
                    let path_clean = path.trim_end_matches('/').to_string();
                    if !path_clean.is_empty() && !routes.contains(&path_clean) {
                        routes.push(path_clean);
                    }
                }
            }
        }
        if routes.len() > 3 {
            findings.push(
                Finding::new(
                    Severity::Info,
                    "BROWSER",
                    &format!("SPA client-side routes: {} paths", routes.len()),
                    target,
                )
                .with_evidence(&format!("First 5 routes: {}", routes.iter().take(5).cloned().collect::<Vec<_>>().join(", ")))
                .with_confidence(30),
            );
        }
    }

    // 4. Check for postMessage listeners (security risk)
    let js_check = r#"
        (() => {
            const handlers = window.__kobra_listeners || [];
            // Try to detect addEventListener('message', ...)
            const orig = EventTarget.prototype.addEventListener;
            let count = 0;
            const origAdd = EventTarget.prototype.addEventListener;
            EventTarget.prototype.addEventListener = function(type, fn) {
                if (type === 'message') count++;
                return origAdd.call(this, type, fn);
            };
            return count;
        })()
    "#;

    if let Ok(result) = page.evaluate(js_check).await {
        let result_str = format!("{:?}", result);
        let val: serde_json::Value = serde_json::from_str(&result_str).unwrap_or_default();
        if let Some(count) = val.as_i64() {
            if count > 0 {
                findings.push(
                    Finding::new(
                        Severity::Low,
                        "BROWSER",
                        &format!("postMessage listeners detected: {}", count),
                        target,
                    )
                    .with_evidence("Page has postMessage event listeners — potential DOM clobbering / XSS")
                    .with_confidence(50),
                );
            }
        }
    }

    // Cleanup
    let _ = browser.close().await;
    handle.await.ok();

    findings
}

/// Extract all visible links from page using headless browser.
/// Useful for discovering hidden endpoints in SPAs.
pub async fn extract_links(target: &str) -> Vec<String> {
    let mut links = Vec::new();

    if !is_available() {
        return links;
    }

    let (mut browser, mut handler) = match Browser::launch(
        BrowserConfig::builder()
            .build()
            .expect("BrowserConfig::build"),
    )
    .await
    {
        Ok(b) => b,
        Err(_) => return links,
    };

    let handle = tokio::spawn(async move {
        while let Some(h) = handler.next().await {
            if h.is_err() {
                break;
            }
        }
    });

    if let Ok(page) = browser.new_page(target).await {
        let _ = tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        if let Ok(elements) = page.find_elements("a[href]").await {
            for el in &elements {
                if let Ok(Some(href)) = el.attribute("href").await {
                    let trimmed = href.trim().to_string();
                    if !trimmed.is_empty() && !links.contains(&trimmed) {
                        links.push(trimmed);
                    }
                }
            }
        }
    }

    let _ = browser.close().await;
    handle.await.ok();
    links
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dom_sinks_non_empty() {
        assert!(DOM_XSS_SINKS.len() > 5);
    }
    #[test]
    fn dom_sources_non_empty() {
        assert!(DOM_XSS_SOURCES.len() > 3);
    }
    #[test]
    fn is_available_returns_bool() {
        // Should not panic
        let _ = is_available();
    }
}
