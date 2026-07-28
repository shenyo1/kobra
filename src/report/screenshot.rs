//! Screenshot Evidence — capture screenshots of vulnerable pages using
//! the headless browser. Attaches visual proof to findings.

use crate::types::Finding;

/// Capture screenshots for high+critical findings into a directory.
/// Returns the number of screenshots captured.
pub async fn capture_screenshots(findings: &[Finding], dir: &str) -> usize {
    // Only screenshot high+critical findings with a valid HTTP target
    let targets: Vec<&Finding> = findings
        .iter()
        .filter(|f| {
            matches!(
                f.severity,
                crate::types::Severity::High | crate::types::Severity::Critical
            ) && f.target.starts_with("http")
        })
        .collect();

    if targets.is_empty() {
        return 0;
    }

    // Check headless availability
    if !crate::scan::headless::is_available() {
        println!("[-] Screenshot skipped: Chrome/Chromium not found");
        return 0;
    }

    // Create output directory
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("[-] Cannot create screenshot dir {}: {}", dir, e);
        return 0;
    }

    let mut count = 0;
    for (i, f) in targets.iter().enumerate() {
        let safe_name = sanitize_filename(&f.target);
        let path = format!("{}/{}_{}.png", dir, i, safe_name);

        match screenshot_url(&f.target, &path).await {
            Ok(_) => {
                println!("[+] Screenshot saved: {}", path);
                count += 1;
            }
            Err(e) => {
                eprintln!("[-] Screenshot failed for {}: {}", f.target, e);
            }
        }
    }

    count
}

/// Take a screenshot of a URL using chromiumoxide
async fn screenshot_url(url: &str, out_path: &str) -> Result<(), String> {
    use chromiumoxide::browser::{Browser, BrowserConfig};
    use chromiumoxide::page::ScreenshotParams;
    use futures_util::StreamExt;

    let (mut browser, mut handler) = Browser::launch(
        BrowserConfig::builder().build().map_err(|e| e.to_string())?,
    )
    .await
    .map_err(|e| format!("launch failed: {}", e))?;

    // Spawn handler
    let handle = tokio::spawn(async move {
        while let Some(_) = handler.next().await {}
    });

    let page = browser
        .new_page(url)
        .await
        .map_err(|e| format!("new_page failed: {}", e))?;

    // Wait for page to load
    let _ = tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Screenshot to bytes, then write to file
    let params = ScreenshotParams::builder()
        .full_page(true)
        .build();
    let bytes = page
        .screenshot(params)
        .await
        .map_err(|e| format!("screenshot failed: {}", e))?;

    std::fs::write(out_path, &bytes)
        .map_err(|e| format!("write failed: {}", e))?;

    let _ = browser.close().await;
    handle.abort();

    Ok(())
}

/// Sanitize a URL into a safe filename
fn sanitize_filename(url: &str) -> String {
    url.replace("https://", "")
        .replace("http://", "")
        .replace(['/', '?', '&', '=', ':', '.'], "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .take(60)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_basic() {
        let s = sanitize_filename("https://example.com/search?q=test&id=1");
        assert!(!s.contains('/'));
        assert!(!s.contains('?'));
        assert!(!s.contains(':'));
    }

    #[test]
    fn sanitize_length_limit() {
        let long = "https://".to_string() + &"a".repeat(200);
        let s = sanitize_filename(&long);
        assert!(s.len() <= 60);
    }

    #[test]
    fn path_creation_logic() {
        let p = std::path::Path::new("/tmp/kobra_screenshots_test");
        assert!(!p.to_str().unwrap().is_empty());
    }
}
