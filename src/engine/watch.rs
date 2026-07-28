//! Watch Mode — periodic rescan with alerting on new findings.
//! Runs scan loop every N minutes, compares against previous results,
//! and alerts (stdout/webhook) when new findings appear.

use crate::engine::diff;
use crate::types::Finding;
use std::time::Duration;

/// Watch configuration
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Interval between scans in minutes
    pub interval_minutes: u64,
    /// Max number of scan iterations (0 = infinite)
    pub max_iterations: u32,
    /// Only alert on High+ findings
    pub high_only: bool,
}

impl Default for WatchConfig {
    fn default() -> Self {
        WatchConfig {
            interval_minutes: 30,
            max_iterations: 0,
            high_only: false,
        }
    }
}

/// Run watch loop: scan → diff → alert → sleep → repeat
/// `scan_fn` is called each iteration and returns current findings.
pub async fn run_watch<F, Fut>(
    config: &WatchConfig,
    mut scan_fn: F,
    webhook_url: Option<&str>,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Vec<Finding>>,
{
    let mut iteration = 0u32;
    let mut baseline: Vec<Finding> = Vec::new();

    println!("\n\x1b[95m👁️  WATCH MODE ACTIVE\x1b[0m");
    println!(
        "   Interval: {} min | Max iterations: {} | High-only: {}",
        config.interval_minutes,
        if config.max_iterations == 0 { "∞".to_string() } else { config.max_iterations.to_string() },
        config.high_only
    );
    println!();

    loop {
        iteration += 1;
        println!(
            "\x1b[96m[*] Watch iteration #{} — {}\x1b[0m",
            iteration,
            chrono_now()
        );

        // Run scan
        let current = scan_fn().await;
        println!("[+] Scan complete: {} findings", current.len());

        if iteration == 1 {
            // First iteration = baseline
            baseline = current.clone();
            println!("[*] Baseline established: {} findings", baseline.len());
        } else {
            // Diff against baseline
            let result = diff::diff_findings(&current, &baseline);

            let alert_findings: Vec<&Finding> = if config.high_only {
                result.new_findings.iter()
                    .filter(|f| matches!(f.severity, crate::types::Severity::High | crate::types::Severity::Critical))
                    .collect()
            } else {
                result.new_findings.iter().collect()
            };

            if !alert_findings.is_empty() {
                println!(
                    "\n\x1b[91m🚨 ALERT: {} NEW finding(s) detected!\x1b[0m",
                    alert_findings.len()
                );
                for f in &alert_findings {
                    println!(
                        "   \x1b[91m[{}]\x1b[0m {} — {}",
                        f.severity.as_str(),
                        f.title,
                        f.target
                    );
                }

                // Webhook alert
                if let Some(url) = webhook_url {
                    let alert_findings_owned: Vec<Finding> = alert_findings.iter().map(|f| (*f).clone()).collect();
                    if let Err(e) = crate::report::webhook::send_generic(
                        url,
                        &alert_findings_owned,
                        &format!("watch-alert-{}", iteration),
                    ).await {
                        eprintln!("[-] Watch webhook error: {}", e);
                    } else {
                        println!("[+] Watch alert sent to webhook");
                    }
                }
            } else {
                println!("[✓] No new findings since last scan");
            }

            if !result.resolved.is_empty() {
                println!(
                    "\x1b[92m[✓] {} finding(s) resolved since last scan\x1b[0m",
                    result.resolved.len()
                );
            }

            // Update baseline for next iteration
            baseline = current;
        }

        // Check max iterations
        if config.max_iterations > 0 && iteration >= config.max_iterations {
            println!("\n[*] Max iterations ({}) reached. Watch mode ending.", config.max_iterations);
            break;
        }

        // Sleep until next iteration
        println!(
            "[*] Next scan in {} minutes... (Ctrl+C to stop)",
            config.interval_minutes
        );
        tokio::time::sleep(Duration::from_secs(config.interval_minutes * 60)).await;
    }
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Simple HH:MM:SS from epoch (UTC)
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{:02}:{:02}:{:02} UTC", h, m, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let c = WatchConfig::default();
        assert_eq!(c.interval_minutes, 30);
        assert_eq!(c.max_iterations, 0);
        assert!(!c.high_only);
    }

    #[test]
    fn chrono_now_format() {
        let t = chrono_now();
        assert!(t.contains("UTC"));
        assert!(t.contains(':'));
    }
}
