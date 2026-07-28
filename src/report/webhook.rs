//! Webhook Reporter — send findings to Slack, Discord, or generic webhook.
//! Format: JSON POST to webhook URL with findings summary.

use crate::types::{Finding, Severity};
use std::collections::HashMap;

/// Send findings summary to a Slack webhook.
pub async fn send_slack(webhook_url: &str, findings: &[Finding], engagement: &str) -> Result<(), String> {
    let sev_counts: HashMap<&str, usize> = findings.iter().fold(HashMap::new(), |mut acc, f| {
        *acc.entry(f.severity.as_str()).or_insert(0) += 1;
        acc
    });

    let critical = sev_counts.get("CRITICAL").copied().unwrap_or(0);
    let high = sev_counts.get("HIGH").copied().unwrap_or(0);
    let medium = sev_counts.get("MEDIUM").copied().unwrap_or(0);
    let total = findings.len();

    let color = if critical > 0 { "#f85149" } else if high > 0 { "#ff7b72" } else { "#d29922" };

    let payload = serde_json::json!({
        "attachments": [{
            "color": color,
            "title": format!("🐍 KOBRA Scan Complete — {}", engagement),
            "fields": [
                {"title": "Critical", "value": critical.to_string(), "short": true},
                {"title": "High", "value": high.to_string(), "short": true},
                {"title": "Medium", "value": medium.to_string(), "short": true},
                {"title": "Total Findings", "value": total.to_string(), "short": true},
            ],
            "footer": "KOBRA v2.0",
            "ts": chrono_now(),
        }]
    });

    let client = reqwest::Client::new();
    let resp = client.post(webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Slack webhook error: {}", e))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Slack webhook returned HTTP {}", resp.status()))
    }
}

/// Send findings summary to a Discord webhook.
pub async fn send_discord(webhook_url: &str, findings: &[Finding], engagement: &str) -> Result<(), String> {
    let sev_counts: HashMap<&str, usize> = findings.iter().fold(HashMap::new(), |mut acc, f| {
        *acc.entry(f.severity.as_str()).or_insert(0) += 1;
        acc
    });

    let critical = sev_counts.get("CRITICAL").copied().unwrap_or(0);
    let high = sev_counts.get("HIGH").copied().unwrap_or(0);
    let medium = sev_counts.get("MEDIUM").copied().unwrap_or(0);

    let mut description = String::new();
    if critical > 0 { description.push_str(&format!("🔴 **{} Critical**\n", critical)); }
    if high > 0 { description.push_str(&format!("🟠 **{} High**\n", high)); }
    if medium > 0 { description.push_str(&format!("🟡 **{} Medium**\n", medium)); }
    description.push_str(&format!("\n**Total**: {} findings", findings.len()));

    // Add top 3 critical findings
    let mut top: Vec<&Finding> = findings.iter().filter(|f| f.severity >= Severity::High).collect();
    top.sort_by_key(|f| match f.severity { Severity::Critical => 0, _ => 1 });
    for f in top.iter().take(3) {
        description.push_str(&format!("\n• **{}**: {}", f.severity.as_str(), f.title));
    }

    let payload = serde_json::json!({
        "content": format!("🐍 **KOBRA Scan — {}**\n\n{}", engagement, description),
        "username": "KOBRA Scanner"
    });

    let client = reqwest::Client::new();
    let resp = client.post(webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Discord webhook error: {}", e))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Discord webhook returned HTTP {}", resp.status()))
    }
}

/// Send findings to a generic webhook (JSON POST).
pub async fn send_generic(webhook_url: &str, findings: &[Finding], engagement: &str) -> Result<(), String> {
    let payload = serde_json::json!({
        "engagement": engagement,
        "total_findings": findings.len(),
        "findings": findings,
        "summary": {
            "critical": findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            "high": findings.iter().filter(|f| f.severity == Severity::High).count(),
            "medium": findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            "low": findings.iter().filter(|f| f.severity == Severity::Low).count(),
            "info": findings.iter().filter(|f| f.severity == Severity::Info).count(),
        }
    });

    let client = reqwest::Client::new();
    let resp = client.post(webhook_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Webhook error: {}", e))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("Webhook returned HTTP {}", resp.status()))
    }
}

fn chrono_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;
    #[test]
    fn chrono_now_positive() {
        assert!(chrono_now() > 1700000000);
    }
}
