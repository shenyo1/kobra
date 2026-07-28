//! CVE auto-update — fetches RSS feed from NVD/CISA and generates CveRule entries.
//! Saves to local JSON cache. Runs on-demand or via --cve-update flag.

use serde::{Deserialize, Serialize};
use std::fs;

#[allow(dead_code)]
const CVE_FEED_URL: &str = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2026.json.zip";
const CISA_KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CveFeedEntry {
    pub id: String,
    pub description: String,
    pub cvss_score: Option<f32>,
    pub cwe: Option<String>,
    pub published: String,
}

/// Fetch CVE feed from NVD (simplified — returns recent high-profile CVEs).
/// In production, this would download + parse the NVD JSON feed.
pub async fn fetch_cve_feed() -> Vec<CveFeedEntry> {
    let mut entries = Vec::new();

    // Try to fetch from CISA KEV (known exploited vulnerabilities)
    if let Ok(resp) = reqwest::get(CISA_KEV_URL).await {
        if let Ok(text) = resp.text().await {
            if let Ok(cisa) = serde_json::from_str::<CisaKev>(&text) {
                for vuln in cisa.vulnerabilities.iter().take(30) {
                    entries.push(CveFeedEntry {
                        id: vuln.cve_id.clone(),
                        description: vuln.short_description.clone(),
                        cvss_score: None,
                        cwe: None,
                        published: vuln.date_added.clone(),
                    });
                }
            }
        }
    }

    entries
}

#[derive(Debug, Deserialize)]
struct CisaKev {
    #[serde(rename = "vulnerabilities")]
    vulnerabilities: Vec<CisaVuln>,
}

#[derive(Debug, Deserialize)]
struct CisaVuln {
    #[serde(rename = "cveID")]
    cve_id: String,
    #[serde(rename = "shortDescription")]
    short_description: String,
    #[serde(rename = "dateAdded")]
    date_added: String,
}

/// Save CVE feed to local cache
pub fn save_cve_cache(entries: &[CveFeedEntry], path: &str) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(entries).unwrap_or_default();
    let _ = fs::write(path, json);
}

/// Load CVE cache from local file
pub fn load_cve_cache(path: &str) -> Vec<CveFeedEntry> {
    if let Ok(s) = fs::read_to_string(path) {
        serde_json::from_str(&s).unwrap_or_default()
    } else {
        Vec::new()
    }
}

/// Check if cache needs refresh (older than 24h)
pub fn needs_refresh(path: &str) -> bool {
    if let Ok(meta) = fs::metadata(path) {
        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = modified.elapsed() {
                return elapsed.as_secs() > 86400; // 24 hours
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn needs_refresh_nonexistent() {
        assert!(needs_refresh("/tmp/nonexistent_cve_cache.json"));
    }
    #[test]
    fn save_and_load() {
        let entries = vec![CveFeedEntry {
            id: "CVE-2026-TEST".into(),
            description: "Test vuln".into(),
            cvss_score: Some(9.8),
            cwe: Some("CWE-89".into()),
            published: "2026-07-28".into(),
        }];
        let path = "/tmp/kobra_cve_test.json";
        save_cve_cache(&entries, path);
        let loaded = load_cve_cache(path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "CVE-2026-TEST");
        fs::remove_file(path).ok();
    }
}
