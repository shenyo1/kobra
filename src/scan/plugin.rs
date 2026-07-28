//! Plugin system — hot-load custom scan modules from JSON descriptors.
//! Plugin format: {name, version, author, target_match (regex), checks: [{id, description, payload, match_pattern, severity}]}

use crate::types::{Finding, Mode, Severity};
use regex::Regex;
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Plugin {
    pub name: String,
    pub version: String,
    pub author: String,
    #[serde(default)]
    pub target_match: Option<String>,
    pub checks: Vec<Check>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Check {
    pub id: String,
    pub description: String,
    #[serde(default)]
    pub method: Option<String>,
    pub path: String,
    pub payload: Option<String>,
    pub match_pattern: String,
    pub severity: String,
    #[serde(default = "default_confidence")]
    pub confidence: u8,
}

fn default_confidence() -> u8 { 60 }

pub fn load_plugin(path: &str) -> Result<Plugin, String> {
    let s = fs::read_to_string(path).map_err(|e| format!("read: {}", e))?;
    serde_json::from_str(&s).map_err(|e| format!("parse: {}", e))
}

pub fn load_dir(dir: &str) -> Vec<Plugin> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(p) = load_plugin(p.to_str().unwrap_or("")) {
                    out.push(p);
                }
            }
        }
    }
    out
}

pub fn plugin_apply(plugin: &Plugin, target: &str, body: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(pattern) = &plugin.target_match {
        if let Ok(re) = Regex::new(pattern) {
            if !re.is_match(target) {
                return findings;
            }
        }
    }
    for c in &plugin.checks {
        let re = match Regex::new(&c.match_pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if re.is_match(body) {
            let sev = match c.severity.as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            };
            findings.push(Finding {
                severity: sev,
                category: format!("PLUGIN:{}", plugin.name),
                title: format!("{} — {}", c.id, c.description),
                target: format!("{}{}", target, c.path),
                param: None,
                payload: c.payload.clone(),
                evidence: Some(format!("Plugin {} v{} by {} matched pattern", plugin.name, plugin.version, plugin.author)),
                confidence: c.confidence,
                note: Some("Loaded from plugin file".into()),
                request: None,
                response: None,
            });
        }
    }
    findings
}

pub async fn scan_with_plugins(
    http: &crate::http::HttpClient,
    target: &str,
    plugins: &[Plugin],
) -> Vec<Finding> {
    let mut all = Vec::new();
    for p in plugins {
        for c in &p.checks {
            let url = format!("{}{}", target.trim_end_matches('/'), c.path);
            if let Ok((_st, _h, body, _f)) = http.get(&url).await {
                all.extend(plugin_apply(p, target, &body));
            }
        }
    }
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn load_sample_plugin() {
        let json = r#"{
            "name": "test-plugin",
            "version": "1.0",
            "author": "afif",
            "checks": [
                {
                    "id": "TEST-001",
                    "description": "checks for hello world",
                    "path": "/",
                    "match_pattern": "hello",
                    "severity": "info",
                    "confidence": 50
                }
            ]
        }"#;
        let tmp = "/tmp/kobra_plugin_test.json";
        fs::write(tmp, json).unwrap();
        let p = load_plugin(tmp).unwrap();
        assert_eq!(p.name, "test-plugin");
        assert_eq!(p.checks.len(), 1);
        fs::remove_file(tmp).ok();
    }
    #[test]
    fn apply_plugin_match() {
        let json = r#"{
            "name": "t", "version": "1", "author": "x",
            "checks": [{"id":"X","description":"d","path":"/","match_pattern":"leaked","severity":"high","confidence":80}]
        }"#;
        let p: Plugin = serde_json::from_str(json).unwrap();
        let f = plugin_apply(&p, "https://x.com", "data leaked here");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
    }
    #[test]
    fn apply_plugin_target_match_filter() {
        let json = r#"{
            "name": "t", "version": "1", "author": "x",
            "target_match": "example\\.com",
            "checks": [{"id":"X","description":"d","path":"/","match_pattern":"x","severity":"low","confidence":50}]
        }"#;
        let p: Plugin = serde_json::from_str(json).unwrap();
        assert!(plugin_apply(&p, "https://x.com", "x").is_empty());
        assert!(!plugin_apply(&p, "https://example.com", "x").is_empty());
    }
    #[test]
    fn load_dir_no_dir() {
        let v = load_dir("/nonexistent");
        assert!(v.is_empty());
    }
}
