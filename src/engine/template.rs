//! Template System — YAML/JSON-based check definitions.
//! Users can add new vulnerability checks WITHOUT writing Rust code.
//! Format: {id, name, method, path, headers, body, matchers, severity}
//! Load from ~/.config/kobra/templates/ directory.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_method")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    pub matchers: Vec<Matcher>,
    pub severity: String,
    #[serde(default = "default_confidence")]
    pub confidence: u8,
    #[serde(default)]
    pub cve: Option<String>,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub cvss: Option<f32>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub target_match: Option<String>,  // regex filter for target URL
}

fn default_method() -> String { "GET".to_string() }
fn default_confidence() -> u8 { 65 }

#[derive(Debug, Clone, Deserialize)]
pub struct Matcher {
    #[serde(default)]
    pub r#type: String,  // "status", "word", "regex", "binary"
    #[serde(default)]
    pub part: String,    // "body", "header", "status"
    pub value: String,
    #[serde(default)]
    pub negate: bool,    // true = match if NOT present
}

/// Load all templates from a directory.
pub fn load_templates(dir: &str) -> Vec<Template> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext == "yaml" || ext == "yml" || ext == "json" {
                if let Ok(content) = fs::read_to_string(&p) {
                    // Try YAML first, then JSON
                    if ext == "yaml" || ext == "yml" {
                        if let Ok(t) = serde_yaml::from_str::<Template>(&content) {
                            out.push(t);
                        } else if let Ok(t) = serde_json::from_str::<Template>(&content) {
                            out.push(t);
                        }
                    } else {
                        if let Ok(t) = serde_json::from_str::<Template>(&content) {
                            out.push(t);
                        } else if let Ok(t) = serde_yaml::from_str::<Template>(&content) {
                            out.push(t);
                        }
                    }
                }
            }
        }
    }
    out
}

/// Run all templates against a target.
pub async fn run_templates(
    http: &HttpClient,
    target: &str,
    templates: &[Template],
    mode: Mode,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = target.trim_end_matches('/');

    for tmpl in templates {
        // Skip if mode is stealth and template has no tags (noisy)
        if mode == Mode::Stealth && tmpl.tags.is_empty() {
            continue;
        }

        // Skip if target_match doesn't match
        if let Some(pattern) = &tmpl.target_match {
            if let Ok(re) = Regex::new(pattern) {
                if !re.is_match(target) {
                    continue;
                }
            }
        }

        let url = format!("{}{}", base, &tmpl.path);
        let method = tmpl.method.to_uppercase();
        let req_method = match method.as_str() {
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "DELETE" => reqwest::Method::DELETE,
            "PATCH" => reqwest::Method::PATCH,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            _ => reqwest::Method::GET,
        };

        // Build headers from template + defaults
        let mut headers = tmpl.headers.clone();
        if !headers.contains_key("User-Agent") {
            headers.insert("User-Agent".into(), "kobra-template/1.0".into());
        }
        let h = if headers.is_empty() { None } else { Some(headers) };

        // Execute request
        let result = match method.as_str() {
            "GET" | "HEAD" | "OPTIONS" | "DELETE" => {
                http.fetch(&url, req_method, None, h).await
            }
            _ => {
                let body = tmpl.body.as_deref();
                http.fetch(&url, req_method, body, h).await
            }
        };

        if let Ok((st, headers_str, body, _final_url)) = result {
            let mut matched = false;
            let mut evidence_parts = Vec::new();

            for matcher in &tmpl.matchers {
                let part_content = match matcher.part.as_str() {
                    "header" => &headers_str,
                    "status" => &st.to_string(),
                    _ => &body,
                };

                let is_match = match matcher.r#type.as_str() {
                    "status" => st.to_string() == matcher.value,
                    "word" => part_content.contains(&matcher.value),
                    "regex" => {
                        if let Ok(re) = Regex::new(&matcher.value) {
                            re.is_match(part_content)
                        } else {
                            false
                        }
                    }
                    _ => part_content.contains(&matcher.value),
                };

                let final_match = if matcher.negate { !is_match } else { is_match };
                if final_match {
                    evidence_parts.push(format!("{}:{} matched", matcher.r#type, matcher.value));
                    matched = true;
                }
            }

            if matched {
                let sev = match tmpl.severity.to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Info,
                };

                let mut finding = Finding::new(sev, "TEMPLATE", &tmpl.name, &url)
                    .with_evidence(&evidence_parts.join("; "))
                    .with_confidence(tmpl.confidence);

                if let Some(cve) = &tmpl.cve {
                    finding = finding.with_note(&format!("{} | CWE: {} | CVSS: {:.1}", cve,
                        tmpl.cwe.as_deref().unwrap_or("N/A"),
                        tmpl.cvss.unwrap_or(0.0)));
                }

                findings.push(finding);
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn load_yaml_template() {
        let yaml = r#"
id: "TEST-001"
name: "Test Template"
method: GET
path: "/test"
severity: medium
confidence: 80
matchers:
  - type: word
    part: body
    value: "vulnerable"
"#;
        let t: Template = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(t.id, "TEST-001");
        assert_eq!(t.matchers.len(), 1);
    }
    #[test]
    fn load_json_template() {
        let json = r#"{
            "id": "TEST-002",
            "name": "JSON Template",
            "method": "POST",
            "path": "/api/test",
            "body": "{\"key\":\"value\"}",
            "severity": "high",
            "matchers": [{"type": "status", "part": "status", "value": "200"}]
        }"#;
        let t: Template = serde_json::from_str(json).unwrap();
        assert_eq!(t.id, "TEST-002");
        assert_eq!(t.method, "POST");
    }
    #[test]
    fn load_dir_nonexistent() {
        let v = load_templates("/nonexistent");
        assert!(v.is_empty());
    }
}
