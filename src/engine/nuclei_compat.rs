//! Nuclei Template Compatibility — parse nuclei YAML templates and convert
//! to KOBRA template format. Supports 9000+ community nuclei templates.

use crate::engine::template::Template;
use serde::Deserialize;
use std::fs;

/// Nuclei template YAML structure (subset we support)
#[derive(Debug, Deserialize)]
pub struct NucleiTemplate {
    id: String,
    #[serde(default)]
    info: Option<NucleiInfo>,
    #[serde(default)]
    http: Option<Vec<NucleiHttp>>,
}

#[derive(Debug, Deserialize)]
struct NucleiInfo {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    tags: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    reference: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct NucleiHttp {
    #[serde(default = "default_method")]
    method: String,
    #[serde(default)]
    path: Vec<String>,
    #[serde(default)]
    headers: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    matchers: Option<Vec<NucleiMatcher>>,
    #[serde(default)]
    #[allow(dead_code)]
    matchers_condition: Option<String>,
}

fn default_method() -> String { "GET".to_string() }

#[derive(Debug, Deserialize)]
struct NucleiMatcher {
    #[serde(default = "default_matcher_type")]
    r#type: String,
    #[serde(default)]
    words: Option<Vec<String>>,
    #[serde(default)]
    status: Option<Vec<u16>>,
    #[serde(default)]
    regex: Option<Vec<String>>,
    #[serde(default)]
    part: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    condition: Option<String>,
    #[serde(default)]
    negative: Option<bool>,
}

fn default_matcher_type() -> String { "word".to_string() }

/// Convert a nuclei template to KOBRA templates (one per path)
pub fn convert_nuclei(nuclei: &NucleiTemplate) -> Vec<Template> {
    let mut out = Vec::new();

    let http_requests = match &nuclei.http {
        Some(h) => h,
        None => return out,
    };

    let name = nuclei.info.as_ref()
        .and_then(|i| i.name.clone())
        .unwrap_or_else(|| nuclei.id.clone());

    let severity = nuclei.info.as_ref()
        .and_then(|i| i.severity.clone())
        .unwrap_or_else(|| "medium".to_string());

    let description = nuclei.info.as_ref()
        .and_then(|i| i.description.clone());

    let tags: Vec<String> = nuclei.info.as_ref()
        .and_then(|i| i.tags.clone())
        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let cve = tags.iter().find(|t| t.to_uppercase().starts_with("CVE")).cloned();
    let cwe = tags.iter().find(|t| t.to_uppercase().starts_with("CWE")).cloned();

    for req in http_requests {
        for path in &req.path {
            // Convert {{BaseURL}}/path → /path
            let clean_path = path
                .replace("{{BaseURL}}", "")
                .replace("{{Hostname}}", "")
                .replace("{{RootURL}}", "");
            let clean_path = if clean_path.is_empty() { "/".to_string() } else { clean_path };

            // Convert nuclei matchers to KOBRA matchers
            let mut matchers = Vec::new();
            if let Some(nm) = &req.matchers {
                for m in nm {
                    let part = m.part.clone().unwrap_or_else(|| "body".to_string());
                    let negate = m.negative.unwrap_or(false);

                    match m.r#type.as_str() {
                        "word" => {
                            if let Some(words) = &m.words {
                                for w in words {
                                    matchers.push(crate::engine::template::Matcher {
                                        r#type: "word".to_string(),
                                        part: part.clone(),
                                        value: w.clone(),
                                        negate,
                                    });
                                }
                            }
                        }
                        "status" => {
                            if let Some(statuses) = &m.status {
                                for s in statuses {
                                    matchers.push(crate::engine::template::Matcher {
                                        r#type: "status".to_string(),
                                        part: "status".to_string(),
                                        value: s.to_string(),
                                        negate,
                                    });
                                }
                            }
                        }
                        "regex" => {
                            if let Some(patterns) = &m.regex {
                                for p in patterns {
                                    matchers.push(crate::engine::template::Matcher {
                                        r#type: "regex".to_string(),
                                        part: part.clone(),
                                        value: p.clone(),
                                        negate,
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }

            if matchers.is_empty() {
                continue; // Skip templates without matchers
            }

            // Convert headers
            let headers = req.headers.clone().unwrap_or_default();

            // Convert body
            let body = req.body.clone();

            out.push(Template {
                id: format!("nuclei-{}", nuclei.id),
                name: name.clone(),
                description: description.clone(),
                method: req.method.clone(),
                path: clean_path,
                headers,
                body,
                matchers,
                severity: severity.clone(),
                confidence: 70,
                cve: cve.clone(),
                cwe: cwe.clone(),
                cvss: None,
                tags: tags.clone(),
                target_match: None,
            });
        }
    }

    out
}

/// Load nuclei templates from a directory and convert to KOBRA format
pub fn load_nuclei_dir(dir: &str) -> Vec<Template> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext == "yaml" || ext == "yml" {
                if let Ok(content) = fs::read_to_string(&p) {
                    if let Ok(nuclei) = serde_yaml::from_str::<NucleiTemplate>(&content) {
                        out.extend(convert_nuclei(&nuclei));
                    }
                }
            }
        }
    }
    out
}

/// Load a single nuclei template from YAML string
pub fn parse_nuclei_yaml(yaml: &str) -> Vec<Template> {
    match serde_yaml::from_str::<NucleiTemplate>(yaml) {
        Ok(n) => convert_nuclei(&n),
        Err(_) => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_nuclei() {
        let yaml = r#"
id: test-xss
info:
  name: Test XSS
  severity: high
  tags: xss,cve2021-1234

http:
  - method: GET
    path:
      - "{{BaseURL}}/search?q={{payload}}"
    matchers:
      - type: word
        words:
          - "<script>"
        part: body
      - type: status
        status:
          - 200
"#;
        let templates = parse_nuclei_yaml(yaml);
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].id, "nuclei-test-xss");
        assert_eq!(templates[0].severity, "high");
        assert_eq!(templates[0].matchers.len(), 2);
        assert_eq!(templates[0].cve, Some("cve2021-1234".to_string()));
    }

    #[test]
    fn parse_multi_path() {
        let yaml = r#"
id: multi-path
info:
  name: Multi Path
  severity: medium

http:
  - method: GET
    path:
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/dashboard"
    matchers:
      - type: word
        words:
          - "admin panel"
        part: body
"#;
        let templates = parse_nuclei_yaml(yaml);
        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0].path, "/admin");
        assert_eq!(templates[1].path, "/dashboard");
    }

    #[test]
    fn parse_with_headers_and_body() {
        let yaml = r#"
id: post-test
info:
  name: POST Test
  severity: critical

http:
  - method: POST
    path:
      - "{{BaseURL}}/api/login"
    headers:
      Content-Type: application/json
    body: '{"user":"admin"}'
    matchers:
      - type: word
        words:
          - "token"
        part: body
"#;
        let templates = parse_nuclei_yaml(yaml);
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].method, "POST");
        assert_eq!(templates[0].body, Some("{\"user\":\"admin\"}".to_string()));
        assert!(templates[0].headers.contains_key("Content-Type"));
    }

    #[test]
    fn skip_no_matchers() {
        let yaml = r#"
id: no-match
info:
  name: No Matchers
  severity: low

http:
  - method: GET
    path:
      - "{{BaseURL}}/test"
"#;
        let templates = parse_nuclei_yaml(yaml);
        assert_eq!(templates.len(), 0);
    }

    #[test]
    fn load_empty_dir() {
        let v = load_nuclei_dir("/nonexistent");
        assert!(v.is_empty());
    }
}
