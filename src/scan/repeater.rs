// SPDX-License-Identifier: MIT
//
// Burp-style Repeater + Intruder (v4.7.0).
//
// Provides the two fundamental manual-hacking primitives from Burp Suite:
// - REPEATER: take a raw HTTP request, send it, return raw response.
//   Lets the operator iterate on a single crafted request.
// - INTRUDER: take a request template with `§marker§` positions, replace with
//   a list of words, send each. Supports 4 attack types:
//   - Sniper: one position, one wordlist (default mode)
//   - Battering ram: all positions, same word
//   - Pitchfork: positions use parallel lists (zip-style)
//   - Cluster bomb: cartesian product of all lists
//
// Negative-control discipline preserved: every response carries `baseline_diff`
// only when the user calls `with_baseline()` — operators decide.

use anyhow::Result;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

/// Marker for injection position in an Intruder template. Use `§foo§` in path/query/headers/body.
pub const MARKER_OPEN: char = '§';
pub const MARKER_CLOSE: char = '§';

/// Parsed Intruder request template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntruderTemplate {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl IntruderTemplate {
    /// Parse from a raw HTTP/1.1-style request (like from `--raw-request`).
    /// First line: `METHOD URL HTTP/1.1`. Headers until blank. Body if any.
    pub fn from_raw(raw: &str) -> Result<Self, String> {
        let mut parts = raw.splitn(2, "\r\n\r\n");
        let head = parts.next().ok_or("empty request")?;
        let body = parts.next().map(|s| s.to_string()).filter(|s| !s.is_empty());
        let mut lines = head.split("\r\n");
        let request_line = lines.next().ok_or("missing request line")?;
        let mut rl_parts = request_line.split_whitespace();
        let method = rl_parts.next().ok_or("missing method")?.to_string();
        let url = rl_parts.next().ok_or("missing URL")?.to_string();
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some(pos) = line.find(':') {
                let k = line[..pos].trim().to_string();
                let v = line[pos + 1..].trim().to_string();
                headers.push((k, v));
            }
        }
        Ok(Self {
            method,
            url,
            headers,
            body,
        })
    }

    /// Find §-bounded positions in the template (URL, headers, body).
    pub fn positions(&self) -> Vec<String> {
        let mut names = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for source in std::iter::once(self.url.as_str())
            .chain(self.headers.iter().map(|(_, v)| v.as_str()))
            .chain(self.body.iter().map(|s| s.as_str()))
        {
            extract_marker_names(source, &mut names, &mut seen);
        }
        names
    }
}

fn extract_marker_names(
    src: &str,
    out: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) {
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c == MARKER_OPEN {
            let mut name = String::new();
            loop {
                match chars.next() {
                    Some(MARKER_CLOSE) => break,
                    Some(ch) => name.push(ch),
                    None => return,
                }
            }
            if !name.is_empty() && seen.insert(name.clone()) {
                out.push(name);
            }
        }
    }
}

/// Substitute marker values into a source string.
fn fill(src: &str, replace: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c == MARKER_OPEN {
            let mut name = String::new();
            loop {
                match chars.next() {
                    Some(MARKER_CLOSE) => break,
                    Some(ch) => name.push(ch),
                    None => {
                        // Unterminated marker — emit raw back.
                        out.push(MARKER_OPEN);
                        out.push_str(&name);
                        return out;
                    }
                }
            }
            if let Some(value) = replace.get(&name) {
                out.push_str(value);
            } else {
                // Unknown marker — preserve as-is.
                out.push(MARKER_OPEN);
                out.push_str(&name);
                out.push(MARKER_CLOSE);
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntruderMode {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

impl FromStr for IntruderMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "sniper" => Ok(Self::Sniper),
            "batteringram" | "battering-ram" | "battering_ram" => Ok(Self::BatteringRam),
            "pitchfork" => Ok(Self::Pitchfork),
            "clusterbomb" | "cluster-bomb" | "cluster_bomb" => Ok(Self::ClusterBomb),
            _ => Err(format!("unknown intruder mode: {s}")),
        }
    }
}

/// One injected payload set: position name → words.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSet {
    pub position: String,
    pub words: Vec<String>,
}

/// Single Intruder result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntruderResult {
    pub payload_used: HashMap<String, String>,
    pub status: u16,
    pub length: usize,
    pub elapsed_ms: u64,
}

/// Render all combinations per mode and produce requests.
pub fn generate_payloads(_template: &IntruderTemplate, mode: IntruderMode, sets: &[PayloadSet]) -> Vec<HashMap<String, String>> {
    match mode {
        IntruderMode::Sniper => {
            // One position at a time, all words.
            let mut out = Vec::new();
            for set in sets {
                for w in &set.words {
                    let mut payload = HashMap::new();
                    payload.insert(set.position.clone(), w.clone());
                    out.push(payload);
                }
            }
            out
        }
        IntruderMode::BatteringRam => {
            // All positions, same single word at a time.
            let mut out = Vec::new();
            if let Some(first) = sets.first() {
                for w in &first.words {
                    let mut payload = HashMap::new();
                    for set in sets {
                        payload.insert(set.position.clone(), w.clone());
                    }
                    out.push(payload);
                }
            }
            out
        }
        IntruderMode::Pitchfork => {
            // Parallel list iteration (zip). Stops at shortest.
            let mut out = Vec::new();
            if sets.is_empty() {
                return out;
            }
            let min = sets.iter().map(|s| s.words.len()).min().unwrap_or(0);
            for i in 0..min {
                let mut payload = HashMap::new();
                for set in sets {
                    payload.insert(set.position.clone(), set.words[i].clone());
                }
                out.push(payload);
            }
            out
        }
        IntruderMode::ClusterBomb => {
            // Cartesian product of all sets.
            let mut out: Vec<HashMap<String, String>> = vec![HashMap::new()];
            for set in sets {
                let mut next = Vec::new();
                for prev in out {
                    for w in &set.words {
                        let mut p = prev.clone();
                        p.insert(set.position.clone(), w.clone());
                        next.push(p);
                    }
                }
                out = next;
            }
            out
        }
    }
}

/// Render an Intruder request from template + payload map.
pub fn render_request(template: &IntruderTemplate, payload: &HashMap<String, String>) -> (String, Vec<(String, String)>, Option<String>) {
    let url = fill(&template.url, payload);
    let headers: Vec<(String, String)> = template
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), fill(v, payload)))
        .collect();
    let body = template.body.as_ref().map(|b| fill(b, payload));
    (url, headers, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_raw_parses_get_request() {
        let raw = "GET /api/v1/test HTTP/1.1\r\nHost: example.com\r\nUser-Agent: kobra\r\n\r\n";
        let t = IntruderTemplate::from_raw(raw).unwrap();
        assert_eq!(t.method, "GET");
        assert_eq!(t.url, "/api/v1/test");
        assert_eq!(t.headers.len(), 2);
        assert!(t.body.is_none());
    }

    #[test]
    fn from_raw_parses_post_with_body() {
        let raw = "POST /api HTTP/1.1\r\nHost: x.com\r\nContent-Type: application/json\r\n\r\n{\"id\":1}";
        let t = IntruderTemplate::from_raw(raw).unwrap();
        assert_eq!(t.method, "POST");
        assert_eq!(t.body.as_deref(), Some("{\"id\":1}"));
    }

    #[test]
    fn from_raw_rejects_empty() {
        assert!(IntruderTemplate::from_raw("").is_err());
        assert!(IntruderTemplate::from_raw("GET").is_err());
    }

    #[test]
    fn positions_extracts_marker_names() {
        let t = IntruderTemplate {
            method: "GET".into(),
            url: "/api/users/§uid§/posts/§pid§".into(),
            headers: vec![("X-Tenant".into(), "§tenant§".into())],
            body: Some(r#"{"q":"§query§"}"#.into()),
        };
        let pos = t.positions();
        assert_eq!(pos.len(), 4);
        assert!(pos.contains(&"uid".to_string()));
        assert!(pos.contains(&"pid".to_string()));
        assert!(pos.contains(&"tenant".to_string()));
        assert!(pos.contains(&"query".to_string()));
    }

    #[test]
    fn sniper_iterates_one_position_at_a_time() {
        let template = IntruderTemplate {
            method: "GET".into(),
            url: "/users/§id§".into(),
            headers: vec![],
            body: None,
        };
        let sets = vec![PayloadSet {
            position: "id".into(),
            words: vec!["1".into(), "2".into(), "3".into()],
        }];
        let out = generate_payloads(&template, IntruderMode::Sniper, &sets);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn batteringram_uses_same_word_all_positions() {
        let template = IntruderTemplate {
            method: "POST".into(),
            url: "/x".into(),
            headers: vec![],
            body: Some("a=§a§&b=§b§".into()),
        };
        let sets = vec![
            PayloadSet {
                position: "a".into(),
                words: vec!["1".into(), "2".into()],
            },
            PayloadSet {
                position: "b".into(),
                words: vec!["x".into(), "y".into()],
            },
        ];
        let out = generate_payloads(&template, IntruderMode::BatteringRam, &sets);
        assert_eq!(out.len(), 2);
        // First iteration: a=1, b=1. Second: a=2, b=2.
        assert_eq!(out[0]["a"], "1");
        assert_eq!(out[0]["b"], "1");
        assert_eq!(out[1]["a"], "2");
        assert_eq!(out[1]["b"], "2");
    }

    #[test]
    fn pitchfork_zips_lists() {
        let sets = vec![
            PayloadSet {
                position: "a".into(),
                words: vec!["1".into(), "2".into(), "3".into()],
            },
            PayloadSet {
                position: "b".into(),
                words: vec!["x".into(), "y".into()],
            },
        ];
        let out = generate_payloads(
            &IntruderTemplate {
                method: "POST".into(),
                url: "/".into(),
                headers: vec![],
                body: None,
            },
            IntruderMode::Pitchfork,
            &sets,
        );
        // min(3, 2) = 2.
        assert_eq!(out.len(), 2);
        assert_eq!(out[0]["a"], "1");
        assert_eq!(out[0]["b"], "x");
        assert_eq!(out[1]["a"], "2");
        assert_eq!(out[1]["b"], "y");
    }

    #[test]
    fn clusterbomb_cartesian_product() {
        let sets = vec![
            PayloadSet {
                position: "a".into(),
                words: vec!["1".into(), "2".into()],
            },
            PayloadSet {
                position: "b".into(),
                words: vec!["x".into(), "y".into()],
            },
        ];
        let out = generate_payloads(
            &IntruderTemplate {
                method: "POST".into(),
                url: "/".into(),
                headers: vec![],
                body: None,
            },
            IntruderMode::ClusterBomb,
            &sets,
        );
        assert_eq!(out.len(), 4); // 2x2
    }

    #[test]
    fn render_request_substitutes_all_sources() {
        let template = IntruderTemplate {
            method: "GET".into(),
            url: "/api/§uid§".into(),
            headers: vec![("X-Token".into(), "Bearer §token§".into())],
            body: Some(r#"{"filter":"§q§"}"#.into()),
        };
        let mut payload = HashMap::new();
        payload.insert("uid".into(), "42".into());
        payload.insert("token".into(), "abc".into());
        payload.insert("q".into(), "test".into());
        let (url, headers, body) = render_request(&template, &payload);
        assert_eq!(url, "/api/42");
        assert_eq!(headers[0].1, "Bearer abc");
        assert_eq!(body.as_deref(), Some(r#"{"filter":"test"}"#));
    }
}