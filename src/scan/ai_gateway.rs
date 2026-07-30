//! AI Gateway detector (Lesson 4 fix v4.4.0).
//! Lesson: KOBRA v4.3.0 missed LiteLLM at ai.sumopod.com (uvicorn server).
//! Fix: detect LiteLLM/vLLM/OpenAI-compatible gateways.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};

const AI_PATHS: &[&str] = &[
    "/v1/models",
    "/v1/chat/completions",
    "/v1/embeddings",
    "/v1/completions",
    "/v1/files",
    "/v1/audio/speech",
    "/v1/assistants",
    "/health",
    "/health/liveliness",
    "/health/readiness",
];

pub fn classify_ai_response(body: &str, _h: &str, server: &str) -> Option<(&'static str, &'static str)> {
    let body_l = body.to_lowercase();
    let srv_l = server.to_lowercase();
    if body_l.contains("litellm") || body_l.contains("invalid proxy server token") {
        return Some(("LiteLLM", "LiteLLM proxy (uvicorn ASGI server)"));
    }
    if body.contains("LiteLLM Virtual Key expected") {
        return Some(("LiteLLM", "LiteLLM proxy virtual key auth"));
    }
    // v4.4.0 Lesson 4 fix: uvicorn + api key = LiteLLM (check BEFORE generic OpenAI-compatible, verified v4.7.0)
    // because LiteLLM also returns the generic "error":{"message":"..."} envelope)
    if srv_l.contains("uvicorn") && body.contains("api key") {
        return Some(("LiteLLM", "uvicorn + api key = likely LiteLLM"));
    }
    if body_l.contains("vllm") || srv_l.contains("vllm") {
        return Some(("vLLM", "vLLM serving engine"));
    }
    if body.contains("\"object\":\"model\"") || body.contains("Incorrect API key provided") {
        return Some(("OpenAI", "OpenAI API direct"));
    }
    // Generic OpenAI-compatible — fallback for non-uvicorn servers
    if body.contains("\"error\":{\"message\":") && body.contains("api key") {
        return Some(("OpenAI-Compatible", "Generic OpenAI-compatible API"));
    }
    None
}

pub async fn scan(http: &HttpClient, target: &str, _mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    // Parse base URL: strip path/query to root (Lesson 4 v4.4.0 fix)
    let base = {
        let u = target.trim_end_matches('/');
        let (proto, rest) = if u.contains("://") {
            let idx = u.find("://").unwrap();
            (u[..idx + 3].to_string(), u[idx + 3..].to_string())
        } else {
            ("https://".to_string(), u.to_string())
        };
        let path_start = rest.find('/').unwrap_or(rest.len());
        format!("{}{}", proto, &rest[..path_start])
    };
    for path in AI_PATHS {
        let url = format!("{}{}", base, path);
        if let Ok((status, headers, body, _f)) = http.get(&url).await {
            let server = headers.lines()
                .find(|l| l.to_lowercase().starts_with("server:"))
                .unwrap_or("")
                .to_string();
            if let Some((vendor, desc)) = classify_ai_response(&body, &headers, &server) {
                // Severity based on exposure level
                let severity = if path.contains("chat") || path.contains("embedding") || path.contains("files") {
                    // Write/sensitive endpoints = Medium
                    Severity::Medium
                } else if path.contains("models") || path.contains("assistants") {
                    // Read-only listing = Low
                    Severity::Low
                } else if path.contains("health") {
                    // Health probes = Info
                    Severity::Info
                } else {
                    // Unknown endpoints = Info (presence)
                    Severity::Info
                };
                findings.push(Finding {
                    severity,
                    category: "AI-GATEWAY".into(),
                    title: format!("AI gateway detected: {} ({})", vendor, path),
                    target: url.clone(),
                    param: None,
                    payload: None,
                    evidence: Some(format!(
                        "Endpoint {} status={} matches {} signature. Desc: {}. Server: {}",
                        url, status, vendor, desc, server.trim())),
                    confidence: 80,
                    note: Some("Lesson 4 fix v4.4.0: AI gateway detection.".into()),
                    request: None,
                    response: None,
                });
            }
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_litellm_proxy_error() {
        let body = r#"{"error":{"message":"Authentication Error, Invalid proxy server token passed."}}"#;
        assert_eq!(classify_ai_response(body, "", "").unwrap().0, "LiteLLM");
    }

    #[test]
    fn detect_litellm_virtual_key() {
        let body = "LiteLLM Virtual Key expected. Received=****, expected to start with sk-.";
        assert_eq!(classify_ai_response(body, "", "").unwrap().0, "LiteLLM");
    }

    #[test]
    fn detect_uvicorn_with_apikey() {
        let body = r#"{"error":{"message":"No api key passed in."}}"#;
        let server = "uvicorn";
        assert_eq!(classify_ai_response(body, "", server).unwrap().0, "LiteLLM");
    }

    #[test]
    fn detect_openai_direct() {
        let body = r#"{"error":{"message":"Incorrect API key provided: sk-***"}}"#;
        assert_eq!(classify_ai_response(body, "", "").unwrap().0, "OpenAI");
    }

    #[test]
    fn detect_vllm() {
        let body = "vLLM server is ready";
        assert_eq!(classify_ai_response(body, "", "").unwrap().0, "vLLM");
    }

    #[test]
    fn detect_generic_openai_compatible() {
        let body = r#"{"error":{"message":"Invalid api key"},"type":"auth_error"}"#;
        assert_eq!(classify_ai_response(body, "", "").unwrap().0, "OpenAI-Compatible");
    }

    #[test]
    fn no_match_random_response() {
        let body = "Hello World";
        assert!(classify_ai_response(body, "", "nginx").is_none());
    }

    #[test]
    fn sumopod_real_case() {
        // Real 2026-07-29 Sumopod: ai.sumopod.com/v1/models
        let body = r#"{"error":{"message":"Authentication Error, No api key passed in.","type":"auth_error","param":"None","code":"401"}}"#;
        let server = "uvicorn";
        let (vendor, _desc) = classify_ai_response(body, "", server).unwrap();
        assert_eq!(vendor, "LiteLLM");
    }
}
