//! Passive Proxy Mode — lightweight HTTP proxy that logs traffic and
//! passively detects vulnerabilities without sending active probes.
//! Complements active scanning by analyzing real user traffic.

use crate::types::{Finding, Severity};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A logged HTTP request/response pair from the proxy
#[derive(Debug, Clone)]
pub struct TrafficEntry {
    pub method: String,
    pub url: String,
    pub request_headers: HashMap<String, String>,
    pub request_body: Option<String>,
    pub status: u16,
    pub response_headers: HashMap<String, String>,
    pub response_body: String,
}

/// Passive analyzer — inspects traffic for security issues
pub struct PassiveAnalyzer {
    pub entries: Arc<Mutex<Vec<TrafficEntry>>>,
}

impl PassiveAnalyzer {
    pub fn new() -> Self {
        PassiveAnalyzer {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Record a traffic entry
    pub fn record(&self, entry: TrafficEntry) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(entry);
        }
    }

    /// Analyze all recorded traffic for passive findings
    pub fn analyze(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        let entries = match self.entries.lock() {
            Ok(e) => e.clone(),
            Err(_) => return findings,
        };

        for entry in &entries {
            // 1. Missing security headers
            self.check_security_headers(entry, &mut findings);

            // 2. Sensitive data in responses
            self.check_sensitive_data(entry, &mut findings);

            // 3. Cookie security
            self.check_cookies(entry, &mut findings);

            // 4. CORS misconfiguration
            self.check_cors(entry, &mut findings);

            // 5. Information disclosure
            self.check_info_disclosure(entry, &mut findings);
        }

        findings
    }

    fn check_security_headers(&self, entry: &TrafficEntry, findings: &mut Vec<Finding>) {
        let headers_lower: HashMap<String, String> = entry
            .response_headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v.clone()))
            .collect();

        let required = [
            ("strict-transport-security", "HSTS header missing"),
            ("x-content-type-options", "X-Content-Type-Options missing"),
            ("x-frame-options", "X-Frame-Options missing (clickjacking risk)"),
            ("content-security-policy", "Content-Security-Policy missing"),
        ];

        for (header, desc) in &required {
            if !headers_lower.contains_key(*header) && entry.status == 200 {
                findings.push(
                    Finding::new(Severity::Low, "PASSIVE", desc, &entry.url)
                        .with_evidence(&format!("Response HTTP {} lacks {} header", entry.status, header))
                        .with_confidence(80),
                );
            }
        }
    }

    fn check_sensitive_data(&self, entry: &TrafficEntry, findings: &mut Vec<Finding>) {
        let body_lower = entry.response_body.to_lowercase();

        // API keys / tokens in response
        let patterns = [
            ("api_key", "Possible API key in response"),
            ("apikey", "Possible API key in response"),
            ("secret_key", "Possible secret key in response"),
            ("access_token", "Possible access token in response"),
            ("private_key", "Possible private key in response"),
            ("aws_secret", "Possible AWS secret in response"),
            ("password", "Possible password in response"),
        ];

        for (pattern, desc) in &patterns {
            if body_lower.contains(pattern) && entry.status == 200 {
                findings.push(
                    Finding::new(Severity::Medium, "PASSIVE", desc, &entry.url)
                        .with_evidence(&format!("Response contains '{}'", pattern))
                        .with_confidence(50),
                );
            }
        }

        // Stack traces / debug info
        let debug_patterns = [
            ("traceback (most recent call last)", "Python stack trace exposed"),
            ("at com.", "Java stack trace exposed"),
            ("stack trace:", "Stack trace exposed"),
            ("fatal error:", "PHP fatal error exposed"),
            ("warning:", "PHP warning exposed"),
            ("syntax error", "SQL/syntax error exposed"),
        ];

        for (pattern, desc) in &debug_patterns {
            if body_lower.contains(pattern) {
                findings.push(
                    Finding::new(Severity::Medium, "PASSIVE", desc, &entry.url)
                        .with_evidence(&format!("Response contains '{}'", pattern))
                        .with_confidence(70),
                );
            }
        }
    }

    fn check_cookies(&self, entry: &TrafficEntry, findings: &mut Vec<Finding>) {
        for (k, v) in &entry.response_headers {
            if k.to_lowercase() == "set-cookie" {
                let cookie_lower = v.to_lowercase();
                if !cookie_lower.contains("httponly") {
                    findings.push(
                        Finding::new(Severity::Low, "PASSIVE", "Cookie missing HttpOnly flag", &entry.url)
                            .with_evidence(&format!("Set-Cookie: {}", &v[..v.len().min(80)]))
                            .with_confidence(85),
                    );
                }
                if !cookie_lower.contains("secure") && entry.url.starts_with("https") {
                    findings.push(
                        Finding::new(Severity::Low, "PASSIVE", "Cookie missing Secure flag", &entry.url)
                            .with_evidence(&format!("Set-Cookie: {}", &v[..v.len().min(80)]))
                            .with_confidence(85),
                    );
                }
                if !cookie_lower.contains("samesite") {
                    findings.push(
                        Finding::new(Severity::Info, "PASSIVE", "Cookie missing SameSite attribute", &entry.url)
                            .with_evidence(&format!("Set-Cookie: {}", &v[..v.len().min(80)]))
                            .with_confidence(70),
                    );
                }
            }
        }
    }

    fn check_cors(&self, entry: &TrafficEntry, findings: &mut Vec<Finding>) {
        for (k, v) in &entry.response_headers {
            if k.to_lowercase() == "access-control-allow-origin" && v == "*" {
                // Check if credentials are also allowed
                let has_creds = entry.response_headers.iter().any(|(hk, hv)| {
                    hk.to_lowercase() == "access-control-allow-credentials" && hv == "true"
                });
                if has_creds {
                    findings.push(
                        Finding::new(Severity::High, "PASSIVE", "CORS wildcard with credentials", &entry.url)
                            .with_evidence("Access-Control-Allow-Origin: * + Access-Control-Allow-Credentials: true")
                            .with_confidence(90),
                    );
                } else {
                    findings.push(
                        Finding::new(Severity::Info, "PASSIVE", "CORS wildcard origin", &entry.url)
                            .with_evidence("Access-Control-Allow-Origin: *")
                            .with_confidence(70),
                    );
                }
            }
        }
    }

    fn check_info_disclosure(&self, entry: &TrafficEntry, findings: &mut Vec<Finding>) {
        for (k, v) in &entry.response_headers {
            let kl = k.to_lowercase();
            if kl == "x-powered-by" || kl == "x-aspnet-version" || kl == "x-aspnetmvc-version" {
                findings.push(
                    Finding::new(Severity::Info, "PASSIVE", &format!("Technology disclosure: {}", k), &entry.url)
                        .with_evidence(&format!("{}: {}", k, v))
                        .with_confidence(90),
                );
            }
            if kl == "server" && (v.contains("Apache") || v.contains("nginx") || v.contains("Microsoft")) {
                // Only flag if version is disclosed
                if v.contains('/') {
                    findings.push(
                        Finding::new(Severity::Info, "PASSIVE", "Server version disclosed", &entry.url)
                            .with_evidence(&format!("Server: {}", v))
                            .with_confidence(80),
                    );
                }
            }
        }
    }
}

impl Default for PassiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> TrafficEntry {
        let mut resp_headers = HashMap::new();
        resp_headers.insert("set-cookie".to_string(), "session=abc123; Path=/".to_string());
        resp_headers.insert("x-powered-by".to_string(), "Express".to_string());

        TrafficEntry {
            method: "GET".to_string(),
            url: "https://example.com/api/users".to_string(),
            request_headers: HashMap::new(),
            request_body: None,
            status: 200,
            response_headers: resp_headers,
            response_body: r#"{"users": [{"id": 1, "name": "admin"}]}"#.to_string(),
        }
    }

    #[test]
    fn detect_missing_headers() {
        let analyzer = PassiveAnalyzer::new();
        analyzer.record(sample_entry());
        let findings = analyzer.analyze();
        assert!(findings.iter().any(|f| f.title.contains("HSTS")));
        assert!(findings.iter().any(|f| f.title.contains("X-Content-Type")));
    }

    #[test]
    fn detect_cookie_issues() {
        let analyzer = PassiveAnalyzer::new();
        analyzer.record(sample_entry());
        let findings = analyzer.analyze();
        assert!(findings.iter().any(|f| f.title.contains("HttpOnly")));
        assert!(findings.iter().any(|f| f.title.contains("Secure")));
    }

    #[test]
    fn detect_tech_disclosure() {
        let analyzer = PassiveAnalyzer::new();
        analyzer.record(sample_entry());
        let findings = analyzer.analyze();
        assert!(findings.iter().any(|f| f.title.contains("Technology disclosure")));
    }

    #[test]
    fn empty_analyzer() {
        let analyzer = PassiveAnalyzer::new();
        let findings = analyzer.analyze();
        assert!(findings.is_empty());
    }
}
