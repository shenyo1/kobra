use serde::Serialize;

/// Severity — ALL levels shown, nothing hidden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
    pub fn color(&self) -> &'static str {
        match self {
            Severity::Info => "\x1b[36m",     // cyan
            Severity::Low => "\x1b[32m",      // green
            Severity::Medium => "\x1b[33m",   // yellow
            Severity::High => "\x1b[91m",     // red
            Severity::Critical => "\x1b[95m", // magenta
        }
    }
}

/// A single finding. We NEVER hide anything — full transparency for the operator.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: String,      // XSS, SQLi, SSRF, AUTH, WAF, INFO...
    pub title: String,
    pub target: String,
    pub param: Option<String>,
    pub payload: Option<String>,
    pub evidence: Option<String>,
    pub confidence: u8,        // 0-100
    pub note: Option<String>,
    pub request: Option<String>,   // raw HTTP request (for report proof)
    pub response: Option<String>,  // raw HTTP response (for report proof)
}

impl Finding {
    pub fn new(severity: Severity, category: &str, title: &str, target: &str) -> Self {
        Finding {
            severity,
            category: category.to_string(),
            title: title.to_string(),
            target: target.to_string(),
            param: None,
            payload: None,
            evidence: None,
            confidence: 50,
            note: None,
            request: None,
            response: None,
        }
    }
    pub fn with_param(mut self, p: &str) -> Self { self.param = Some(p.to_string()); self }
    pub fn with_payload(mut self, p: &str) -> Self { self.payload = Some(p.to_string()); self }
    pub fn with_evidence(mut self, e: &str) -> Self { self.evidence = Some(e.to_string()); self }
    pub fn with_confidence(mut self, c: u8) -> Self { self.confidence = c.min(100); self }
    pub fn with_note(mut self, n: &str) -> Self { self.note = Some(n.to_string()); self }
    pub fn with_request(mut self, r: &str) -> Self { self.request = Some(r.to_string()); self }
    pub fn with_response(mut self, r: &str) -> Self { self.response = Some(r.to_string()); self }
}

/// Scan mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Stealth,   // slow, minimal, low-noise
    Normal,    // balanced
    Crazy,     // ALL modules, MAX payloads, aggressive bypass attempts
}

impl Mode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "stealth" => Mode::Stealth,
            "crazy" | "gila" => Mode::Crazy,
            _ => Mode::Normal,
        }
    }
    pub fn concurrency(&self) -> usize {
        match self {
            Mode::Stealth => 3,
            Mode::Normal => 20,
            Mode::Crazy => 60,
        }
    }
    pub fn delay_ms(&self) -> u64 {
        match self {
            Mode::Stealth => 500,
            Mode::Normal => 50,
            Mode::Crazy => 0,
        }
    }
    pub fn payload_intensity(&self) -> usize {
        match self {
            Mode::Stealth => 8,
            Mode::Normal => 40,
            Mode::Crazy => 250,
        }
    }
    pub fn attempt_bypass(&self) -> bool {
        matches!(self, Mode::Normal | Mode::Crazy)
    }
}
