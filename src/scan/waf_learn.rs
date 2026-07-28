//! WAF Learning Mode — detects WAF type, auto-selects stealth mode,
//! suggests bypass techniques based on WAF fingerprint.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use std::collections::HashMap;

const WAF_SIGNATURES: &[(&str, &[&str])] = &[
    ("Cloudflare", &["cloudflare", "__cfduid", "cf-ray", "cf-cache-status"]),
    ("Akamai", &["akamai", "akamaighost"]),
    ("Imperva/Incapsula", &["incapsula", "imperva", "X-Iinfo"]),
    ("AWS WAF", &["awswaf", "x-amzn-requestid", "x-amzn-errortype"]),
    ("F5 BIG-IP", &["big-ip", "f5"]),
    ("Fortinet FortiWeb", &["fortiwaf", "fortinet"]),
    ("Sucuri", &["sucuri", "cloudproxy"]),
    ("ModSecurity", &["mod_security", "modsecurity"]),
    ("Wordfence", &["wordfence"]),
    ("Barracuda", &["barracuda"]),
    ("Citrix NetScaler", &["netscaler", "nsc_"]),
    ("Radware", &["radware", "appwall"]),
    ("Comodo WAF", &["comodo"]),
    ("Airlock", &["airlock"]),
    ("Approach", &["approach"]),
    ("Hyperguard", &["hyperguard"]),
];

const CLOUDFLARE_BYPASS_TIPS: &[&str] = &[
    "Use www subdomain (CF may not proxy it)",
    "Find origin IP via crt.sh historical DNS",
    "Use X-Forwarded-For: 127.0.0.1",
    "Use True-Client-IP header",
    "Try direct IP:443 if origin IP found",
    "Use HTTP/1.0 instead of HTTP/1.1",
    "Try different port (8080, 8443) on origin IP",
    "Use Cloudflare Workers bypass techniques",
];

const AKAMAI_BYPASS_TIPS: &[&str] = &[
    "Try X-Forwarded-For spoofing",
    "Try True-Client-IP header",
    "Use HTTP/2 connection",
    "Modify User-Agent to known Akamai crawler",
];

const GENERIC_BYPASS_TIPS: &[&str] = &[
    "Use different HTTP methods (POST vs GET)",
    "Add random query parameters",
    "Encode payload with URL encoding",
    "Use Unicode/UTF-8 encoding",
    "Split payload across multiple parameters",
    "Use HTTP parameter pollution",
    "Send payload in headers instead of body",
    "Use chunked transfer encoding",
    "Add random comments in payload (/**/)",
    "Use case variations (SeLeCt vs select)",
    "Use null bytes in payload",
    "Try different Content-Type headers",
];

/// Detect WAF from response headers + body + status code.
pub fn detect_waf(st: u16, headers: &str, body: &str) -> Option<String> {
    let combined = format!("{} {} {}", st, headers.to_lowercase(), body.to_lowercase());

    for (name, sigs) in WAF_SIGNATURES {
        if sigs.iter().any(|s| combined.contains(s)) {
            return Some(name.to_string());
        }
    }

    // Generic detection based on status codes
    if st == 403 {
        let body_lower = body.to_lowercase();
        if body_lower.contains("cloudflare") || body_lower.contains("cf-error") {
            return Some("Cloudflare".to_string());
        }
        if body_lower.contains("reference") && body_lower.contains("#") {
            return Some("Unknown WAF (block page)".to_string());
        }
    }

    None
}

/// Get bypass suggestions for a specific WAF
pub fn bypass_tips(waf_name: &str) -> Vec<String> {
    let mut tips = Vec::new();
    match waf_name {
        "Cloudflare" => tips.extend(CLOUDFLARE_BYPASS_TIPS.iter().map(|s| s.to_string())),
        "Akamai" => tips.extend(AKAMAI_BYPASS_TIPS.iter().map(|s| s.to_string())),
        _ => {}
    }
    // Add generic tips
    tips.extend(GENERIC_BYPASS_TIPS.iter().take(5).map(|s| s.to_string()));
    tips
}

/// Full WAF learning scan
pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut out = Vec::new();
    let base = target.trim_end_matches('/');

    // Baseline: normal request
    let baseline = http.get(&format!("{}/", base)).await.ok();
    let (baseline_st, baseline_headers, baseline_body) = match &baseline {
        Some((st, h, b, _)) => (*st, h.clone(), b.clone()),
        None => (0, String::new(), String::new()),
    };

    // Probe with malicious-looking request
    let probe_url = format!("{}/?id=1'+UNION+SELECT+1--", base);
    let probe = http.get(&probe_url).await.ok();
    let (probe_st, probe_headers, probe_body) = match &probe {
        Some((st, h, b, _)) => (*st, h.clone(), b.clone()),
        None => (0, String::new(), String::new()),
    };

    // Detect WAF from probe response
    let waf_name = detect_waf(probe_st, &probe_headers, &probe_body);
    let baseline_waf = detect_waf(baseline_st, &baseline_headers, &baseline_body);
    let detected_waf = waf_name.or(baseline_waf);

    if let Some(waf) = detected_waf {
        out.push(
            Finding::new(Severity::Info, "WAF-LEARN", &format!("WAF detected: {}", waf), target)
                .with_evidence(&format!("Probe returned HTTP {}, baseline HTTP {}", probe_st, baseline_st))
                .with_confidence(85),
        );

        // WAF bypass tips
        let tips = bypass_tips(&waf);
        if !tips.is_empty() {
            out.push(
                Finding::new(Severity::Info, "WAF-LEARN", &format!("Bypass suggestions for {}", waf), target)
                    .with_evidence(&format!("{} bypass techniques available", tips.len()))
                    .with_note(&tips.iter().take(5).cloned().collect::<Vec<_>>().join("; "))
                    .with_confidence(70),
            );
        }

        // Auto-suggest stealth mode if WAF is aggressive
        if probe_st == 403 || probe_st == 429 || probe_st == 419 {
            out.push(
                Finding::new(Severity::Low, "WAF-LEARN", "WAF is blocking probes — consider stealth mode", target)
                    .with_evidence(&format!("Probe returned HTTP {} — WAF is aggressive", probe_st))
                    .with_note("Use -m stealth to reduce request rate and avoid triggering WAF")
                    .with_confidence(90),
            );
        }
    }

    // Check if response differs significantly (WAF interference)
    if probe_st != baseline_st && probe_st != 0 && baseline_st != 0 {
        out.push(
            Finding::new(Severity::Info, "WAF-LEARN", "WAF modifies response based on payload", target)
                .with_evidence(&format!("Baseline HTTP {}, Probe HTTP {}", baseline_st, probe_st))
                .with_confidence(75),
        );
    }

    // Try a simple bypass to test WAF strictness
    if mode.attempt_bypass() {
        let bypass_headers = HashMap::from([
            ("X-Forwarded-For".to_string(), "127.0.0.1".to_string()),
        ]);
        if let Ok((bypass_st, _bypass_h, _bypass_b, _)) = http.fetch(&probe_url, reqwest::Method::GET, None, Some(bypass_headers)).await {
            if bypass_st == 200 && probe_st == 403 {
                out.push(
                    Finding::new(Severity::Medium, "WAF-LEARN", "WAF bypass possible via X-Forwarded-For header", target)
                        .with_evidence(&format!("Blocked HTTP {}, bypass HTTP {}", probe_st, bypass_st))
                        .with_confidence(70),
                );
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detect_cloudflare_from_headers() {
        let h = "server: cloudflare\ncf-ray: abc123\n";
        assert_eq!(detect_waf(403, h, ""), Some("Cloudflare".to_string()));
    }
    #[test]
    fn detect_akamai_from_headers() {
        let h = "x-akamai-request-id: abc\n";
        assert_eq!(detect_waf(403, h, ""), Some("Akamai".to_string()));
    }
    #[test]
    fn detect_unknown_gives_none() {
        let h = "server: nginx\n";
        assert_eq!(detect_waf(200, h, ""), None);
    }
    #[test]
    fn waf_signatures_non_empty() {
        assert!(WAF_SIGNATURES.len() > 10);
    }
}
