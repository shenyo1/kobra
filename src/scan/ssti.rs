use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use anyhow::Result;

/// Server-Side Template Injection.
/// Sends `{{7*7}}` etc and looks for evaluation evidence in the response.
///
/// CRITICAL: uses a NEGATIVE CONTROL. Many pages contain "49" innocuously
/// (SVG coordinates, port numbers, CSS). We only flag evaluation if the
/// evidence string appears in the PAYLOAD response but NOT in the BASELINE
/// (same URL without the template payload). This kills false positives from
/// static pages that happen to contain "49".
pub async fn scan(http: &HttpClient, target: &str, params: &[String], _mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = if target.contains('?') {
        target.to_string()
    } else {
        format!("{}/?q=test", target.trim_end_matches('/'))
    };

    // Unique markers that ONLY appear if the engine truly evaluates them.
    let probes: Vec<(&str, &str, &str)> = vec![
        // (label, payload, evidence-marker that must appear ONLY after eval)
        ("freemarker", "<#if 7*7==49>KOBRA_OK</#if>", "KOBRA_OK"),
        ("jinja/twig", "{{999999*999999}}", "998996000001"),
        ("twig/php", "${{999999*999999}}", "998996000001"),
        ("mako/erb/ruby", "#{999999*999999}", "998996000001"),
        ("velocity", "#set($x=999999*999999)$x", "998996000001"),
    ];

    for p in params {
        // Negative control: fetch baseline (marker that will NOT evaluate)
        let base_url = inject(&base, p, "k0bra_n0eval_marker_xyz");
        let baseline_has_marker = if let Ok((_s, _h, b, _f)) = http.get(&base_url).await {
            b.contains("998996000001") || b.contains("KOBRA_OK") || b.contains("49")
        } else {
            false
        };

        for (_label, payload, marker) in &probes {
            let u = inject(&base, p, payload);
            if let Ok((_st, _h, body, _f, raw)) = http.get_full(&u).await {
                // The arithmetic result must appear in the eval response.
                let eval_evidence = body.contains(marker);
                // And it must NOT be present in the baseline page (negative control).
                if eval_evidence && !baseline_has_marker {
                    out.push(
                        Finding::new(Severity::High, "SSTI", "Server-Side Template Injection", target)
                            .with_param(p)
                            .with_payload(*payload)
                            .with_evidence(&format!("template expression evaluated ({})", marker))
                            .with_response(&raw)
                            .with_confidence(90),
                    );
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
