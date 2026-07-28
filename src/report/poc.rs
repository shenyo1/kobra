//! PoC (Proof of Concept) auto-generator.
//! Converts a KOBRA Finding into a reproducible curl command + bash script.

use crate::types::{Finding, Severity};
use std::fs;
use std::path::Path;

pub fn curl_for(finding: &Finding) -> String {
    let method = match finding.category.as_str() {
        "SQLi" | "RCE" | "NOSQL" | "SSTI" | "XXE" | "DESER" => "POST",
        "RACE" => "POST",
        "JWT" | "OAUTH" => "GET",
        "AUTH" | "AUTHFLOW" => "POST",
        "DOM-XSS" => "GET",
        "TAKEOVER" | "EXPOSED" | "SOURCEMAP" | "RECON" | "INFO" => "GET",
        _ => "GET",
    };

    let mut cmd = format!("curl -sk -X {} '{}'", method, finding.target);

    if let Some(payload) = &finding.payload {
        let escaped = payload.replace('\'', "'\\''");
        cmd.push_str(&format!(" \\\n  --data-binary '{}'", escaped));
    }

    if let Some(param) = &finding.param {
        cmd.push_str(&format!(" \\\n  # parameter: {}", param));
    }

    if let Some(note) = &finding.note {
        cmd.push_str(&format!(" \\\n  # note: {}", note.replace('\n', " ")));
    }

    cmd.push_str(&format!(
        " \\\n  --max-time 30 \\\n  -o response_evidence.txt -w '%{{http_code}}\\n'"
    ));
    cmd
}

pub fn bash_script(findings: &[Finding], engagement: &str) -> String {
    let mut out = String::new();
    out.push_str("#!/usr/bin/env bash\n");
    out.push_str("# KOBRA PoC bundle\n");
    out.push_str(&format!("# Engagement: {}\n", engagement));
    out.push_str(&format!("# Generated: {}\n", chrono_like_now()));
    out.push_str(&format!("# Total findings: {}\n\n", findings.len()));
    out.push_str("set -u  # don't set -e — some PoCs expected to fail\n\n");

    let mut n = 1;
    for f in findings {
        let label = format!("poc-{:03}-{}", n, slugify(&f.category));
        out.push_str(&format!("# ─── Finding #{} [{}] {} ───\n", n, f.severity.as_str(), f.title));
        out.push_str(&format!("# {} :: {}\n", f.category, f.target));
        if let Some(evidence) = &f.evidence {
            out.push_str(&format!("# Evidence: {}\n", truncate(evidence, 80)));
        }
        out.push_str(&format!("function {label}() {{\n"));
        out.push_str(&format!("  echo '>>> {label}'\n"));
        out.push_str(&format!("  {}\n", curl_for(f)));
        out.push_str(&format!("}}\n\n"));
        n += 1;
    }

    out.push_str("# Run all PoCs in order:\n");
    out.push_str("for fn in $(compgen -A function poc-); do \"$fn\"; done\n");
    out
}

pub fn write_poc_bundle(findings: &[Finding], engagement: &str, outdir: &str) -> std::io::Result<usize> {
    fs::create_dir_all(outdir)?;
    let script = bash_script(findings, engagement);
    let script_path = format!("{}/poc_all.sh", outdir);
    fs::write(&script_path, &script)?;

    let mut n = 0;
    for (i, f) in findings.iter().enumerate() {
        if f.severity >= Severity::High {
            let label = format!("poc-{:03}-{}.sh", i + 1, slugify(&f.category));
            let path = format!("{}/{}", outdir, label);
            let body = format!(
                "#!/usr/bin/env bash\n# {} :: {}\n# {}\n\n{}\n",
                f.severity.as_str(),
                f.title,
                f.target,
                curl_for(f)
            );
            fs::write(&path, body)?;
            n += 1;
        }
    }
    Ok(n)
}

fn slugify(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n])
    }
}

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{}s since epoch", dur.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;
    fn sample_finding() -> Finding {
        Finding {
            severity: Severity::High,
            category: "SQLi".into(),
            title: "Boolean SQLi at /search".into(),
            target: "https://x.com/search?q=test".into(),
            param: Some("q".into()),
            payload: Some("' OR 1=1--".into()),
            evidence: Some("DB error leaked".into()),
            confidence: 80,
            note: Some("Verify manually".into()),
            request: None,
            response: None,
        }
    }
    #[test]
    fn curl_contains_target() {
        let c = curl_for(&sample_finding());
        assert!(c.contains("https://x.com/search"));
        assert!(c.contains("curl -sk"));
    }
    #[test]
    fn curl_includes_payload() {
        let c = curl_for(&sample_finding());
        assert!(c.contains("OR 1=1"));
    }
    #[test]
    fn bash_has_function() {
        let f = sample_finding();
        let s = bash_script(&[f.clone()], "test-engagement");
        assert!(s.contains("function poc-001-sqli()"));
        assert!(s.contains("KOBRA PoC bundle"));
        assert!(s.contains("Engagement: test-engagement"));
    }
    #[test]
    fn slug_basic() {
        assert_eq!(slugify("SQLi"), "sqli");
        assert_eq!(slugify("DOM-XSS"), "dom-xss");
    }
    #[test]
    fn truncate_short() {
        assert_eq!(truncate("abc", 5), "abc");
    }
}
