//! Timing-based detection for blind SQLi / RCE / command injection.
//! Statistical: 5+ samples, mean + stdev differential vs baseline.

use std::time::Duration;

/// SLEEP payloads per backend. Each is a no-op that takes `seconds`.
pub const SQL_SLEEP: &[&str] = &[
    "' OR SLEEP({s})--",
    "1' OR SLEEP({s})#",
    "' WAITFOR DELAY '0:0:{s}'--",
    "'; WAITFOR DELAY '0:0:{s}'--",
    "1; SELECT pg_sleep({s})--",
    "'; SELECT pg_sleep({s})--",
    "'; DBMS_LOCK.SLEEP({s})--",
];

pub const CMD_SLEEP: &[&str] = &[
    "& sleep {s}",
    "; sleep {s}",
    "| sleep {s}",
    "$(sleep {s})",
    "`sleep {s}`",
];

/// Build payload variants with seconds baked in.
pub fn sql_sleep_payloads(seconds: u64) -> Vec<String> {
    SQL_SLEEP.iter().map(|p| p.replace("{s}", &seconds.to_string())).collect()
}

pub fn cmd_sleep_payloads(seconds: u64) -> Vec<String> {
    CMD_SLEEP.iter().map(|p| p.replace("{s}", &seconds.to_string())).collect()
}

/// Sample mean from durations. Returns 0 if empty.
pub fn mean(samples: &[Duration]) -> Duration {
    if samples.is_empty() {
        return Duration::ZERO;
    }
    let total: Duration = samples.iter().sum();
    total / samples.len() as u32
}

/// Sample standard deviation.
pub fn stdev(samples: &[Duration], mean_d: Duration) -> Duration {
    if samples.len() < 2 {
        return Duration::ZERO;
    }
    let var: f64 = samples.iter().map(|d| {
        let diff = d.as_secs_f64() - mean_d.as_secs_f64();
        diff * diff
    }).sum::<f64>() / (samples.len() as f64 - 1.0);
    Duration::from_secs_f64(var.sqrt())
}

/// Heuristic: response is "delayed" if mean > baseline.mean + baseline.stdev * 3 + threshold.
pub fn is_delayed(baseline: &[Duration], response: &[Duration], threshold_ms: u64) -> bool {
    let bm = mean(baseline);
    let bs = stdev(baseline, bm);
    let rm = mean(response);
    let cutoff = bm + bs * 3 + Duration::from_millis(threshold_ms);
    rm > cutoff
}

/// Statistical time-based detection (anti-FP v3.3.0)
/// Returns true ONLY if:
///   (1) probe median > 2x baseline median (relative delay)
///   AND
///   (2) at least 3 of 5 probe samples > 2 seconds (consistent delay, not jitter)
pub fn is_delayed_strong(baseline: &[Duration], response: &[Duration]) -> bool {
    if baseline.is_empty() || response.is_empty() {
        return false;
    }
    let med_baseline = percentile(baseline, 0.50);
    let med_response = percentile(response, 0.50);

    // (1) Median delay: probe median must be > 2x baseline median
    let ratio = med_response.as_secs_f64() / med_baseline.as_secs_f64().max(0.001);
    let rel_delay_ok = ratio >= 2.0;

    // (2) Consistency: at least 3 of 5 probe samples must be > 2 seconds
    let slow_count = response.iter()
        .filter(|d| d.as_millis() > 2000)
        .count();
    let abs_delay_ok = slow_count >= 3;

    rel_delay_ok && abs_delay_ok
}

fn percentile(samples: &[Duration], p: f64) -> Duration {
    if samples.is_empty() {
        return Duration::from_millis(0);
    }
    let mut sorted: Vec<Duration> = samples.to_vec();
    sorted.sort();
    let idx = ((p * (sorted.len() as f64 - 1.0)).round() as usize).min(sorted.len() - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sql_payload_count() {
        assert_eq!(sql_sleep_payloads(5).len(), SQL_SLEEP.len());
    }
    #[test]
    fn delay_detection_positive() {
        let baseline = vec![
            Duration::from_millis(50),
            Duration::from_millis(55),
            Duration::from_millis(48),
        ];
        let response = vec![Duration::from_millis(2000), Duration::from_millis(2100)];
        assert!(is_delayed(&baseline, &response, 500));
    }
    #[test]
    fn delay_detection_negative() {
        let baseline = vec![
            Duration::from_millis(50),
            Duration::from_millis(55),
            Duration::from_millis(48),
        ];
        let response = vec![Duration::from_millis(60), Duration::from_millis(58)];
        assert!(!is_delayed(&baseline, &response, 500));
    }
    #[test]
    fn stdev_zero_one_sample() {
        let s = vec![Duration::from_millis(100)];
        let m = mean(&s);
        assert_eq!(stdev(&s, m), Duration::ZERO);
    }
}
