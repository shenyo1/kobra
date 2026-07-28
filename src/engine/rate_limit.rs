//! Rate-limit aware: detect 429/503/ban patterns and exponential backoff.
//! Per-host request counter + adaptive delay to stay under thresholds.

use std::collections::HashMap;
use std::sync::{Mutex, LockResult, MutexGuard};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct HostStats {
    pub requests: u32,
    pub last_429: Option<Instant>,
    pub last_503: Option<Instant>,
    pub current_delay: Duration,
    pub banned: bool,
}

pub type SharedRateLimiter = std::sync::Arc<Mutex<HashMap<String, HostStats>>>;

pub fn new_limiter() -> SharedRateLimiter {
    std::sync::Arc::new(Mutex::new(HashMap::new()))
}

fn extract_host(url: &str) -> String {
    let trimmed = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    trimmed.split('/').next().unwrap_or("unknown").to_string()
}

fn map_lock_err<T>(r: LockResult<T>) -> T {
    match r {
        Ok(v) => v,
        Err(p) => p.into_inner(),
    }
}

#[allow(dead_code)]
type HostGuard<'a> = MutexGuard<'a, HashMap<String, HostStats>>;

pub fn record_request(rl: &SharedRateLimiter, url: &str) {
    let host = extract_host(url);
    let mut g = map_lock_err(rl.lock());
    let s = g.entry(host).or_insert(HostStats {
        requests: 0,
        last_429: None,
        last_503: None,
        current_delay: Duration::ZERO,
        banned: false,
    });
    s.requests = s.requests.saturating_add(1);
}

pub fn record_response(rl: &SharedRateLimiter, url: &str, status: u16) {
    let host = extract_host(url);
    let mut g = map_lock_err(rl.lock());
    let s = g.entry(host).or_insert(HostStats {
        requests: 0,
        last_429: None,
        last_503: None,
        current_delay: Duration::ZERO,
        banned: false,
    });
    match status {
        403 => {
            if s.requests > 20 {
                s.banned = true;
            }
        }
        429 => {
            s.last_429 = Some(Instant::now());
            s.current_delay = (s.current_delay * 2).max(Duration::from_millis(500));
            if s.current_delay > Duration::from_secs(30) {
                s.banned = true;
            }
        }
        503 => {
            s.last_503 = Some(Instant::now());
            s.current_delay = (s.current_delay * 2).max(Duration::from_millis(200));
        }
        _ => {
            // Success path: gradually reduce delay
            if s.current_delay > Duration::ZERO {
                s.current_delay = s.current_delay / 2;
                if s.current_delay < Duration::from_millis(50) {
                    s.current_delay = Duration::ZERO;
                }
            }
        }
    }
}

pub fn delay_for(rl: &SharedRateLimiter, url: &str) -> Duration {
    let host = extract_host(url);
    let g = map_lock_err(rl.lock());
    g.get(&host).map(|s| s.current_delay).unwrap_or(Duration::ZERO)
}

pub fn is_banned(rl: &SharedRateLimiter, url: &str) -> bool {
    let host = extract_host(url);
    let g = map_lock_err(rl.lock());
    g.get(&host).map(|s| s.banned).unwrap_or(false)
}

/// Sync helper. Caller should `tokio::time::sleep(delay_for(rl, url)).await` when in async context.
pub fn wait_ms(rl: &SharedRateLimiter, url: &str) -> u64 {
    delay_for(rl, url).as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extract_host_basic() {
        assert_eq!(extract_host("https://example.com/path"), "example.com");
        assert_eq!(extract_host("http://api.test.io:8080/x"), "api.test.io:8080");
    }
    #[test]
    fn bump_delay_on_429() {
        let rl = new_limiter();
        record_request(&rl, "https://x.com/");
        record_response(&rl, "https://x.com/", 429);
        record_response(&rl, "https://x.com/", 429);
        let d = delay_for(&rl, "https://x.com/");
        assert!(d >= Duration::from_millis(500));
    }
    #[test]
    fn success_reduces_delay() {
        let rl = new_limiter();
        record_request(&rl, "https://x.com/");
        record_response(&rl, "https://x.com/", 429);
        record_response(&rl, "https://x.com/", 429);
        let before = delay_for(&rl, "https://x.com/");
        record_response(&rl, "https://x.com/", 200);
        record_response(&rl, "https://x.com/", 200);
        record_response(&rl, "https://x.com/", 200);
        record_response(&rl, "https://x.com/", 200);
        record_response(&rl, "https://x.com/", 200);
        let after = delay_for(&rl, "https://x.com/");
        assert!(after < before);
    }
    #[test]
    fn banned_after_429_loop() {
        let rl = new_limiter();
        record_request(&rl, "https://x.com/");
        for _ in 0..10 {
            record_response(&rl, "https://x.com/", 429);
        }
        assert!(is_banned(&rl, "https://x.com/"));
    }
}
