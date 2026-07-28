//! OOB (Out-of-Band) callback server — proves blind SSRF/RCE/XSS via token callback.
//! Listens on a random local port, generates unique tokens per finding.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
pub type SharedCallbackLog = Arc<Mutex<HashMap<String, CallbackEntry>>>;

#[derive(Clone, Debug)]
pub struct CallbackEntry {
    pub token: String,
    pub hit_at_ms: u128,
    pub path: String,
    pub query: String,
    pub src_ip: String,
    pub user_agent: String,
}

pub fn make_token() -> String {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let r: u64 = (ts as u64).wrapping_mul(2654435761) ^ (ts as u64).wrapping_shr(33);
    format!("k0bra-{:x}-{:x}", ts, r & 0xFFFF)
}

pub fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

/// Return the local OOB HTTP listener address. Bind ephemeral port; never expose externally.
pub fn bind_addr() -> Option<SocketAddr> {
    std::net::TcpListener::bind("127.0.0.1:0").ok().and_then(|l| l.local_addr().ok())
}

/// Record a callback hit. Called by the OOB HTTP handler.
pub fn record_hit(log: &SharedCallbackLog, entry: CallbackEntry) {
    let mut g = match log.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    g.insert(entry.token.clone(), entry);
}

/// Check whether a token was hit within `window_ms`.
pub fn was_hit(log: &SharedCallbackLog, token: &str, window_ms: u128) -> bool {
    let g = match log.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    g.get(token)
        .map(|e| now_ms().saturating_sub(e.hit_at_ms) <= window_ms)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_unique() {
        let t1 = make_token();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let t2 = make_token();
        assert!(t1.starts_with("k0bra-"));
        assert_ne!(t1, t2);
    }
    #[test]
    fn bind_localhost() {
        let addr = bind_addr();
        assert!(addr.is_some());
        let a = addr.unwrap();
        assert!(a.ip().is_loopback());
    }
    #[test]
    fn record_hit_check() {
        let log: SharedCallbackLog = Arc::new(Mutex::new(HashMap::new()));
        record_hit(&log, CallbackEntry {
            token: "abc".into(),
            hit_at_ms: now_ms(),
            path: "/c".into(),
            query: "x=1".into(),
            src_ip: "127.0.0.1".into(),
            user_agent: "ua".into(),
        });
        assert!(was_hit(&log, "abc", 5000));
        assert!(!was_hit(&log, "zzz", 5000));
    }
}
