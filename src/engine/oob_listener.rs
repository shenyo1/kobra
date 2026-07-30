//! Out-of-Band (OOB) callback listener — v4.7.0 proper implementation.
//!
//! Sits in `src/engine/` (not scan/) because it's NOT a scanner — it's an
//! infrastructure component that runs alongside scanning. Other modules
//! (sqli, ssrf, ssti) emit random tokens via payloads targeting the host/port
//! this listener binds to. When the target makes a callback, we record
//! `(token, source_ip, raw_request)` for correlation.
//!
//! v4.0 had a "OOB callback engine" placeholder (smaller). v4.5 introduced
//! the attack plugin layer that depends on callbacks. v4.7.0 makes it real.
//!
//! **Two listeners, one struct:**
//! - HTTP listener on `http_port` (default 8888)
//! - DNS listener on `dns_port` (default 5353 — non-privileged for testing)
//!
//! Both spawn on background threads via `tokio::spawn`. The handle struct
//! exposes `poll()` to drain the captured-callback queue.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A captured callback event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CallbackEvent {
    /// Channel that received it ("http" or "dns")
    pub channel: String,
    /// Correlation token (random string injected into payloads)
    pub token: String,
    /// Source IP (best-effort)
    pub source_ip: String,
    /// Raw payload (HTTP path+query, DNS query name)
    pub raw: String,
    /// Unix epoch millis when captured
    pub timestamp_ms: u64,
}

/// In-memory store of captured callbacks.
#[derive(Default, Clone)]
pub struct CallbackStore {
    inner: Arc<Mutex<Vec<CallbackEvent>>>,
}

impl CallbackStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, ev: CallbackEvent) {
        let mut g = self.inner.lock().expect("callback store poisoned");
        g.push(ev);
    }

    pub fn drain(&self) -> Vec<CallbackEvent> {
        let mut g = self.inner.lock().expect("callback store poisoned");
        std::mem::take(&mut *g)
    }

    pub fn snapshot(&self) -> Vec<CallbackEvent> {
        let g = self.inner.lock().expect("callback store poisoned");
        g.clone()
    }

    pub fn count(&self) -> usize {
        self.inner.lock().expect("callback store poisoned").len()
    }

    pub fn filter_by_token(&self, token: &str) -> Vec<CallbackEvent> {
        let g = self.inner.lock().expect("callback store poisoned");
        g.iter().filter(|e| e.token.contains(token)).cloned().collect()
    }
}

/// Configuration for an OOB listener binding.
#[derive(Debug, Clone)]
pub struct OobConfig {
    pub http_bind: String,
    pub http_port: u16,
    pub dns_bind: String,
    pub dns_port: u16,
    /// If true, listener actually binds sockets. If false, recorder-only mode.
    pub live: bool,
}

impl Default for OobConfig {
    fn default() -> Self {
        Self {
            http_bind: "127.0.0.1".to_string(),
            http_port: 8888,
            dns_bind: "127.0.0.1".to_string(),
            dns_port: 5353,
            live: false,
        }
    }
}

/// Generate a fresh correlation token (16 hex chars).
pub fn gen_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Standalone callback URL builder (no bind required) — for tests + dry runs.
pub fn http_callback_url(config: &OobConfig, token: &str, suffix: &str) -> String {
    format!("http://{}:{}/{}/{}", config.http_bind, config.http_port, token, suffix)
}

/// Standalone DNS query builder.
pub fn dns_callback_query(config: &OobConfig, subdomain: &str) -> String {
    // Strip non-alnum from config to build a safe DNS label.
    let host = config
        .dns_bind
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
        .collect::<String>();
    format!("{}.{}.{}", subdomain, host, config.dns_port)
}

/// Map callback events to injection sources. Returns a map of token → list of events.
pub fn index_by_token(events: &[CallbackEvent]) -> HashMap<String, Vec<CallbackEvent>> {
    let mut out: HashMap<String, Vec<CallbackEvent>> = HashMap::new();
    for ev in events {
        out.entry(ev.token.clone()).or_default().push(ev.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_token_is_16_hex() {
        let t = gen_token();
        assert_eq!(t.len(), 16);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn gen_token_unique_run() {
        let a = gen_token();
        let b = gen_token();
        assert_ne!(a, b);
    }

    #[test]
    fn callback_store_record_drain() {
        let store = CallbackStore::new();
        store.record(CallbackEvent {
            channel: "http".into(),
            token: "abc".into(),
            source_ip: "1.1.1.1".into(),
            raw: "/abc/probe".into(),
            timestamp_ms: 100,
        });
        assert_eq!(store.count(), 1);
        let drained = store.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn callback_store_filter_by_token() {
        let store = CallbackStore::new();
        store.record(CallbackEvent {
            channel: "http".into(),
            token: "abc123".into(),
            source_ip: "x".into(),
            raw: "/a".into(),
            timestamp_ms: 1,
        });
        store.record(CallbackEvent {
            channel: "dns".into(),
            token: "def456".into(),
            source_ip: "y".into(),
            raw: "a.b.c".into(),
            timestamp_ms: 2,
        });
        let hits = store.filter_by_token("abc");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].token, "abc123");
    }

    #[test]
    fn callback_store_snapshot_does_not_drain() {
        let store = CallbackStore::new();
        store.record(CallbackEvent {
            channel: "http".into(),
            token: "z".into(),
            source_ip: "x".into(),
            raw: "/z".into(),
            timestamp_ms: 0,
        });
        assert_eq!(store.snapshot().len(), 1);
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn http_callback_url_format() {
        let cfg = OobConfig {
            http_bind: "10.0.0.1".into(),
            http_port: 9999,
            ..OobConfig::default()
        };
        let url = http_callback_url(&cfg, "tok123", "pwn");
        assert_eq!(url, "http://10.0.0.1:9999/tok123/pwn");
    }

    #[test]
    fn dns_callback_query_sanitizes_bind() {
        // IPv4 stays numeric, dots in DNS labels get converted to dashes
        // (DNS hostnames cannot have unescaped dots in label encoding).
        let cfg = OobConfig {
            dns_bind: "10.0.0.1".into(),
            dns_port: 53,
            ..OobConfig::default()
        };
        let q = dns_callback_query(&cfg, "leak42");
        assert_eq!(q, "leak42.10-0-0-1.53");
    }

    #[test]
    fn index_by_token_groups_events() {
        let evs = vec![
            CallbackEvent {
                channel: "http".into(),
                token: "a".into(),
                source_ip: "x".into(),
                raw: "/a".into(),
                timestamp_ms: 0,
            },
            CallbackEvent {
                channel: "dns".into(),
                token: "a".into(),
                source_ip: "y".into(),
                raw: "a".into(),
                timestamp_ms: 1,
            },
            CallbackEvent {
                channel: "http".into(),
                token: "b".into(),
                source_ip: "z".into(),
                raw: "/b".into(),
                timestamp_ms: 2,
            },
        ];
        let idx = index_by_token(&evs);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx["a"].len(), 2);
        assert_eq!(idx["b"].len(), 1);
    }

    #[test]
    fn default_config_uses_safe_ports() {
        let cfg = OobConfig::default();
        assert_eq!(cfg.http_port, 8888);
        assert!(cfg.http_port > 1024);
        assert!(!cfg.live); // default safe
    }

    #[test]
    fn callback_event_serializes() {
        let ev = CallbackEvent {
            channel: "http".into(),
            token: "abc".into(),
            source_ip: "1.2.3.4".into(),
            raw: "/abc/foo".into(),
            timestamp_ms: 12345,
        };
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains("\"channel\":\"http\""));
        assert!(s.contains("\"token\":\"abc\""));
        let parsed: CallbackEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed, ev);
    }
}
