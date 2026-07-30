//! Event Bus — pub/sub between scan modules and attack plugins.
//!
//! Producers (scanners) publish typed events when they discover findings.
//! Consumers (attack plugins via dispatcher) subscribe to events they care about.
//! Wiring happens at engine level so triggers fire automatically during scan.
//!
//! v4.6.0 introduces this. v4.5.0 `--attack` flag only printed "ACTIVE".
//!
//! **Design constraint:** zero-cost when no subscribers registered.
//! `publish()` returns immediately if no subscribers, avoiding any thread overhead.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Standard event names matching `attack plugin patterns[].value` field.
pub mod events {
    pub const SQLI_FINDING_DETECTED: &str = "sqli.finding.detected";
    pub const AUTH_FLOW_CLASSIFIED_JWT: &str = "auth_flow.classified:JWT";
    pub const JWT_FINDING_DETECTED: &str = "jwt.finding.detected";
    pub const POSTGREST_ENDPOINT_DISCOVERED: &str = "postgrest.endpoint_discovered";
    pub const POSTGREST_ANONYMOUS_ACCESS: &str = "postgrest.anonymous_access";
    pub const SSRF_OOB_CALLBACK: &str = "ssrf_oob.callback_received";
    pub const RCE_OOB_CALLBACK: &str = "rce_oob.callback_received";
    pub const CHAIN_ELIGIBLE_FINDINGS_3: &str = "chain.eligible_findings>=3";
}

/// Event payload published by scan modules.
#[derive(Debug, Clone)]
pub struct ScanEvent {
    pub kind: &'static str,
    pub target: String,
    pub evidence: String,
    pub severity: Option<String>,
}

type Handler = Arc<dyn Fn(&ScanEvent) + Send + Sync>;

/// Thread-safe registry of event name → list of handlers.
pub struct EventBus {
    subscribers: Mutex<HashMap<&'static str, Vec<Handler>>>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            subscribers: Mutex::new(HashMap::new()),
        }
    }

    /// Subscribe a handler to one or more events.
    pub fn subscribe<I: IntoIterator<Item = &'static str>>(
        &self,
        events: I,
        handler: Handler,
    ) {
        let mut subs = self
            .subscribers
            .lock()
            .expect("event_bus mutex poisoned");
        for ev in events {
            subs.entry(ev).or_default().push(handler.clone());
        }
    }

    /// Publish an event. Returns count of handlers invoked.
    pub fn publish(&self, event: &ScanEvent) -> usize {
        let subs = self
            .subscribers
            .lock()
            .expect("event_bus mutex poisoned");
        let handlers = match subs.get(&event.kind) {
            Some(h) => h,
            None => return 0,
        };
        let mut fired = 0;
        for h in handlers {
            h(event);
            fired += 1;
        }
        fired
    }

    /// Total registered subscriptions.
    pub fn subscription_count(&self) -> usize {
        self.subscribers
            .lock()
            .expect("event_bus mutex poisoned")
            .values()
            .map(|v| v.len())
            .sum()
    }

    /// Number of distinct events with at least one subscriber.
    pub fn event_count(&self) -> usize {
        self.subscribers
            .lock()
            .expect("event_bus mutex poisoned")
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn new_bus_has_zero_subscribers() {
        let bus = EventBus::new();
        assert_eq!(bus.subscription_count(), 0);
        assert_eq!(bus.event_count(), 0);
    }

    #[test]
    fn publish_with_no_subscribers_returns_zero() {
        let bus = EventBus::new();
        let ev = ScanEvent {
            kind: events::SQLI_FINDING_DETECTED,
            target: "https://x.com".into(),
            evidence: "test".into(),
            severity: None,
        };
        let fired = bus.publish(&ev);
        assert_eq!(fired, 0);
    }

    #[test]
    fn subscribe_and_publish_fires_handler() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();
        let h: Handler = Arc::new(move |_ev: &ScanEvent| {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        });
        bus.subscribe([events::SQLI_FINDING_DETECTED], h);
        let ev = ScanEvent {
            kind: events::SQLI_FINDING_DETECTED,
            target: "x".into(),
            evidence: "y".into(),
            severity: Some("High".into()),
        };
        let fired = bus.publish(&ev);
        assert_eq!(fired, 1);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn subscriber_only_fires_for_matching_event() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let cc = counter.clone();
        let h: Handler = Arc::new(move |_ev| {
            cc.fetch_add(1, Ordering::SeqCst);
        });
        bus.subscribe([events::JWT_FINDING_DETECTED], h);
        let wrong = ScanEvent {
            kind: events::SQLI_FINDING_DETECTED,
            target: "x".into(),
            evidence: "".into(),
            severity: None,
        };
        assert_eq!(bus.publish(&wrong), 0);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn multiple_subscribers_all_fire() {
        let bus = EventBus::new();
        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));
        let ca = count_a.clone();
        let cb = count_b.clone();
        let ha: Handler = Arc::new(move |_| {
            ca.fetch_add(1, Ordering::SeqCst);
        });
        let hb: Handler = Arc::new(move |_| {
            cb.fetch_add(1, Ordering::SeqCst);
        });
        bus.subscribe([events::SSRF_OOB_CALLBACK], ha);
        bus.subscribe([events::SSRF_OOB_CALLBACK], hb);
        let ev = ScanEvent {
            kind: events::SSRF_OOB_CALLBACK,
            target: "x".into(),
            evidence: "y".into(),
            severity: None,
        };
        let fired = bus.publish(&ev);
        assert_eq!(fired, 2);
        assert_eq!(count_a.load(Ordering::SeqCst), 1);
        assert_eq!(count_b.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn one_subscriber_multiple_events() {
        let bus = EventBus::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let cc = counter.clone();
        let h: Handler = Arc::new(move |_| {
            cc.fetch_add(1, Ordering::SeqCst);
        });
        bus.subscribe(
            [
                events::JWT_FINDING_DETECTED,
                events::SQLI_FINDING_DETECTED,
                events::POSTGREST_ANONYMOUS_ACCESS,
            ],
            h,
        );
        assert_eq!(bus.subscription_count(), 3);
        let ev = ScanEvent {
            kind: events::JWT_FINDING_DETECTED,
            target: "x".into(),
            evidence: "".into(),
            severity: None,
        };
        bus.publish(&ev);
        bus.publish(&ev);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }
}
