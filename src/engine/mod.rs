//! Engine modules — adaptive payload, OOB callback, timing, rate-limit, FP filter.
//! Engine modules — adaptive payload, OOB callback, timing, rate-limit, FP filter, chain detect.
pub mod mutator;
pub mod oob;
pub mod timing;
pub mod rate_limit;
pub mod fp_filter;
pub mod chain_detect;
pub mod cve_update;
pub mod template;
pub mod nuclei_compat;
pub mod diff;
pub mod cross_chain;
pub mod watch;
pub mod ai_triage;
pub mod profiles;
pub mod mutator_v2;
pub mod exploit_verify;
pub mod historical;
pub mod dedup;
pub mod plugin_v2;
pub mod event_bus;
pub mod oob_listener;
