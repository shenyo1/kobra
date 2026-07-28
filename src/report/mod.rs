//! Reporting modules — Markdown v2, HTML dashboard, PoC generator + legacy stdout.

pub mod poc;
pub mod markdown_v2;
pub mod dashboard;
pub mod legacy;
pub mod resilience;
pub mod webhook;        // Slack/Discord/generic webhook reporter
