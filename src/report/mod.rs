//! Reporting modules — Markdown v2, HTML dashboard, PoC generator + legacy stdout.

pub mod poc;
pub mod markdown_v2;
pub mod dashboard;
pub mod legacy;
pub mod resilience;
pub mod webhook;        // Slack/Discord/generic webhook reporter
pub mod simple;         // Simple Bahasa Indonesia output for beginners
pub mod sarif;          // SARIF v2.1.0 export for GitHub Security tab
pub mod screenshot;     // Screenshot evidence via headless browser
