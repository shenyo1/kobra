//! Attack Plugin Layer (v4.5.0)
//!
//! Loads JSON plugin manifests from `plugins-attack/` (or custom dir) and executes
//! them as subprocesses when triggered events fire during a scan.
//!
//! This is SEPARATE from `plugin_v2.rs` (the marketplace plugin system) because
//! attack plugins have a fundamentally different shape: they spawn external
//! binaries (sqlmap, hashcat, etc.) with templated args, not in-process patterns.
//!
//! Plugin JSON format (`plugins-attack/*.json`):
//! ```json
//! {
//!   "name": "kobra-plugin-sqlmap-auto",
//!   "version": "1.0.0",
//!   "engine_version": ">=4.5.0",
//!   "category": "Exploit",
//!   "description": "...",
//!   "patterns": [{"kind": "trigger", "value": "sqli.finding.detected"}],
//!   "config": {
//!     "binary": "sqlmap",
//!     "args": ["-u", "{target}", "--batch", ...],
//!     "timeout_secs": 600,
//!     "post_actions": ["extract_dbs"]
//!   },
//!   "outputs": {"db_dump": "..."}
//! }
//! ```

pub mod runner;
pub mod dispatcher;
pub mod jwt_crack;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Plugin manifest matching the JSON schema on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPlugin {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub author: String,
    pub description: String,
    #[serde(default)]
    pub engine_version: String,
    pub category: String,
    pub patterns: Vec<AttackPattern>,
    #[serde(default)]
    pub config: PluginConfig,
    #[serde(default)]
    pub outputs: HashMap<String, String>,
}

/// Trigger pattern — matches scan events like `sqli.finding.detected`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPattern {
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub severity_hint: Option<String>,
}

/// Subprocess execution spec.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PluginConfig {
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub post_actions: Vec<String>,
}

/// Discovery + registry of all loaded attack plugins.
/// Uses RawManifest (multi-shape) instead of the strict AttackPlugin struct so it
/// can load subprocess, workflow, action, chain, and orchestrator plugin shapes.
pub struct AttackRegistry {
    pub dir: PathBuf,
    pub plugins: HashMap<String, dispatcher::RawManifest>,
}

impl Default for AttackRegistry {
    fn default() -> Self {
        Self::new(
            PathBuf::from(std::env::var("HOME").unwrap_or_default())
                .join(".local/share/kobra/plugins/attack"),
        )
    }
}

impl AttackRegistry {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            plugins: HashMap::new(),
        }
    }

    pub fn load_all(&mut self) -> Result<LoadReport, String> {
        if !self.dir.exists() {
            return Ok(LoadReport {
                loaded: 0,
                errors: vec![],
                dir: self.dir.clone(),
            });
        }
        let mut report = LoadReport {
            loaded: 0,
            errors: vec![],
            dir: self.dir.clone(),
        };
        let entries = std::fs::read_dir(&self.dir).map_err(|e| format!("read dir: {e}"))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            match self.load_one(&path) {
                Ok(name) => {
                    report.loaded += 1;
                    log_load(&name, &path);
                }
                Err(e) => {
                    report.errors.push(format!("{}: {}", path.display(), e));
                }
            }
        }
        Ok(report)
    }

    /// Load a single plugin manifest. Accepts any of the 5 plugin shapes
    /// (subprocess, workflow, action, chain, orchestrator).
    pub fn load_one(&mut self, path: &Path) -> Result<String, String> {
        let data = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
        let plugin: dispatcher::RawManifest =
            serde_json::from_str(&data).map_err(|e| format!("parse: {e}"))?;
        if plugin.name.is_empty() {
            return Err("name required".to_string());
        }
        let name = plugin.name.clone();
        self.plugins.insert(name.clone(), plugin);
        Ok(name)
    }

    /// Find plugins that fire on a given event.
    pub fn for_event(&self, event: &str) -> Vec<&dispatcher::RawManifest> {
        self.plugins
            .values()
            .filter(|p| {
                p.patterns.iter().any(|pat| {
                    pat.get("kind").and_then(|v| v.as_str()) == Some("trigger")
                        && pat.get("value").and_then(|v| v.as_str()) == Some(event)
                })
            })
            .collect()
    }

    /// Number of registered plugins.
    pub fn count(&self) -> usize {
        self.plugins.len()
    }
}

#[derive(Debug, Clone)]
pub struct LoadReport {
    pub loaded: usize,
    pub errors: Vec<String>,
    pub dir: PathBuf,
}

fn default_timeout() -> u64 {
    300
}

fn log_load(name: &str, path: &Path) {
    eprintln!("[attack] loaded: {} ({})", name, path.display());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp_dir() -> PathBuf {
        let dir = env::temp_dir().join(format!("kobra-attack-{}", rand_u64()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn rand_u64() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn sample_plugin(name: &str) -> String {
        format!(
            r#"{{
  "name": "{name}",
  "version": "1.0.0",
  "author": "tester",
  "description": "test",
  "engine_version": ">=4.5.0",
  "category": "Exploit",
  "patterns": [{{"kind": "trigger", "value": "sqli.finding.detected"}}],
  "config": {{
    "binary": "echo",
    "args": ["hello"],
    "timeout_secs": 5,
    "post_actions": []
  }},
  "outputs": {{}}
}}"#
        )
    }

    #[test]
    fn empty_dir_loads_zero() {
        let mut reg = AttackRegistry::new(tmp_dir());
        let report = reg.load_all().unwrap();
        assert_eq!(report.loaded, 0);
    }

    #[test]
    fn missing_dir_returns_zero_not_error() {
        let mut reg = AttackRegistry::new(PathBuf::from("/nonexistent/kobra/a/b/c"));
        let report = reg.load_all().unwrap();
        assert_eq!(report.loaded, 0);
    }

    #[test]
    fn load_valid_plugin_increments_count() {
        let dir = tmp_dir();
        std::fs::write(dir.join("a.json"), sample_plugin("a-plugin")).unwrap();
        let mut reg = AttackRegistry::new(dir);
        let report = reg.load_all().unwrap();
        assert_eq!(report.loaded, 1);
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn load_malformed_json_collects_error() {
        let dir = tmp_dir();
        std::fs::write(dir.join("bad.json"), "{not json").unwrap();
        let mut reg = AttackRegistry::new(dir);
        let report = reg.load_all().unwrap();
        assert_eq!(report.loaded, 0);
        assert_eq!(report.errors.len(), 1);
    }

    #[test]
    fn load_plugin_missing_binary_errors() {
        let dir = tmp_dir();
        std::fs::write(
            dir.join("no-bin.json"),
            r#"{"name": "x", "version": "1.0.0", "description": "x",
                "category": "Exploit", "patterns": [{"kind": "trigger", "value": "e"}],
                "config": {"binary": "", "args": []}}"#,
        )
        .unwrap();
        let mut reg = AttackRegistry::new(dir);
        let report = reg.load_all().unwrap();
        // v4.5.0 multi-shape: any of 5 plugin shapes accepted; subprocess w/o binary
        // is now valid as a Workflow/Action/Chain plugin too. So this loads as 1.
        assert_eq!(report.loaded, 1);
        assert_eq!(report.errors.len(), 0);
    }

    #[test]
    fn for_event_returns_matching_plugins() {
        let dir = tmp_dir();
        std::fs::write(dir.join("a.json"), sample_plugin("sqlmap-x")).unwrap();
        let mut reg = AttackRegistry::new(dir);
        reg.load_all().unwrap();
        let hits = reg.for_event("sqli.finding.detected");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "sqlmap-x");
        let no_hits = reg.for_event("rce.finding.detected");
        assert_eq!(no_hits.len(), 0);
    }

    #[test]
    fn parse_real_sqlmap_plugin_works() {
        let dir = tmp_dir();
        // Copy from actual repo plugin if present
        let real = std::env::var("HOME").unwrap_or_default()
            + "/.local/opt/kobra/plugins-attack/sqlmap-auto.json";
        let path = std::path::Path::new(&real);
        if !path.exists() {
            return; // skip if file missing
        }
        let data = std::fs::read_to_string(path).unwrap();
        std::fs::write(dir.join("sqlmap.json"), data).unwrap();
        let mut reg = AttackRegistry::new(dir);
        let report = reg.load_all().unwrap();
        assert_eq!(report.loaded, 1);
        assert_eq!(report.errors.len(), 0);
    }
}
