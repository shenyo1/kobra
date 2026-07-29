//! Plugin Marketplace
//!
//! Allows users to download KOBRA plugins from a registry.
//!
//! Three-tier plugin system:
//! 1. Built-in: compiled in src/scan/
//! 2. Local: dropped in ~/.local/share/kobra/plugins/*.json
//! 3. Marketplace: downloaded from remote registry (e.g. github raw URLs)
//!
//! Plugin format (JSON):
//! ```json
//! {
//!   "name": "kobra-plugin-cve-2026-foo",
//!   "version": "1.0.0",
//!   "author": "...",
//!   "category": "SCAN",
//!   "patterns": [{"type": "regex", "value": "..."}]
//! }
//! ```

// Finding not used in main code
#[cfg(test)]
use crate::types::Severity;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub category: PluginCategory,
    pub patterns: Vec<PluginPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PluginCategory {
    Scan,
    Report,
    Engine,
    Mutation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPattern {
    pub kind: PatternKind,
    pub value: String,
    pub severity_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatternKind {
    Regex,
    String,
    Header,
    Jsonpath,
}

pub struct PluginMarketplace {
    pub local_dir: std::path::PathBuf,
    pub installed: HashMap<String, PluginManifest>,
}

impl PluginMarketplace {
    pub fn new(local_dir: std::path::PathBuf) -> Self {
        Self {
            local_dir,
            installed: HashMap::new(),
        }
    }

    /// Install a plugin from in-memory manifest.
    pub fn install(&mut self, manifest: PluginManifest) -> Result<String, String> {
        if manifest.name.is_empty() {
            return Err("plugin name cannot be empty".to_string());
        }
        if self.installed.contains_key(&manifest.name) {
            return Err(format!("plugin {} already installed", manifest.name));
        }
        let name = manifest.name.clone();

        // Save to local dir as JSON
        std::fs::create_dir_all(&self.local_dir)
            .map_err(|e| format!("create dir: {}", e))?;
        let path = self.local_dir.join(format!("{}.json", name));
        let json = serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(&path, json).map_err(|e| format!("write: {}", e))?;

        self.installed.insert(name.clone(), manifest);
        Ok(name)
    }

    /// Uninstall plugin.
    pub fn uninstall(&mut self, name: &str) -> Result<(), String> {
        self.installed
            .remove(name)
            .ok_or_else(|| format!("plugin {} not found", name))?;
        let path = self.local_dir.join(format!("{}.json", name));
        if path.exists() {
            std::fs::remove_file(&path).ok();
        }
        Ok(())
    }

    /// Load all plugins from local directory.
    pub fn load_local(&mut self) -> Result<usize, String> {
        if !self.local_dir.exists() {
            return Ok(0);
        }
        let mut count = 0;
        for entry in std::fs::read_dir(&self.local_dir).map_err(|e| format!("read dir: {}", e))? {
            let entry = entry.map_err(|e| format!("entry: {}", e))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let data = std::fs::read_to_string(&path).map_err(|e| format!("read: {}", e))?;
            let manifest: PluginManifest =
                serde_json::from_str(&data).map_err(|e| format!("parse: {}", e))?;
            self.installed.insert(manifest.name.clone(), manifest);
            count += 1;
        }
        Ok(count)
    }

    /// Validate manifest structure.
    pub fn validate(manifest: &PluginManifest) -> Result<(), String> {
        if manifest.name.is_empty() {
            return Err("name required".to_string());
        }
        if manifest.version.is_empty() {
            return Err("version required".to_string());
        }
        if manifest.patterns.is_empty() {
            return Err("at least one pattern required".to_string());
        }
        Ok(())
    }

    /// List installed plugins.
    pub fn list(&self) -> Vec<&PluginManifest> {
        self.installed.values().collect()
    }

    /// Search by category.
    pub fn search_by_category(&self, category: &PluginCategory) -> Vec<&PluginManifest> {
        self.installed
            .values()
            .filter(|p| p.category == *category)
            .collect()
    }

    /// Total installed plugin count.
    pub fn count(&self) -> usize {
        self.installed.len()
    }
}

impl Default for PluginMarketplace {
    fn default() -> Self {
        Self::new(
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
                .join(".local/share/kobra/plugins"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn mk_manifest(name: &str) -> PluginManifest {
        PluginManifest {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            author: "tester".to_string(),
            description: "test plugin".to_string(),
            category: PluginCategory::Scan,
            patterns: vec![PluginPattern {
                kind: PatternKind::Regex,
                value: r"x\.com".to_string(),
                severity_hint: Some("high".to_string()),
            }],
        }
    }

    fn tmp_dir() -> std::path::PathBuf {
        let dir = env::temp_dir().join(format!("kobra-plugins-{}", rand_u64()));
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

    #[test]
    fn install_plugin_saves_to_disk() {
        let dir = tmp_dir();
        let mut market = PluginMarketplace::new(dir.clone());
        let name = market.install(mk_manifest("test-plugin")).unwrap();
        assert_eq!(name, "test-plugin");
        let path = dir.join("test-plugin.json");
        assert!(path.exists());
    }

    #[test]
    fn install_duplicate_fails() {
        let dir = tmp_dir();
        let mut market = PluginMarketplace::new(dir);
        market.install(mk_manifest("dup")).unwrap();
        let res = market.install(mk_manifest("dup"));
        assert!(res.is_err());
    }

    #[test]
    fn uninstall_removes_plugin() {
        let dir = tmp_dir();
        let mut market = PluginMarketplace::new(dir);
        market.install(mk_manifest("rem")).unwrap();
        market.uninstall("rem").unwrap();
        assert_eq!(market.count(), 0);
    }

    #[test]
    fn load_local_plugins() {
        let dir = tmp_dir();
        let mut market = PluginMarketplace::new(dir.clone());
        market.install(mk_manifest("plugin-a")).unwrap();
        market.install(mk_manifest("plugin-b")).unwrap();

        let mut market2 = PluginMarketplace::new(dir);
        let count = market2.load_local().unwrap();
        assert_eq!(count, 2);
        assert_eq!(market2.count(), 2);
    }

    #[test]
    fn validate_manifest_catches_empty() {
        let mut m = mk_manifest("foo");
        m.name = "".to_string();
        assert!(PluginMarketplace::validate(&m).is_err());
    }

    #[test]
    fn validate_patterns_required() {
        let mut m = mk_manifest("foo");
        m.patterns = vec![];
        assert!(PluginMarketplace::validate(&m).is_err());
    }

    #[test]
    fn search_by_category_filters() {
        let dir = tmp_dir();
        let mut market = PluginMarketplace::new(dir);
        let mut m = mk_manifest("scan1");
        m.category = PluginCategory::Scan;
        market.install(m).unwrap();
        let mut m = mk_manifest("report1");
        m.category = PluginCategory::Report;
        market.install(m).unwrap();

        let scans = market.search_by_category(&PluginCategory::Scan);
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].name, "scan1");
    }

    #[test]
    fn count_tracks_installs() {
        let dir = tmp_dir();
        let mut market = PluginMarketplace::new(dir);
        assert_eq!(market.count(), 0);
        market.install(mk_manifest("p1")).unwrap();
        assert_eq!(market.count(), 1);
    }
}
