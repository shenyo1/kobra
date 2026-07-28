//! Checkpoint / Resume — persist state after each module completion.
//! On crash or restart, skip already-scanned (target, module) combos.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Checkpoint {
    pub engagement: String,
    pub completed: HashSet<String>,
    pub started_at_ms: u128,
    pub last_update_ms: u128,
}

impl Checkpoint {
    pub fn new(engagement: &str) -> Self {
        Self {
            engagement: engagement.to_string(),
            completed: HashSet::new(),
            started_at_ms: now_ms(),
            last_update_ms: now_ms(),
        }
    }

    pub fn mark_done(&mut self, target: &str, module: &str) {
        self.completed.insert(make_key(target, module));
        self.last_update_ms = now_ms();
    }

    pub fn is_done(&self, target: &str, module: &str) -> bool {
        self.completed.contains(&make_key(target, module))
    }

    pub fn save(&self, path: &str) -> std::io::Result<()> {
        if let Some(parent) = Path::new(path).parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        fs::write(path, json)
    }

    pub fn load(path: &str) -> Self {
        if let Ok(s) = fs::read_to_string(path) {
            serde_json::from_str(&s).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    pub fn stats(&self) -> (usize, u128) {
        (self.completed.len(), self.last_update_ms.saturating_sub(self.started_at_ms))
    }
}

pub fn make_key(target: &str, module: &str) -> String {
    format!("{}|{}", target, module)
}

pub fn now_ms() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_checkpoint_empty() {
        let c = Checkpoint::new("test");
        assert_eq!(c.completed.len(), 0);
        assert_eq!(c.engagement, "test");
    }
    #[test]
    fn mark_and_check() {
        let mut c = Checkpoint::new("test");
        c.mark_done("https://x.com/", "xss");
        assert!(c.is_done("https://x.com/", "xss"));
        assert!(!c.is_done("https://x.com/", "sqli"));
    }
    #[test]
    fn save_and_load() {
        let mut c = Checkpoint::new("persist-test");
        c.mark_done("https://a.com/", "xss");
        c.mark_done("https://b.com/", "sqli");
        let tmp = "/tmp/kobra_checkpoint_test.json";
        c.save(tmp).unwrap();
        let loaded = Checkpoint::load(tmp);
        assert_eq!(loaded.completed.len(), 2);
        assert!(loaded.is_done("https://a.com/", "xss"));
        let _ = fs::remove_file(tmp);
    }
    #[test]
    fn key_uniqueness() {
        assert_ne!(make_key("a", "b"), make_key("b", "a"));
    }
}
