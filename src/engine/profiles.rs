//! Scan Profiles — preset configurations for common scenarios.
//! Profiles: bb (bug bounty), pentest (compliance), quick (fast triage).
//! Location: ~/.config/kobra/profiles/<name>.json

use crate::types::Mode;
use std::collections::HashMap;
use std::fs;

/// Scan profile containing all CLI flags
#[derive(Debug, Clone)]
pub struct ScanProfile {
    pub name: String,
    pub mode: Mode,
    pub concurrency: Option<usize>,
    pub timeout: Option<u64>,
    pub no_confirm: bool,
    pub simple: bool,
    pub triage: bool,
    pub browser: bool,
    pub template_dir: Option<String>,
    pub nuclei_dir: Option<String>,
    pub plugin_dir: Option<String>,
    pub wordlist: Option<String>,
    pub modules: Vec<String>, // Module whitelist (empty = all)
    pub skip_modules: Vec<String>, // Module blacklist
}

/// Built-in profiles
pub fn builtin_profiles() -> HashMap<String, ScanProfile> {
    let mut profiles = HashMap::new();

    // Bug Bounty — aggressive, full coverage
    profiles.insert("bb".to_string(), ScanProfile {
        name: "bb".to_string(),
        mode: Mode::Crazy,
        concurrency: Some(30),
        timeout: Some(30),
        no_confirm: false,
        simple: false,
        triage: true,
        browser: true,
        template_dir: None,
        nuclei_dir: None,
        plugin_dir: None,
        wordlist: None,
        modules: vec![],
        skip_modules: vec![],
    });

    // Penetration Testing — compliance-focused, thorough
    profiles.insert("pentest".to_string(), ScanProfile {
        name: "pentest".to_string(),
        mode: Mode::Normal,
        concurrency: Some(15),
        timeout: Some(20),
        no_confirm: false,
        simple: false,
        triage: true,
        browser: false,
        template_dir: None,
        nuclei_dir: None,
        plugin_dir: None,
        wordlist: None,
        modules: vec![],
        skip_modules: vec!["ip_ban_bypass".to_string(), "smuggle_v2".to_string()],
    });

    // Quick Triage — fast, low-noise
    profiles.insert("quick".to_string(), ScanProfile {
        name: "quick".to_string(),
        mode: Mode::Stealth,
        concurrency: Some(5),
        timeout: Some(10),
        no_confirm: false,
        simple: true,
        triage: false,
        browser: false,
        template_dir: None,
        nuclei_dir: None,
        plugin_dir: None,
        wordlist: None,
        modules: vec![],
        skip_modules: vec![]
    });

    // CI/CD — automated, no confirmation, JSON output
    profiles.insert("ci".to_string(), ScanProfile {
        name: "ci".to_string(),
        mode: Mode::Normal,
        concurrency: Some(20),
        timeout: Some(15),
        no_confirm: true, // NEVER prompt in CI
        simple: false,
        triage: true,
        browser: false,
        template_dir: None,
        nuclei_dir: None,
        plugin_dir: None,
        wordlist: None,
        modules: vec![],
        skip_modules: vec!["headless".to_string()], // No Chrome in CI
    });

    profiles
}

/// Load profile from custom file (~/.config/kobra/profiles/<name>.json)
pub fn load_profile(name: &str) -> Option<ScanProfile> {
    // First check built-in
    if let Some(p) = builtin_profiles().get(name) {
        return Some(p.clone());
    }

    // Then check custom
    let path = format!("{}/.config/kobra/profiles/{}.json", std::env::var("HOME").unwrap_or_default(), name);
    if let Ok(content) = fs::read_to_string(&path) {
        if let Ok(custom) = serde_json::from_str::<serde_json::Value>(&content) {
            return Some(profile_from_json(&custom, name));
        }
    }

    None
}

fn profile_from_json(json: &serde_json::Value, name: &str) -> ScanProfile {
    let mode_str = json["mode"].as_str().unwrap_or("normal");
    let mode = match mode_str {
        "crazy" | "gila" => Mode::Crazy,
        "stealth" => Mode::Stealth,
        _ => Mode::Normal,
    };

    ScanProfile {
        name: name.to_string(),
        mode,
        concurrency: json["concurrency"].as_u64().map(|n| n as usize),
        timeout: json["timeout"].as_u64(),
        no_confirm: json["no_confirm"].as_bool().unwrap_or(false),
        simple: json["simple"].as_bool().unwrap_or(false),
        triage: json["triage"].as_bool().unwrap_or(false),
        browser: json["browser"].as_bool().unwrap_or(false),
        template_dir: json["template_dir"].as_str().map(String::from),
        nuclei_dir: json["nuclei_dir"].as_str().map(String::from),
        plugin_dir: json["plugin_dir"].as_str().map(String::from),
        wordlist: json["wordlist"].as_str().map(String::from),
        modules: json["modules"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        skip_modules: json["skip_modules"].as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default(),
    }
}

/// Print profile list
pub fn list_profiles() {
    let profiles = builtin_profiles();
    println!("📋 Available profiles:");
    for (name, profile) in profiles.iter() {
        println!("  • {:10} — mode={:?}, concurrency={}, triage={}, browser={}",
            name, profile.mode, profile.concurrency.unwrap_or(0),
            profile.triage, profile.browser);
    }
    println!("\nCustom profiles: ~/.config/kobra/profiles/<name>.json");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_has_bb() {
        let profiles = builtin_profiles();
        assert!(profiles.contains_key("bb"));
        assert!(profiles.contains_key("pentest"));
        assert!(profiles.contains_key("quick"));
        assert!(profiles.contains_key("ci"));
    }

    #[test]
    fn bb_profile_is_crazy() {
        let p = builtin_profiles().get("bb").unwrap().clone();
        assert!(matches!(p.mode, Mode::Crazy));
        assert!(p.triage);
    }

    #[test]
    fn quick_profile_is_stealth() {
        let p = builtin_profiles().get("quick").unwrap().clone();
        assert!(matches!(p.mode, Mode::Stealth));
        assert!(p.simple);
    }

    #[test]
    fn ci_profile_no_confirm() {
        let p = builtin_profiles().get("ci").unwrap().clone();
        assert!(p.no_confirm);
        assert!(!p.browser); // No Chrome in CI
    }

    #[test]
    fn load_builtin_profile() {
        let p = load_profile("bb");
        assert!(p.is_some());
        assert_eq!(p.unwrap().name, "bb");
    }

    #[test]
    fn load_nonexistent_profile() {
        let p = load_profile("nonexistent_profile_xyz");
        assert!(p.is_none());
    }
}
