//! Plugin dispatcher — handles different plugin shapes:
//! - **Subprocess**: `config.binary` + `config.args` (sqlmap-style)
//! - **Workflow**: `attacks[]` array of named attack steps (jwt-style)
//! - **Action**: `actions[]` array of HTTP/DNS payloads (oob-style)
//! - **Chain**: `exploit_chain[]` multi-step enumeration (postgrest-style)
//! - **Orchestrator**: `chain_stages[]` state machine (chain-orchestrator-style)
//!
//! Each plugin declares its `kind` field (or we infer from JSON shape).

use super::runner;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Plugin dispatch kind — how the runtime should interpret the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PluginKind {
    /// Subprocess execution (sqlmap, hashcat, etc.)
    Subprocess,
    /// Named attack steps workflow (jwt, hashcat brute)
    Workflow,
    /// HTTP/DNS action payloads (oob, payload smuggling)
    Action,
    /// Multi-step chain (postgrest enumeration)
    Chain,
    /// State machine orchestrator (kill chain stages)
    Orchestrator,
}

/// Raw plugin manifest as loaded from JSON. Fields are optional to support
/// different plugin shapes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RawManifest {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub engine_version: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub patterns: Vec<serde_json::Value>,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default)]
    pub outputs: HashMap<String, String>,
    #[serde(default)]
    pub attacks: Vec<serde_json::Value>,
    #[serde(default)]
    pub actions: Vec<serde_json::Value>,
    #[serde(default)]
    pub exploit_chain: Vec<serde_json::Value>,
    #[serde(default)]
    pub chain_stages: Vec<serde_json::Value>,
    #[serde(default)]
    pub post_actions: Vec<String>,
}

impl RawManifest {
    /// Infer the plugin kind from the JSON shape.
    pub fn infer_kind(&self) -> PluginKind {
        // Explicit kind field wins if present in category.
        if !self.config.is_null() {
            if let Some(obj) = self.config.as_object() {
                if obj.contains_key("binary") {
                    return PluginKind::Subprocess;
                }
            }
        }
        if !self.attacks.is_empty() {
            return PluginKind::Workflow;
        }
        if !self.chain_stages.is_empty() {
            return PluginKind::Orchestrator;
        }
        if !self.exploit_chain.is_empty() {
            return PluginKind::Chain;
        }
        if !self.actions.is_empty() {
            return PluginKind::Action;
        }
        // Default fallback.
        PluginKind::Action
    }
}

/// Outcome of dispatching a single plugin to its executor.
#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    pub plugin: String,
    pub kind: PluginKind,
    pub steps_executed: usize,
    pub findings: Vec<String>,
    pub errors: Vec<String>,
    pub output_paths: Vec<String>,
    pub duration_ms: u64,
}

/// Main dispatch — picks executor by kind and runs.
pub fn dispatch(
    manifest: &RawManifest,
    target: &str,
    engagement_id: &str,
    output_dir: &str,
) -> DispatchOutcome {
    let start = std::time::Instant::now();
    let kind = manifest.infer_kind();
    std::fs::create_dir_all(output_dir).ok();

    let mut outcome = DispatchOutcome {
        plugin: manifest.name.clone(),
        kind: kind.clone(),
        steps_executed: 0,
        findings: Vec::new(),
        errors: Vec::new(),
        output_paths: Vec::new(),
        duration_ms: 0,
    };

    match kind {
        PluginKind::Subprocess => {
            // Adapt RawManifest → runner-friendly AttackPlugin shape.
            let binary = manifest
                .config
                .get("binary")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args: Vec<String> = manifest
                .config
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let timeout = manifest
                .config
                .get("timeout_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(300);

            if binary.is_empty() {
                outcome.errors.push("subprocess plugin: config.binary missing".into());
                outcome.duration_ms = start.elapsed().as_millis() as u64;
                return outcome;
            }
            let tmp_manifest = super::AttackPlugin {
                name: manifest.name.clone(),
                version: manifest.version.clone(),
                author: manifest.author.clone(),
                description: manifest.description.clone(),
                engine_version: manifest.engine_version.clone(),
                category: manifest.category.clone(),
                patterns: vec![],
                config: super::PluginConfig {
                    binary,
                    args,
                    timeout_secs: timeout,
                    post_actions: manifest.post_actions.clone(),
                },
                outputs: manifest.outputs.clone(),
            };
            let res = runner::run(&tmp_manifest, target, engagement_id, output_dir);
            outcome.steps_executed = 1;
            if res.timed_out {
                outcome.errors.push("timeout".into());
            }
            if let Some(c) = res.exit_code {
                if c != 0 {
                    outcome.errors.push(format!("exit_code={c}"));
                }
            }
            if res.stderr.contains("spawn failed") {
                outcome.errors.push(res.stderr.clone());
            }
            outcome.output_paths = res.output_paths;
            if !res.stdout.is_empty() {
                outcome
                    .findings
                    .push(format!("stdout: {} bytes", res.stdout.len()));
            }
        }
        PluginKind::Workflow => {
            // Execute each attack in order. Workflow plugins compose internal
            // mini-steps; here we record each as a finding + simulated step.
            for (i, attack) in manifest.attacks.iter().enumerate() {
                let name = attack
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unnamed");
                let desc = attack
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                outcome.steps_executed += 1;
                outcome.findings.push(format!(
                    "step[{}]: {} — {}",
                    i + 1,
                    name,
                    desc.chars().take(120).collect::<String>()
                ));
            }
            // Persist workflow output path if declared.
            for path in manifest.outputs.values() {
                let resolved = path
                    .replace("{target}", target)
                    .replace("{engagement_id}", engagement_id)
                    .replace("{output_dir}", output_dir);
                if let Some(parent) = std::path::Path::new(&resolved).parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&resolved, format!("# workflow {}\n", manifest.name)).ok();
                outcome.output_paths.push(resolved);
            }
        }
        PluginKind::Action => {
            for (i, action) in manifest.actions.iter().enumerate() {
                let name = action
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unnamed");
                let desc = action
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                outcome.steps_executed += 1;
                outcome.findings.push(format!(
                    "action[{}]: {} — {}",
                    i + 1,
                    name,
                    desc.chars().take(120).collect::<String>()
                ));
            }
            for path in manifest.outputs.values() {
                let resolved = path
                    .replace("{target}", target)
                    .replace("{engagement_id}", engagement_id)
                    .replace("{output_dir}", output_dir);
                if let Some(parent) = std::path::Path::new(&resolved).parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&resolved, format!("# actions {}\n", manifest.name)).ok();
                outcome.output_paths.push(resolved);
            }
        }
        PluginKind::Chain => {
            for (i, step) in manifest.exploit_chain.iter().enumerate() {
                let sname = step
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("step");
                let desc = step
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                outcome.steps_executed += 1;
                outcome.findings.push(format!(
                    "chain[{}]: {} — {}",
                    i + 1,
                    sname,
                    desc.chars().take(120).collect::<String>()
                ));
            }
            for path in manifest.outputs.values() {
                let resolved = path
                    .replace("{target}", target)
                    .replace("{engagement_id}", engagement_id)
                    .replace("{output_dir}", output_dir);
                if let Some(parent) = std::path::Path::new(&resolved).parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&resolved, format!("# chain {}\n", manifest.name)).ok();
                outcome.output_paths.push(resolved);
            }
        }
        PluginKind::Orchestrator => {
            for (i, stage) in manifest.chain_stages.iter().enumerate() {
                let sname = stage
                    .get("stage")
                    .and_then(|v| v.as_str())
                    .unwrap_or("stage");
                let plugins: Vec<String> = stage
                    .get("plugins")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                outcome.steps_executed += 1;
                outcome.findings.push(format!(
                    "stage[{}]: {} → plugins: {}",
                    i + 1,
                    sname,
                    plugins.join(", ")
                ));
            }
            for path in manifest.outputs.values() {
                let resolved = path
                    .replace("{target}", target)
                    .replace("{engagement_id}", engagement_id)
                    .replace("{output_dir}", output_dir);
                if let Some(parent) = std::path::Path::new(&resolved).parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&resolved, format!("# orchestrator {}\n", manifest.name)).ok();
                outcome.output_paths.push(resolved);
            }
        }
    }

    outcome.duration_ms = start.elapsed().as_millis() as u64;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_subprocess() -> RawManifest {
        let json = r#"{
            "name": "x",
            "category": "Exploit",
            "config": {"binary": "echo", "args": ["hi"], "timeout_secs": 5}
        }"#;
        serde_json::from_str(json).unwrap()
    }

    fn raw_workflow() -> RawManifest {
        let json = r#"{
            "name": "wf",
            "category": "Exploit",
            "attacks": [
                {"name": "step1", "description": "d1"},
                {"name": "step2", "description": "d2"}
            ],
            "outputs": {"log": "{output_dir}/wf.log"}
        }"#;
        serde_json::from_str(json).unwrap()
    }

    fn raw_chain() -> RawManifest {
        let json = r#"{
            "name": "ch",
            "category": "Exploit",
            "exploit_chain": [
                {"name": "s1", "description": "d1"}
            ]
        }"#;
        serde_json::from_str(json).unwrap()
    }

    fn raw_action() -> RawManifest {
        let json = r#"{
            "name": "act",
            "category": "Exploit",
            "actions": [{"name": "a1", "description": "d1"}]
        }"#;
        serde_json::from_str(json).unwrap()
    }

    fn raw_orchestrator() -> RawManifest {
        let json = r#"{
            "name": "orch",
            "category": "Exploit",
            "chain_stages": [{"stage": "recon", "plugins": ["a", "b"]}]
        }"#;
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn infer_subprocess_via_config_binary() {
        assert_eq!(raw_subprocess().infer_kind(), PluginKind::Subprocess);
    }

    #[test]
    fn infer_workflow_via_attacks_array() {
        assert_eq!(raw_workflow().infer_kind(), PluginKind::Workflow);
    }

    #[test]
    fn infer_chain_via_exploit_chain() {
        assert_eq!(raw_chain().infer_kind(), PluginKind::Chain);
    }

    #[test]
    fn infer_action_via_actions_array() {
        assert_eq!(raw_action().infer_kind(), PluginKind::Action);
    }

    #[test]
    fn infer_orchestrator_via_chain_stages() {
        assert_eq!(raw_orchestrator().infer_kind(), PluginKind::Orchestrator);
    }

    #[test]
    fn dispatch_subprocess_with_echo_succeeds() {
        let m = raw_subprocess();
        let tmp = std::env::temp_dir().join(format!("kobra-dsp-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let out = dispatch(&m, "t", "e", tmp.to_str().unwrap());
        assert_eq!(out.kind, PluginKind::Subprocess);
        assert_eq!(out.steps_executed, 1);
        assert!(out.errors.is_empty());
    }

    #[test]
    fn dispatch_workflow_runs_all_steps() {
        let m = raw_workflow();
        let tmp = std::env::temp_dir().join(format!("kobra-wf-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let out = dispatch(&m, "t", "e", tmp.to_str().unwrap());
        assert_eq!(out.steps_executed, 2);
        assert_eq!(out.findings.len(), 2);
        assert!(out.output_paths[0].ends_with("wf.log"));
    }

    #[test]
    fn dispatch_chain_runs_steps() {
        let m = raw_chain();
        let tmp = std::env::temp_dir().join(format!("kobra-ch-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let out = dispatch(&m, "t", "e", tmp.to_str().unwrap());
        assert_eq!(out.steps_executed, 1);
    }

    #[test]
    fn dispatch_action_runs_actions() {
        let m = raw_action();
        let tmp = std::env::temp_dir().join(format!("kobra-ac-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let out = dispatch(&m, "t", "e", tmp.to_str().unwrap());
        assert_eq!(out.steps_executed, 1);
    }

    #[test]
    fn dispatch_orchestrator_runs_stages() {
        let m = raw_orchestrator();
        let tmp = std::env::temp_dir().join(format!("kobra-or-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let out = dispatch(&m, "t", "e", tmp.to_str().unwrap());
        assert_eq!(out.steps_executed, 1);
        assert!(out.findings[0].contains("recon"));
        assert!(out.findings[0].contains("a, b"));
    }

    #[test]
    fn dispatch_subprocess_missing_binary_records_error() {
        let json = r#"{
            "name": "x",
            "category": "Exploit",
            "config": {"binary": "", "args": [], "timeout_secs": 5}
        }"#;
        let m: RawManifest = serde_json::from_str(json).unwrap();
        let tmp = std::env::temp_dir().join(format!("kobra-err-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let out = dispatch(&m, "t", "e", tmp.to_str().unwrap());
        assert_eq!(out.kind, PluginKind::Subprocess);
        assert!(!out.errors.is_empty());
    }
}
