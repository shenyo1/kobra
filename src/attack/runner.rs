//! Attack plugin subprocess runner.
//!
//! Executes plugin commands with timeout, captures stdout/stderr, and reports
//! execution results for the report layer.

use super::AttackPlugin;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Result of a single plugin invocation.
#[derive(Debug, Clone)]
pub struct PluginRunResult {
    pub plugin: String,
    pub binary: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub output_paths: Vec<String>,
}

/// Substitute `{target}`, `{engagement_id}`, `{output_dir}` in arg strings.
pub fn render_args(plugin: &AttackPlugin, target: &str, engagement_id: &str, output_dir: &str) -> Vec<String> {
    plugin
        .config
        .args
        .iter()
        .map(|a| {
            a.replace("{target}", target)
                .replace("{engagement_id}", engagement_id)
                .replace("{output_dir}", output_dir)
        })
        .collect()
}

/// Execute a plugin's configured binary with rendered args + timeout.
///
/// Uses a thread-based timeout because `Command::spawn` + `wait_timeout` is not
/// stable on all platforms. We read stdout/stderr in separate threads to avoid
/// pipe-buffer deadlock on long-output tools (sqlmap, hashcat).
pub fn run(plugin: &AttackPlugin, target: &str, engagement_id: &str, output_dir: &str) -> PluginRunResult {
    let args = render_args(plugin, target, engagement_id, output_dir);
    let binary = plugin.config.binary.clone();
    let timeout = Duration::from_secs(plugin.config.timeout_secs);

    let start = std::time::Instant::now();

    let mut cmd = Command::new(&binary);
    cmd.args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return PluginRunResult {
                plugin: plugin.name.clone(),
                binary,
                args,
                exit_code: None,
                timed_out: false,
                stdout: String::new(),
                stderr: format!("spawn failed: {e}"),
                duration_ms: start.elapsed().as_millis() as u64,
                output_paths: vec![],
            };
        }
    };

    let mut stdout_handle = child.stdout.take();
    let mut stderr_handle = child.stderr.take();

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(ref mut h) = stdout_handle {
            // Cap read to 1MB to avoid unbounded memory.
            let _ = h.take(1_048_576).read_to_string(&mut buf);
        }
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(ref mut h) = stderr_handle {
            let _ = h.take(1_048_576).read_to_string(&mut buf);
        }
        buf
    });

    // Poll for completion vs timeout.
    let timed_out;
    let exit_code;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                timed_out = false;
                exit_code = status.code();
                break;
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    exit_code = None;
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                timed_out = false;
                exit_code = None;
                let _ = e;
                let _ = writeln!(std::io::stderr(), "wait error: {e}");
                break;
            }
        }
    }

    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    // Collect output paths that now exist on disk.
    let output_paths: Vec<String> = plugin
        .outputs
        .values()
        .map(|pattern| {
            pattern
                .replace("{target}", target)
                .replace("{engagement_id}", engagement_id)
                .replace("{output_dir}", output_dir)
        })
        .filter(|p| std::path::Path::new(p).exists())
        .collect();

    PluginRunResult {
        plugin: plugin.name.clone(),
        binary,
        args,
        exit_code,
        timed_out,
        stdout,
        stderr,
        duration_ms: start.elapsed().as_millis() as u64,
        output_paths,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::{AttackPattern, PluginConfig};

    fn mk_plugin(binary: &str, args: Vec<String>, timeout: u64) -> AttackPlugin {
        AttackPlugin {
            name: "test-plugin".to_string(),
            version: "1.0.0".to_string(),
            author: "t".to_string(),
            description: "t".to_string(),
            engine_version: ">=4.5.0".to_string(),
            category: "Exploit".to_string(),
            patterns: vec![AttackPattern {
                kind: "trigger".to_string(),
                value: "e".to_string(),
                severity_hint: None,
            }],
            config: PluginConfig {
                binary: binary.to_string(),
                args,
                timeout_secs: timeout,
                post_actions: vec![],
            },
            outputs: Default::default(),
        }
    }

    #[test]
    fn render_args_substitutes_placeholders() {
        let p = mk_plugin("echo", vec!["{target}".into(), "{engagement_id}".into()], 5);
        let r = render_args(&p, "https://x.com", "eng42", "/tmp/o");
        assert_eq!(r, vec!["https://x.com", "eng42"]);
    }

    #[test]
    fn run_echo_succeeds_and_captures_stdout() {
        let p = mk_plugin("echo", vec!["hello-kobra".into()], 5);
        let res = run(&p, "t", "e", "/tmp");
        assert_eq!(res.exit_code, Some(0));
        assert!(res.stdout.contains("hello-kobra"));
        assert!(!res.timed_out);
    }

    #[test]
    fn run_nonexistent_binary_returns_error_gracefully() {
        let p = mk_plugin("definitely-not-a-binary-xyz", vec![], 5);
        let res = run(&p, "t", "e", "/tmp");
        assert_eq!(res.exit_code, None);
        assert!(!res.timed_out);
        assert!(res.stderr.contains("spawn failed"));
    }

    #[test]
    fn run_short_timeout_marks_timed_out() {
        let p = mk_plugin("sleep", vec!["10".into()], 1);
        let res = run(&p, "t", "e", "/tmp");
        assert!(res.timed_out);
    }

    #[test]
    fn run_captures_stderr() {
        let p = mk_plugin("sh", vec!["-c".into(), "echo err 1>&2".into()], 5);
        let res = run(&p, "t", "e", "/tmp");
        assert_eq!(res.exit_code, Some(0));
        assert!(res.stderr.contains("err"));
    }
}
