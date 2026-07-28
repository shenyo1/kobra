//! Wordlist Fuzzing — ffuf-style parameter and path fuzzing with custom wordlists.
//! Supports SecLists-compatible wordlists (one entry per line).

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use std::collections::HashSet;

/// Default wordlist for path fuzzing (common endpoints)
const DEFAULT_PATHS: &[&str] = &[
    "admin", "login", "register", "api", "graphql", "debug", "status",
    "health", "metrics", "swagger", "docs", "redoc", "openapi.json",
    ".env", ".git/config", "robots.txt", "sitemap.xml", "wp-login.php",
    "phpinfo.php", "server-status", "actuator", "actuator/env",
    "console", "dashboard", "config", "backup", "dump", "test",
    "internal", "private", "secret", "staging", "dev", "debug/vars",
    "api/v1", "api/v2", "api/v3", "v1", "v2", "v3",
    "wp-json", "xmlrpc.php", ".well-known", "favicon.ico",
    "package.json", "composer.json", "Gemfile", "requirements.txt",
    "Dockerfile", "docker-compose.yml", ".dockerenv",
    "api/users", "api/admin", "api/config", "api/keys",
    "api/tokens", "api/sessions", "api/webhooks",
    "graphql/console", "graphiql", "playground",
    "trace", "info", "env", "beans", "mappings", "configprops",
    "heapdump", "threaddump", "loggers", "conditions",
];

/// Default wordlist for parameter fuzzing
const DEFAULT_PARAMS: &[&str] = &[
    "id", "user", "uid", "userid", "user_id", "username", "name",
    "email", "token", "key", "api_key", "apikey", "secret",
    "file", "path", "page", "url", "redirect", "next", "return",
    "callback", "continue", "dest", "destination", "go", "out",
    "q", "query", "search", "s", "keyword", "term",
    "cmd", "command", "exec", "execute", "run", "code",
    "data", "input", "value", "param", "arg", "option",
    "debug", "test", "admin", "role", "level", "access",
    "order", "sort", "filter", "limit", "offset", "page",
];

/// Fuzz paths on a target using a wordlist
pub async fn fuzz_paths(
    http: &HttpClient,
    target: &str,
    wordlist: Option<&[String]>,
    mode: Mode,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = target.trim_end_matches('/');

    let paths: Vec<String> = match wordlist {
        Some(wl) => wl.to_vec(),
        None => DEFAULT_PATHS.iter().map(|s| s.to_string()).collect(),
    };

    // Limit based on mode
    let limit = match mode {
        Mode::Stealth => 10,
        Mode::Normal => paths.len().min(30),
        Mode::Crazy => paths.len(),
    };

    let mut seen_status: HashSet<u16> = HashSet::new();

    for path in paths.iter().take(limit) {
        let url = format!("{}/{}", base, path.trim_start_matches('/'));
        if let Ok((st, _h, body, _f)) = http.get(&url).await {
            // Interesting status codes
            match st {
                200 => {
                    // Check if it's not a generic 404 page (some servers return 200 for everything)
                    if body.len() > 100 && !body.contains("404") && !body.contains("not found") {
                        findings.push(
                            Finding::new(Severity::Info, "FUZZ", &format!("Path found: /{}", path), target)
                                .with_evidence(&format!("HTTP 200, {} bytes", body.len()))
                                .with_confidence(60),
                        );
                    }
                }
                301 | 302 | 307 | 308 => {
                    findings.push(
                        Finding::new(Severity::Info, "FUZZ", &format!("Redirect: /{}", path), target)
                            .with_evidence(&format!("HTTP {}", st))
                            .with_confidence(50),
                    );
                }
                401 | 403 => {
                    findings.push(
                        Finding::new(Severity::Low, "FUZZ", &format!("Protected path: /{}", path), target)
                            .with_evidence(&format!("HTTP {} — exists but requires auth", st))
                            .with_confidence(70),
                    );
                }
                500 => {
                    findings.push(
                        Finding::new(Severity::Medium, "FUZZ", &format!("Server error: /{}", path), target)
                            .with_evidence(&format!("HTTP 500 — possible crash/info leak"))
                            .with_confidence(75),
                    );
                }
                _ => {}
            }
            seen_status.insert(st);
        }
    }

    findings
}

/// Fuzz parameters on a target URL
pub async fn fuzz_params(
    http: &HttpClient,
    target: &str,
    wordlist: Option<&[String]>,
    mode: Mode,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = target.trim_end_matches('/');

    let params: Vec<String> = match wordlist {
        Some(wl) => wl.to_vec(),
        None => DEFAULT_PARAMS.iter().map(|s| s.to_string()).collect(),
    };

    let limit = match mode {
        Mode::Stealth => 5,
        Mode::Normal => params.len().min(20),
        Mode::Crazy => params.len(),
    };

    // Baseline: request without params
    let (baseline_st, _, baseline_body, _) = match http.get(&format!("{}/", base)).await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    for param in params.iter().take(limit) {
        let url = format!("{}?{}=FUZZ", base, param);
        if let Ok((st, _h, body, _f)) = http.get(&url).await {
            // If response differs significantly from baseline, param is reflected
            if st == baseline_st && body.len() != baseline_body.len() {
                let diff = (body.len() as i64 - baseline_body.len() as i64).unsigned_abs();
                if diff > 50 {
                    findings.push(
                        Finding::new(Severity::Info, "FUZZ", &format!("Parameter reflected: {}", param), target)
                            .with_param(param)
                            .with_evidence(&format!("Response size changed by {} bytes", diff))
                            .with_confidence(55),
                    );
                }
            }
            // Error-based: param triggers different status
            if st != baseline_st && (st == 500 || st == 400) {
                findings.push(
                    Finding::new(Severity::Low, "FUZZ", &format!("Parameter causes error: {}", param), target)
                        .with_param(param)
                        .with_evidence(&format!("HTTP {} (baseline: {})", st, baseline_st))
                        .with_confidence(60),
                );
            }
        }
    }

    findings
}

/// Load a wordlist from file (one entry per line, # comments ignored)
pub fn load_wordlist(path: &str) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(content) => content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect(),
        Err(_) => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_non_empty() {
        assert!(DEFAULT_PATHS.len() > 30);
    }

    #[test]
    fn default_params_non_empty() {
        assert!(DEFAULT_PARAMS.len() > 30);
    }

    #[test]
    fn load_nonexistent_wordlist() {
        let wl = load_wordlist("/nonexistent/file.txt");
        assert!(wl.is_empty());
    }

    #[test]
    fn load_wordlist_filters_comments() {
        let tmp = "/tmp/kobra_test_wl.txt";
        std::fs::write(tmp, "admin\n# comment\n\nlogin\n").ok();
        let wl = load_wordlist(tmp);
        assert_eq!(wl.len(), 2);
        assert_eq!(wl[0], "admin");
        assert_eq!(wl[1], "login");
        std::fs::remove_file(tmp).ok();
    }
}
