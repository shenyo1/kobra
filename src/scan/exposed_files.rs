//! Exposed sensitive files detection (.env, .git, backups, config).
//! 500+ path wordlist + CMS fingerprints.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};

/// Subset of most impactful sensitive paths.
const SENSITIVE_PATHS: &[&str] = &[
    "/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.backup",
    "/.env.sample", "/.env.example", "/env", "/env.local",
    "/.git/config", "/.git/HEAD", "/.git/index", "/.gitignore",
    "/.svn/entries", "/.hg/store",
    "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.bak",
    "/configuration.php.bak", "/web.config", "/web.config.bak",
    "/server.cfg", "/server.ini", "/server.yaml",
    "/config.php", "/config.yml", "/config.yaml", "/config.json", "/config.ini",
    "/config.xml", "/config.old", "/config.bak",
    "/database.yml", "/database.yaml", "/database.json",
    "/credentials", "/credentials.json", "/credentials.txt",
    "/secrets", "/secrets.json", "/secrets.yaml",
    "/admin", "/admin/", "/admin.php", "/admin/login",
    "/phpinfo.php", "/info.php", "/test.php",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.sql.gz", "/backup.bak",
    "/db.sql", "/dump.sql", "/database.sql",
    "/debug.log", "/error.log", "/app.log", "/laravel.log", "/storage/logs/laravel.log",
    "/.htpasswd", "/.htaccess",
    "/crossdomain.xml", "/sitemap.xml",
    "/composer.json", "/composer.lock", "/package.json", "/package-lock.json",
    "/Gemfile", "/Gemfile.lock", "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    "/.idea/workspace.xml", "/.vscode/settings.json",
    "/Procfile", "/Dockerfile", "/docker-compose.yml",
    "/id_rsa", "/id_dsa", "/id_ecdsa", "/id_ed25519",
    "/server.key", "/server.pem", "/private.key", "/private.pem",
    "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/known_hosts",
    "/.bash_history", "/.zsh_history", "/.psql_history",
    "/actuator", "/actuator/env", "/actuator/beans", "/actuator/health",
    "/actuator/info", "/actuator/mappings", "/actuator/configprops",
    "/swagger-ui.html", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/graphql", "/graphiql", "/altair",
    "/trace", "/trace.axd", "/elmah.axd",
    "/server-status", "/server-info", "/.DS_Store", "/Thumbs.db",
    "/WEB-INF/web.xml", "/META-INF/MANIFEST.MF",
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v1/users", "/api/v1/admin",
    "/debug/default/view", "/debug/vars", "/_debug", "/_profiler",
    "/_status", "/_health", "/health", "/healthz", "/ready", "/live",
    "/metrics", "/prometheus",
    "/wp-admin", "/administrator", "/admin/login.php",
    "/cgi-bin/", "/cgi-bin/test.cgi",
    "/.well-known/security.txt", "/.well-known/openid-configuration",
];

/// Body signatures that confirm the path is the actual file (not 404 page).
/// IMPORTANT: Each signature must be DISTINCTIVE — must only match its target file,
/// NOT generic URLs that happen to contain the string.
/// Fix v4.2.0: removed "localhost" (too broad — matched Juice Shop security.txt CSAF URL).
/// Fix v4.2.0: removed "database" (too broad — matches any DB doc).
/// Fix v4.2.0: narrowed "secret_key" to "secret_key=" (avoid random HTML).
const BODY_SIGNATURES: &[(&str, &str)] = &[
    ("DB_PASSWORD=", ".env"),
    ("APP_KEY=base64:", "Laravel .env"),
    ("APP_DEBUG=true", ".env"),
    ("[core]", ".git/config"),
    ("repositoryformatversion", ".git/config"),
    ("ref: refs/", ".git/HEAD"),
    ("ref: refs/heads/", ".git/HEAD"),
    ("-----BEGIN", "private key"),
    ("-----BEGIN RSA", "RSA private key"),
    ("-----BEGIN OPENSSH", "SSH private key"),
    ("-----BEGIN PRIVATE", "private key"),
    ("AKIA", "AWS key"),
    ("ASIA", "AWS temporary key"),
    ("postgres://", "DB connection string"),
    ("mysql://", "DB connection string"),
    ("mongodb://", "DB connection string"),
    ("/etc/passwd", "passwd leak"),
    ("root:x:0:0", "/etc/passwd leak"),
    ("<?xml version=", "config.xml"),
    ("<configuration>", "config.xml"),
    ("client_secret", "OAuth secret"),
    ("api_key=", "API key"),
    ("apiKey=", "API key"),
    ("secret_key=", "secret"),
    ("SECRET_KEY=", "secret"),
    ("# HELP", "Prometheus metrics"),
    ("# TYPE", "Prometheus metrics"),
];

pub fn matches_signature(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();
    for (sig, _label) in BODY_SIGNATURES {
        if lower.contains(&sig.to_lowercase()) {
            return Some(sig);
        }
    }
    None
}

pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    let base = normalize_base(target);
    let limit = match mode {
        Mode::Stealth => 30,
        Mode::Normal => 100,
        Mode::Crazy => SENSITIVE_PATHS.len(),
    };
    // Negative-control baseline: fetch / once and check if all "exposed" paths
    // return the same body (SPA fallback). Fix v4.2.0 — prevents 9903-byte SPA
    // HTML false positives.
    let baseline_hash = match http.get(&base).await {
        Ok((_, _, body, _)) => Some(hash_body(&body)),
        Err(_) => None,
    };
    for path in SENSITIVE_PATHS.iter().take(limit) {
        let url = format!("{}{}", base, path);
        if let Ok((st, _h, body, _f)) = http.get(&url).await {
            if st == 200 && body.len() > 10 && !body.to_lowercase().contains("<html") {
                // Negative-control: if body matches baseline, it's SPA fallback
                if let Some(bh) = baseline_hash {
                    if hash_body(&body) == bh {
                        continue; // SPA fallback — skip
                    }
                }
                let sig = matches_signature(&body);
                let sev = match sig {
                    Some(_) => Severity::Critical,
                    None => Severity::Medium,
                };
                findings.push(Finding {
                    severity: sev,
                    category: "EXPOSED".into(),
                    title: format!("Exposed file: {}", path),
                    target: url,
                    param: None,
                    payload: None,
                    evidence: Some(format!(
                        "status={} len={} sig={:?}",
                        st,
                        body.len(),
                        sig.unwrap_or("(no signature)")
                    )),
                    confidence: 80,
                    note: Some("Manual verify content; report if contains credentials or secrets".into()),
                    request: None,
                    response: None,
                });
            }
        }
    }
    findings
}

fn normalize_base(url: &str) -> String {
    if let Some(idx) = url.find('?') {
        url[..idx].to_string()
    } else if let Some(idx) = url.find('#') {
        url[..idx].to_string()
    } else {
        url.to_string()
    }
}

/// Fast body hash for negative-control comparison (FNV-1a 64-bit).
/// Same body bytes → same hash → SPA fallback.
fn hash_body(body: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in body.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sig_env() {
        let body = "DB_PASSWORD=hunter2\nAPP_KEY=base64:xxx";
        assert!(matches_signature(body).is_some());
    }
    #[test]
    fn sig_git_config() {
        let body = "[core]\n\trepositoryformatversion = 0";
        assert!(matches_signature(body).is_some());
    }
    #[test]
    fn sig_none() {
        let body = "just some random text";
        assert!(matches_signature(body).is_none());
    }
    #[test]
    fn path_count_min() {
        assert!(SENSITIVE_PATHS.len() >= 50);
    }

    #[test]
    fn hash_body_identical() {
        let h1 = hash_body("hello world");
        let h2 = hash_body("hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_body_different() {
        let h1 = hash_body("hello");
        let h2 = hash_body("world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sig_no_localhost() {
        // Remove localhost signature — too broad, matches any URL containing it.
        let body = "CSAF: http://localhost:3000/.well-known/csaf";
        assert!(matches_signature(body).is_none(),
            "localhost signature was removed in v4.2.0 — but body still matches");
    }

    #[test]
    fn sig_prometheus() {
        let body = "# HELP foo bar\n# TYPE foo counter\nfoo 1\n";
        assert!(matches_signature(body).is_some());
    }
}
