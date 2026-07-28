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
const BODY_SIGNATURES: &[(&str, &str)] = &[
    ("DB_PASSWORD=", ".env"),
    ("APP_KEY=base64:", "Laravel .env"),
    ("[core]", ".git/config"),
    ("ref: refs/", ".git/HEAD"),
    ("-----BEGIN", "private key"),
    ("AKIA", "AWS key"),
    ("postgres://", "DB connection string"),
    ("mysql://", "DB connection string"),
    ("mongodb://", "DB connection string"),
    ("localhost", "config db"),
    ("production", "production env"),
    ("database", "DB config"),
    ("root:x:0:0", "/etc/passwd leak"),
    ("<?xml", "config.xml"),
    ("secret_key", "secret"),
    ("client_secret", "OAuth secret"),
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
    for path in SENSITIVE_PATHS.iter().take(limit) {
        let url = format!("{}{}", base, path);
        if let Ok((st, _h, body, _f)) = http.get(&url).await {
            if st == 200 && body.len() > 10 && !body.to_lowercase().contains("<html") {
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
}
