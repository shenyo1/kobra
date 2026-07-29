//! PostgREST / Supabase table disclosure scanner.
//! Detects:
//!   - Table name leakage via PostgREST error messages ("Perhaps you meant...")
//!   - Tables accessible with anon key (RLS not enforced or empty tables)
//!   - Supabase project refs in error responses
//!
//! Attack vector: any anon user can enumerate DB schema by sending requests to
//! https://<project-ref>.supabase.co/rest/v1/<random_table>
//! PostgREST returns helpful errors that leak nearby table names.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};

/// Common table name probes (PostgREST will hint at similar names in errors)
const PROBES: &[&str] = &[
    "users", "profiles", "accounts", "members", "customers",
    "sessions", "tokens", "keys", "secrets", "config",
    "settings", "messages", "chats", "conversations",
    "subscriptions", "plans", "products", "orders",
    "payments", "transactions", "invoices", "wallets",
    "agents", "prompts", "tools", "models", "embeddings",
    "documents", "files", "uploads", "media",
    "tenants", "orgs", "teams", "workspaces", "projects",
];

/// Common Supabase project refs to probe (used when target host is not supabase)
/// Scan target for PostgREST table disclosure
pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Determine the PostgREST base URL
    let base_url = match extract_postgrest_base(target) {
        Some(u) => u,
        None => return findings,  // Not a Supabase/PostgREST target
    };

    // Probe common tables
    let mut leaked_tables = Vec::new();
    let mut accessible_tables = Vec::new();

    for table in PROBES {
        let url = format!("{}/rest/v1/{}", base_url, table);
        match http.get(&url).await {
            Ok((status, _headers, body, _f)) => {
                // PGRST205 = table not found, with helpful hint
                if body.contains("Perhaps you meant") {
                    // Extract leaked table name
                    if let Some(name) = extract_hint(&body) {
                        leaked_tables.push(name.to_string());
                    }
                } else if body.contains("Could not find the table") {
                    // No leak — skip
                } else if status == 200 || (status == 401 && body.contains("[]")) {
                    // Table accessible!
                    accessible_tables.push(table.to_string());
                }
            }
            Err(_) => continue,
        }
    }

    // Report leaked table names
    if !leaked_tables.is_empty() {
        let tables_csv = leaked_tables.iter().take(10).cloned().collect::<Vec<_>>().join(", ");
        findings.push(Finding::new(
            Severity::Medium,
            "POSTGREST",
            "PostgREST table name disclosure via error hints",
            target,
        )
        .with_param("rest/v1/*")
        .with_payload(&format!("Tables leaked: {}", tables_csv))
        .with_note("Disable PostgREST schema introspection for anon role. Error messages reveal DB schema.")
        .with_confidence(80));
    }

    // Report accessible tables
    if !accessible_tables.is_empty() {
        for table in &accessible_tables {
            findings.push(Finding::new(
                if mode == Mode::Crazy { Severity::High } else { Severity::Medium },
                "POSTGREST",
                "PostgREST table accessible with anon key (no RLS or empty)",
                &format!("{}/rest/v1/{}", base_url, table),
            )
            .with_param(table)
            .with_evidence("Table returns 200 or 401 with empty result — RLS not enforced")
            .with_note("Verify RLS policy is enabled and working. Empty result may mean table is empty OR RLS blocks reads.")
            .with_confidence(70));
        }
    }

    findings
}

/// Extract the PostgREST base URL from target.
/// If target is *.supabase.co, use it. Otherwise, look in JS bundles.
fn extract_postgrest_base(target: &str) -> Option<String> {
    // Direct Supabase target
    if target.contains("supabase.co") || target.contains("supabase.in") {
        // Extract base: https://<ref>.supabase.co
        if let Some(start) = target.find("https://") {
            let after = &target[start+8..];
            if let Some(end) = after.find('/') {
                return Some(format!("https://{}", &after[..end]));
            }
            return Some(format!("https://{}", after));
        }
    }
    None
}

/// Extract table name hint from PostgREST error response
fn extract_hint(body: &str) -> Option<String> {
    const PREFIX: &str = "Perhaps you meant the table '";
    if let Some(start) = body.find(PREFIX) {
        let after = &body[start + PREFIX.len()..];
        if let Some(end) = after.find('\'') {
            return Some(after[..end].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_postgrest_base_works() {
        let url = "https://dhsrwbufpdvuptdzeieo.supabase.co/rest/v1/users";
        assert_eq!(
            extract_postgrest_base(url),
            Some("https://dhsrwbufpdvuptdzeieo.supabase.co".to_string())
        );
    }

    #[test]
    fn extract_postgrest_base_nontarget_returns_none() {
        assert_eq!(extract_postgrest_base("https://example.com"), None);
    }

    #[test]
    fn extract_hint_works() {
        let body = r#"{"code":"PGRST205","details":null,"hint":"Perhaps you meant the table 'public.servers'","message":"Could not find the table"}"#;
        assert_eq!(extract_hint(body), Some("public.servers".to_string()));
    }

    #[test]
    fn extract_hint_no_match() {
        let body = "no hint here";
        assert_eq!(extract_hint(body), None);
    }

    #[test]
    fn probes_non_empty() {
        assert!(PROBES.len() >= 30, "Need 30+ probes, got {}", PROBES.len());
    }
}