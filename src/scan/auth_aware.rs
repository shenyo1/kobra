//! Auth-aware probing (Priority 4 fix v4.3.0).
//! Lesson: KOBRA v4.2.0 had --auth flag but modules didn't know to probe differently.
//! Fix: when auth is detected, expand probe space (auth-only endpoints, deeper paths).

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};

/// Detect if HTTP client has auth configured (headers or cookie).
pub fn has_auth(http: &HttpClient) -> bool {
    !http.extra_headers.is_empty() || http.cookie.is_some()
}

/// Auth-only endpoint patterns (only meaningful with valid auth session).
const AUTH_PROTECTED_PATHS: &[&str] = &[
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/api/user/profile", "/api/user/settings",
    "/api/account", "/api/account/settings",
    "/api/private", "/api/internal", "/api/dashboard",
    "/api/billing", "/api/billing/invoices",
    "/api/orders", "/api/orders/all",
    "/api/users", "/api/users/all",
    "/api/v1/admin", "/api/v1/private", "/api/v1/internal",
    "/internal/api", "/_internal",
    "/admin", "/admin/api", "/admin/users", "/admin/config", "/admin/dashboard",
    "/dashboard", "/dashboard/api",
    "/account", "/account/settings",
    "/profile", "/settings",
    "/billing", "/orders",
];

/// Run auth-aware probes (only when auth is configured).
pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut out = Vec::new();

    if !has_auth(http) {
        out.push(Finding::new(Severity::Info, "AUTH-AWARE",
            "Auth-aware scan SKIPPED (no --auth configured). Run with --auth \"url|body\" for authenticated probing.",
            target)
            .with_evidence("has_auth=false; auth-protected paths not probed")
            .with_confidence(100));
        return out;
    }

    let limit = match mode {
        Mode::Stealth => 5,
        Mode::Normal => 15,
        Mode::Crazy => AUTH_PROTECTED_PATHS.len(),
    };

    let base = target.trim_end_matches('/');
    let mut accessible: Vec<(&str, u16, usize)> = Vec::new();

    for path in AUTH_PROTECTED_PATHS.iter().take(limit) {
        let url = format!("{}{}", base, path);
        if let Ok((st, _h, body, _f)) = http.get(&url).await {
            let bl = body.to_lowercase();
            let is_html = bl.contains("<html") || bl.contains("<!doctype");
            if st == 200 && body.len() > 20 && !is_html {
                accessible.push((path, st, body.len()));
            }
        }
    }

    if !accessible.is_empty() {
        out.push(Finding::new(Severity::Medium, "AUTH-AWARE",
            "Auth-only endpoints accessible (potential IDOR/BAC surface)",
            target)
            .with_evidence(&format!("{} auth-protected paths returned 200: {:?}",
                accessible.len(),
                accessible.iter().map(|(p, _s, _l)| p).collect::<Vec<_>>()))
            .with_confidence(75));
    }

    out.push(Finding::new(Severity::Info, "AUTH-AWARE",
        &format!("Auth-aware scan: probed {} paths, {} accessible",
            limit, accessible.len()),
        target)
        .with_confidence(100));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_count() {
        assert!(AUTH_PROTECTED_PATHS.len() >= 25);
    }

    #[test]
    fn paths_have_api_prefix() {
        // Most should start with /api or /admin
        let api_count = AUTH_PROTECTED_PATHS.iter().filter(|p| p.starts_with("/api") || p.starts_with("/admin")).count();
        assert!(api_count >= 20);
    }
}