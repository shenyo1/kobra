//! Cross-Target Chain Detection — correlate findings ACROSS different
//! targets/subdomains to detect multi-step attack chains.
//! Example: XSS on subdomain A + shared cookie → ATO on domain B.

use crate::types::{Finding, Severity};
use std::collections::HashMap;

/// A cross-target attack chain
#[derive(Debug, Clone)]
pub struct CrossChain {
    pub name: String,
    pub severity: Severity,
    pub confidence: u8,
    pub description: String,
    pub steps: Vec<String>,
    pub targets: Vec<String>,
}

/// Detect cross-target chains from findings across multiple targets
pub fn detect_cross_chains(findings: &[Finding]) -> Vec<CrossChain> {
    let mut chains = Vec::new();

    // Group findings by target
    let mut by_target: HashMap<String, Vec<&Finding>> = HashMap::new();
    for f in findings {
        let domain = extract_domain(&f.target);
        by_target.entry(domain).or_default().push(f);
    }

    // Group by category across all targets
    let mut by_category: HashMap<String, Vec<&Finding>> = HashMap::new();
    for f in findings {
        by_category.entry(f.category.clone()).or_default().push(f);
    }

    // Chain 1: XSS on one subdomain + session/cookie finding on another → ATO
    let xss_targets: Vec<String> = by_category
        .get("XSS")
        .map(|fs| fs.iter().map(|f| extract_domain(&f.target)).collect())
        .unwrap_or_default();
    let auth_targets: Vec<String> = by_category
        .keys()
        .filter(|k| k.contains("AUTH") || k.contains("JWT") || k.contains("IDOR"))
        .flat_map(|k| by_category[k].iter().map(|f| extract_domain(&f.target)))
        .collect();

    for xt in &xss_targets {
        for at in &auth_targets {
            if xt != at && share_parent_domain(xt, at) {
                chains.push(CrossChain {
                    name: "Cross-Subdomain XSS → Account Takeover".to_string(),
                    severity: Severity::Critical,
                    confidence: 60,
                    description: format!(
                        "XSS on {} can steal cookies/session used by {} — potential ATO across subdomains",
                        xt, at
                    ),
                    steps: vec![
                        format!("XSS found on {}", xt),
                        format!("Auth/session endpoint on {}", at),
                        "Shared parent domain → cookies may be shared".to_string(),
                        "XSS can steal session → ATO on auth target".to_string(),
                    ],
                    targets: vec![xt.clone(), at.clone()],
                });
            }
        }
    }

    // Chain 2: SSRF on one target + internal service on another
    let ssrf_targets: Vec<String> = by_category
        .get("SSRF")
        .map(|fs| fs.iter().map(|f| extract_domain(&f.target)).collect())
        .unwrap_or_default();
    let internal_targets: Vec<String> = by_category
        .keys()
        .filter(|k| k.contains("INFO") || k.contains("TECH"))
        .flat_map(|k| by_category[k].iter().map(|f| extract_domain(&f.target)))
        .collect();

    for st in &ssrf_targets {
        for it in &internal_targets {
            if st != it {
                chains.push(CrossChain {
                    name: "SSRF → Internal Service Access".to_string(),
                    severity: Severity::High,
                    confidence: 50,
                    description: format!(
                        "SSRF on {} could reach internal services discovered on {}",
                        st, it
                    ),
                    steps: vec![
                        format!("SSRF found on {}", st),
                        format!("Internal/info endpoints on {}", it),
                        "SSRF can pivot to internal network".to_string(),
                    ],
                    targets: vec![st.clone(), it.clone()],
                });
            }
        }
    }

    // Chain 3: Info leak on one target + auth bypass on another
    let info_targets: Vec<String> = by_category
        .keys()
        .filter(|k| k.contains("INFO") || k.contains("TECH") || k.contains("FUZZ"))
        .flat_map(|k| by_category[k].iter().map(|f| extract_domain(&f.target)))
        .collect();
    let bypass_targets: Vec<String> = by_category
        .keys()
        .filter(|k| k.contains("WAF") || k.contains("AUTH"))
        .flat_map(|k| by_category[k].iter().map(|f| extract_domain(&f.target)))
        .collect();

    for it in &info_targets {
        for bt in &bypass_targets {
            if it != bt && share_parent_domain(it, bt) {
                chains.push(CrossChain {
                    name: "Info Leak → Auth Bypass Chain".to_string(),
                    severity: Severity::Medium,
                    confidence: 45,
                    description: format!(
                        "Info disclosure on {} may reveal credentials/tokens usable on {}",
                        it, bt
                    ),
                    steps: vec![
                        format!("Info leak on {}", it),
                        format!("Auth/WAF bypass on {}", bt),
                        "Leaked data may enable bypass".to_string(),
                    ],
                    targets: vec![it.clone(), bt.clone()],
                });
            }
        }
    }

    // Deduplicate chains by name+targets
    let mut seen = std::collections::HashSet::new();
    chains.retain(|c| {
        let key = format!("{}|{}", c.name, c.targets.join(","));
        seen.insert(key)
    });

    chains
}

/// Extract domain from URL (strip protocol, path, port)
fn extract_domain(url: &str) -> String {
    url.replace("https://", "")
        .replace("http://", "")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Check if two domains share a parent domain (e.g., a.example.com and b.example.com)
fn share_parent_domain(a: &str, b: &str) -> bool {
    let parts_a: Vec<&str> = a.split('.').collect();
    let parts_b: Vec<&str> = b.split('.').collect();
    if parts_a.len() < 2 || parts_b.len() < 2 {
        return false;
    }
    let parent_a = parts_a[parts_a.len() - 2..].join(".");
    let parent_b = parts_b[parts_b.len() - 2..].join(".");
    parent_a == parent_b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_domain_basic() {
        assert_eq!(extract_domain("https://api.example.com/path"), "api.example.com");
        assert_eq!(extract_domain("http://test.com:8080"), "test.com");
    }

    #[test]
    fn share_parent_true() {
        assert!(share_parent_domain("a.example.com", "b.example.com"));
        assert!(share_parent_domain("api.test.com", "www.test.com"));
    }

    #[test]
    fn share_parent_false() {
        assert!(!share_parent_domain("example.com", "other.com"));
        assert!(!share_parent_domain("a.example.com", "b.other.com"));
    }

    #[test]
    fn cross_chain_xss_auth() {
        let findings = vec![
            Finding::new(Severity::High, "XSS", "Reflected XSS", "https://sub1.example.com/search"),
            Finding::new(Severity::High, "AUTH", "Weak auth", "https://sub2.example.com/login"),
        ];
        let chains = detect_cross_chains(&findings);
        assert!(!chains.is_empty());
        assert!(chains[0].name.contains("XSS"));
    }

    #[test]
    fn no_cross_chain_same_target() {
        let findings = vec![
            Finding::new(Severity::High, "XSS", "XSS", "https://a.com/page"),
            Finding::new(Severity::High, "AUTH", "Auth", "https://a.com/login"),
        ];
        let chains = detect_cross_chains(&findings);
        // Same domain → no cross-target chain
        assert!(chains.is_empty());
    }
}
