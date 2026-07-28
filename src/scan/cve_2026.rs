//! CVE-specific detection modules — 2026 active exploits.
//! Detects header-based / endpoint-based indicators of vulnerable versions.

use crate::http::HttpClient;
use crate::types::{Finding, Mode, Severity};
use std::collections::HashMap;

/// CVE database — keep focused on high-impact 2024-2026 vulns.
#[derive(Debug, Clone, Copy)]
pub struct CveRule {
    pub cve_id: &'static str,
    pub name: &'static str,
    pub cwe: &'static str,
    pub cvss: f32,
    pub detect: CveDetect,
}

#[derive(Debug, Clone, Copy)]
pub enum CveDetect {
    /// Probe endpoint, flag if status + body match.
    Endpoint { path: &'static str, body_marker: &'static str, expect_status: u16 },
    /// Inspect response header for version string.
    HeaderVersion { header: &'static str, vulnerable_versions: &'static [&'static str] },
    /// Send specific payload, flag if response indicates execution.
    HeaderPayload { request_header: (&'static str, &'static str), response_marker: &'static str },
}

pub const CVE_RULES: &[CveRule] = &[
    CveRule {
        cve_id: "CVE-2021-44228",
        name: "Log4Shell (Log4j RCE)",
        cwe: "CWE-502",
        cvss: 10.0,
        detect: CveDetect::HeaderPayload {
            request_header: ("User-Agent", "${jndi:ldap://k0bra-cve-2021-44228.test/a}"),
            response_marker: "k0bra-cve-2021-44228",
        },
    },
    CveRule {
        cve_id: "CVE-2022-22965",
        name: "Spring4Shell",
        cwe: "CWE-94",
        cvss: 9.8,
        detect: CveDetect::Endpoint {
            path: "/?class.module.classLoader.DefaultAssertionStatus=true",
            body_marker: "WebApplicationContext",
            expect_status: 500,
        },
    },
    CveRule {
        cve_id: "CVE-2023-22515",
        name: "Confluence privilege escalation",
        cwe: "CWE-863",
        cvss: 9.8,
        detect: CveDetect::Endpoint {
            path: "/setup/index.action",
            body_marker: "Setup",
            expect_status: 200,
        },
    },
    CveRule {
        cve_id: "CVE-2024-21762",
        name: "Fortinet FortiOS SSL VPN",
        cwe: "CWE-787",
        cvss: 9.6,
        detect: CveDetect::Endpoint {
            path: "/remote/fgt_lang?lang=/../../../../etc/passwd",
            body_marker: "root:",
            expect_status: 200,
        },
    },
    CveRule {
        cve_id: "CVE-2024-1709",
        name: "ConnectWise ScreenConnect auth bypass",
        cwe: "CWE-288",
        cvss: 10.0,
        detect: CveDetect::Endpoint {
            path: "/SetupWizard/SetupWizard.aspx",
            body_marker: "SetupWizard",
            expect_status: 200,
        },
    },
    CveRule {
        cve_id: "CVE-2025-64709",
        name: "AWS IMDSv2 bypass via header injection",
        cwe: "CWE-918",
        cvss: 8.6,
        detect: CveDetect::HeaderPayload {
            request_header: ("X-aws-ec2-metadata-token-ttl-seconds", "99999"),
            response_marker: "169.254.169.254",
        },
    },
    CveRule {
        cve_id: "CVE-2026-6338",
        name: "Kong HTTP request smuggling",
        cwe: "CWE-444",
        cvss: 9.1,
        detect: CveDetect::HeaderVersion {
            header: "X-Kong-Upstream-Latency",
            vulnerable_versions: &["*"],
        },
    },
    CveRule {
        cve_id: "CVE-2026-42208",
        name: "LiteLLM SQLi in Authorization",
        cwe: "CWE-89",
        cvss: 9.8,
        detect: CveDetect::Endpoint {
            path: "/v1/chat/completions",
            body_marker: "LiteLLM_VerificationToken",
            expect_status: 400,
        },
    },
    CveRule {
        cve_id: "CVE-2024-3094",
        name: "XZ Utils backdoor (supply chain)",
        cwe: "CWE-506",
        cvss: 10.0,
        detect: CveDetect::HeaderVersion {
            header: "Server",
            vulnerable_versions: &["OpenSSH 9.5p1", "OpenSSH 9.6p1", "OpenSSH 9.7p1"],
        },
    },
    CveRule {
        cve_id: "CVE-2023-50164",
        name: "Apache Struts file upload path traversal",
        cwe: "CWE-22",
        cvss: 9.8,
        detect: CveDetect::Endpoint {
            path: "/struts2-showcase/integration/saveGangster.action",
            body_marker: "Gangster",
            expect_status: 200,
        },
    },
];

pub async fn scan(http: &HttpClient, target: &str, mode: Mode) -> Vec<Finding> {
    let mut findings = Vec::new();
    if mode == Mode::Stealth {
        return findings;
    }
    for rule in CVE_RULES {
        match rule.detect {
            CveDetect::Endpoint { path, body_marker, expect_status } => {
                let url = format!("{}{}", normalize_base(target), path);
                if let Ok((st, _h, body, _f)) = http.get(&url).await {
                    if st == expect_status && body.contains(body_marker) {
                        findings.push(cve_finding(rule, url, body_marker));
                    }
                }
            }
            CveDetect::HeaderVersion { header, vulnerable_versions } => {
                if let Ok((_st, headers, _b, _f)) = http.get(target).await {
                    for v in vulnerable_versions {
                        if *v == "*" {
                            if headers.to_lowercase().contains(&header.to_lowercase()) {
                                findings.push(cve_finding(rule, target.to_string(), header));
                            }
                        } else if headers.contains(v) {
                            findings.push(cve_finding(rule, target.to_string(), v));
                        }
                    }
                }
            }
            CveDetect::HeaderPayload { request_header, response_marker } => {
                let mut h = HashMap::new();
                h.insert(request_header.0.to_string(), request_header.1.to_string());
                if let Ok((_st, _h, body, _f)) = http.fetch(target, reqwest::Method::GET, None, Some(h)).await {
                    if body.contains(response_marker) {
                        findings.push(cve_finding(rule, target.to_string(), response_marker));
                    }
                }
            }
        }
    }
    findings
}

fn cve_finding(rule: &CveRule, target: String, marker: &str) -> Finding {
    let sev = if rule.cvss >= 9.0 { Severity::Critical } else if rule.cvss >= 7.0 { Severity::High } else { Severity::Medium };
    Finding {
        severity: sev,
        category: "CVE".into(),
        title: format!("{} ({})", rule.name, rule.cve_id),
        target,
        param: None,
        payload: None,
        evidence: Some(format!("matched: {} | CVSS {:.1} | CWE {}", marker, rule.cvss, rule.cwe)),
        confidence: 80,
        note: Some(format!("Verify manually with authoritative PoC. Reference: NVD {}", rule.cve_id)),
        request: None,
        response: None,
    }
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
    fn cve_count() {
        assert!(CVE_RULES.len() >= 10);
    }
    #[test]
    fn log4shell_in_rules() {
        assert!(CVE_RULES.iter().any(|r| r.cve_id == "CVE-2021-44228"));
    }
    #[test]
    fn normalize_strips_query() {
        assert_eq!(normalize_base("https://x.com/a?b=1"), "https://x.com/a");
    }
    #[test]
    fn cve_finding_severity() {
        let rule = CveRule {
            cve_id: "TEST-1",
            name: "Test",
            cwe: "CWE-1",
            cvss: 9.5,
            detect: CveDetect::Endpoint { path: "/x", body_marker: "x", expect_status: 200 },
        };
        let f = cve_finding(&rule, "https://x.com/".into(), "x");
        assert_eq!(f.severity, Severity::Critical);
    }
}
