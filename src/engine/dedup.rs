//! Smart Deduplication Engine
//!
//! Groups similar findings to reduce noise in scan reports.
//! Unlike the historical tracker (which dedups ACROSS scans), this
//! dedups similar findings WITHIN a single scan.
//!
//! Strategies:
//! - Exact: same category + target + evidence
//! - Path-level: same category + same path (different params)
//! - Pattern-based: similar regex signature (e.g. all "missing X-Frame-Options")
//! - Severity-aware: keep highest severity when collapsing
//!
//! Use case:
//!     let mut dedup = SmartDedup::new();
//!     let grouped = dedup.group(findings);
//!     // Returns: Vec<DedupGroup> where each group has 1 representative + count

use crate::types::{Finding, Severity};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DedupGroup {
    pub representative: Finding,
    pub duplicates: Vec<Finding>,
    pub similarity_score: f32,
    pub group_strategy: DedupStrategy,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DedupStrategy {
    Exact,
    PathLevel,
    Pattern,
    Category,
}

pub struct SmartDedup {
    pub threshold: f32,
}

impl SmartDedup {
    pub fn new() -> Self {
        Self { threshold: 0.65 }
    }

    pub fn with_threshold(threshold: f32) -> Self {
        Self { threshold }
    }

    /// Group similar findings. Returns a vec where each item is one group.
    pub fn group(&self, findings: &[Finding]) -> Vec<DedupGroup> {
        if findings.is_empty() {
            return vec![];
        }

        let mut groups: Vec<DedupGroup> = vec![];

        for finding in findings {
            // Try to merge with existing group
            let mut merged = false;
            for group in groups.iter_mut() {
                let sim = self.similarity(&group.representative, finding);
                if sim >= self.threshold {
                    group.duplicates.push(finding.clone());
                    group.similarity_score =
                        (group.similarity_score + sim) / 2.0;
                    // Keep highest severity
                    if severity_rank(&finding.severity) > severity_rank(&group.representative.severity)
                    {
                        group.representative.severity = finding.severity.clone();
                    }
                    merged = true;
                    break;
                }
            }

            if !merged {
                let strategy = self.classify(findings, finding);
                groups.push(DedupGroup {
                    representative: finding.clone(),
                    duplicates: vec![],
                    similarity_score: 1.0,
                    group_strategy: strategy,
                });
            }
        }

        groups
    }

    /// Compute similarity score between two findings (0.0 - 1.0).
    pub fn similarity(&self, a: &Finding, b: &Finding) -> f32 {
        let mut score = 0.0;
        let mut weight = 0.0;

        // Category match (high weight)
        if a.category == b.category {
            score += 0.4;
        }
        weight += 0.4;

        // Target path match (medium weight)
        let path_a = path_only(&a.target);
        let path_b = path_only(&b.target);
        if path_a == path_b {
            score += 0.3;
        }
        weight += 0.3;

        // Evidence similarity (lower weight, fuzzy)
        if let (Some(eva), Some(evb)) = (&a.evidence, &b.evidence) {
            let ev_sim = jaccard_similarity(eva, evb);
            score += 0.2 * ev_sim;
        }
        weight += 0.2;

        // Severity match (small weight)
        if a.severity == b.severity {
            score += 0.1;
        }
        weight += 0.1;

        score / weight
    }

    fn classify(&self, _findings: &[Finding], _finding: &Finding) -> DedupStrategy {
        // For now, default to PathLevel (most common case)
        DedupStrategy::PathLevel
    }

    /// Get statistics about deduplication.
    pub fn stats(groups: &[DedupGroup]) -> DedupStats {
        let total_original: usize = groups
            .iter()
            .map(|g| 1 + g.duplicates.len())
            .sum();
        let after_dedup = groups.len();
        let removed = total_original.saturating_sub(after_dedup);
        let reduction_pct = if total_original > 0 {
            (removed as f32 / total_original as f32) * 100.0
        } else {
            0.0
        };

        let by_strategy: HashMap<String, usize> = {
            let mut map = HashMap::new();
            for g in groups {
                let key = format!("{:?}", g.group_strategy);
                *map.entry(key).or_insert(0) += 1;
            }
            map
        };

        DedupStats {
            total_original,
            after_dedup,
            removed,
            reduction_pct,
            by_strategy,
        }
    }
}

impl Default for SmartDedup {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct DedupStats {
    pub total_original: usize,
    pub after_dedup: usize,
    pub removed: usize,
    pub reduction_pct: f32,
    pub by_strategy: HashMap<String, usize>,
}

fn path_only(url: &str) -> String {
    url.split('?').next().unwrap_or(url).to_string()
}

fn severity_rank(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn jaccard_similarity(a: &str, b: &str) -> f32 {
    let set_a: std::collections::HashSet<&str> = a.split_whitespace().collect();
    let set_b: std::collections::HashSet<&str> = b.split_whitespace().collect();
    if set_a.is_empty() && set_b.is_empty() {
        return 1.0;
    }
    let intersection = set_a.intersection(&set_b).count() as f32;
    let union = set_a.union(&set_b).count() as f32;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(cat: &str, target: &str, sev: Severity, evidence: Option<&str>) -> Finding {
        let mut f = Finding::new(sev, cat, cat, target);
        f.evidence = evidence.map(|s| s.to_string());
        f
    }

    #[test]
    fn similar_xss_same_path_dedup() {
        let dedup = SmartDedup::new();
        let findings = vec![
            mk("XSS", "https://a.com/p", Severity::High, Some("payload1")),
            mk("XSS", "https://a.com/p", Severity::High, Some("payload2")),
            mk("XSS", "https://a.com/p", Severity::High, Some("payload3")),
        ];
        let groups = dedup.group(&findings);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].duplicates.len(), 2);
    }

    #[test]
    fn different_categories_not_deduped() {
        let dedup = SmartDedup::new();
        let findings = vec![
            mk("XSS", "https://a.com/p", Severity::High, None),
            mk("SQLi", "https://a.com/p", Severity::Critical, None),
        ];
        let groups = dedup.group(&findings);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn different_paths_not_deduped() {
        let dedup = SmartDedup::new();
        let findings = vec![
            mk("XSS", "https://a.com/p1", Severity::High, None),
            mk("XSS", "https://a.com/p2", Severity::High, None),
        ];
        let groups = dedup.group(&findings);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn keeps_highest_severity() {
        let dedup = SmartDedup::new();
        let findings = vec![
            mk("XSS", "https://a.com/p", Severity::Low, None),
            mk("XSS", "https://a.com/p", Severity::Critical, None),
            mk("XSS", "https://a.com/p", Severity::High, None),
        ];
        let groups = dedup.group(&findings);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].representative.severity, Severity::Critical);
    }

    #[test]
    fn empty_findings() {
        let dedup = SmartDedup::new();
        let groups = dedup.group(&[]);
        assert!(groups.is_empty());
    }

    #[test]
    fn stats_calculation() {
        let dedup = SmartDedup::new();
        let findings = vec![
            mk("XSS", "https://a.com/p", Severity::High, None),
            mk("XSS", "https://a.com/p", Severity::High, None),
            mk("XSS", "https://a.com/p", Severity::High, None),
            mk("SQLi", "https://a.com/q", Severity::Critical, None),
        ];
        let groups = dedup.group(&findings);
        let stats = SmartDedup::stats(&groups);
        assert_eq!(stats.total_original, 4);
        assert_eq!(stats.after_dedup, 2);
        assert_eq!(stats.removed, 2);
        assert!(stats.reduction_pct > 0.0);
    }

    #[test]
    fn jaccard_basic() {
        let sim = jaccard_similarity("hello world", "hello rust");
        assert!(sim > 0.0 && sim < 1.0);
    }
}
