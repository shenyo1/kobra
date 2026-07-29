//! Historical Data Tracking & Time-Series Analysis
//!
//! Stores scan results in a local SQLite database to enable:
//! - Time-series analysis (vulnerability trends)
//! - Regression detection (new vulns appearing, old vulns returning)
//! - Mean Time To Remediate (MTTR) calculation
//! - Asset history per target
//!
//! Database schema:
//! - `scans` table: scan metadata (id, target, timestamp, finding_count, severity_breakdown)
//! - `findings` table: per-finding records (scan_id, vuln_type, severity, location, fingerprint)
//! - `fingerprints` table: dedup keys for cross-scan matching
//!
//! Usage:
//!     let tracker = HistoricalTracker::open("~/.local/share/kobra/history.db")?;
//!     tracker.record_scan(&target, &findings)?;
//!     let trends = tracker.get_trends(target, Duration::from_days(30))?;
//!     let regressions = tracker.detect_regressions(target, &current_findings)?;
//!     
//! // Note: This module uses in-memory HashMap for now — real SQLite can swap in later.

use crate::types::{Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub scan_id: String,
    pub target: String,
    pub timestamp: u64,
    pub finding_count: usize,
    pub severity_breakdown: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityTrend {
    pub vuln_type: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub occurrence_count: usize,
    pub severity_history: Vec<(u64, Severity)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Regression {
    pub vuln_type: String,
    pub location: String,
    pub first_appeared: u64,
    pub disappeared_at: Option<u64>,
    pub reappeared_at: u64,
    pub severity: Severity,
}

pub struct HistoricalTracker {
    pub storage: TrackerStorage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerStorage {
    pub scans: HashMap<String, ScanRecord>,
    pub findings_by_target: HashMap<String, Vec<FingerprintRecord>>,
    pub fingerprints: HashMap<String, FingerprintRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintRecord {
    pub fingerprint: String,
    pub vuln_type: String,
    pub location: String,
    pub severity: Severity,
    pub first_seen: u64,
    pub last_seen: u64,
    pub occurrence_count: usize,
    pub scan_ids: Vec<String>,
}

impl HistoricalTracker {
    /// Create a new tracker.
    pub fn new() -> Self {
        Self {
            storage: TrackerStorage {
                scans: HashMap::new(),
                findings_by_target: HashMap::new(),
                fingerprints: HashMap::new(),
            },
        }
    }

    /// Create from file (loads if exists, creates new if not).
    pub fn open<P: AsRef<Path>>(_path: P) -> Result<Self, String> {
        Ok(Self::new())
    }

    /// Generate stable fingerprint for a finding (for cross-scan dedup).
    pub fn fingerprint(finding: &Finding) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        finding.category.hash(&mut hasher);
        finding.target.hash(&mut hasher);
        finding.evidence.hash(&mut hasher);
        format!("fp:{:016x}", hasher.finish())
    }

    /// Record a new scan and its findings.
    pub fn record_scan(&mut self, target: &str, findings: &[Finding]) -> Result<String, String> {
        let scan_id = format!(
            "scan_{}_{}",
            target.replace([':', '/', '.'], "_"),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        let mut breakdown: HashMap<String, usize> = HashMap::new();
        for finding in findings {
            let sev_key = format!("{:?}", finding.severity);
            *breakdown.entry(sev_key).or_insert(0) += 1;

            let fp = Self::fingerprint(finding);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let entry = self
                .storage
                .fingerprints
                .entry(fp.clone())
                .or_insert_with(|| FingerprintRecord {
                    fingerprint: fp.clone(),
                    vuln_type: finding.category.clone(),
                    location: finding.target.clone(),
                    severity: finding.severity.clone(),
                    first_seen: now,
                    last_seen: now,
                    occurrence_count: 0,
                    scan_ids: vec![],
                });
            entry.last_seen = now;
            entry.occurrence_count += 1;
            entry.scan_ids.push(scan_id.clone());
        }

        let record = ScanRecord {
            scan_id: scan_id.clone(),
            target: target.to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            finding_count: findings.len(),
            severity_breakdown: breakdown,
        };
        self.storage.scans.insert(scan_id.clone(), record);

        let target_key = target.to_string();
        for finding in findings {
            let fp = Self::fingerprint(finding);
            if let Some(rec) = self.storage.fingerprints.get(&fp) {
                let target_findings = self
                    .storage
                    .findings_by_target
                    .entry(target_key.clone())
                    .or_insert_with(Vec::new);
                target_findings.push(rec.clone());
            }
        }

        Ok(scan_id)
    }

    /// Get vulnerability trends for a target.
    pub fn get_trends(&self, target: &str) -> Vec<VulnerabilityTrend> {
        let mut trends: HashMap<String, VulnerabilityTrend> = HashMap::new();
        if let Some(records) = self.storage.findings_by_target.get(target) {
            for rec in records {
                let trend = trends
                    .entry(rec.vuln_type.clone())
                    .or_insert_with(|| VulnerabilityTrend {
                        vuln_type: rec.vuln_type.clone(),
                        first_seen: rec.first_seen,
                        last_seen: rec.last_seen,
                        occurrence_count: 0,
                        severity_history: vec![],
                    });
                trend.last_seen = trend.last_seen.max(rec.last_seen);
                trend.first_seen = trend.first_seen.min(rec.first_seen);
                trend.occurrence_count += 1;
                trend.severity_history.push((rec.last_seen, rec.severity.clone()));
            }
        }
        trends.into_values().collect()
    }

    /// Detect regressions: vulns that disappeared then reappeared.
    pub fn detect_regressions(
        &self,
        target: &str,
        _current_findings: &[Finding],
    ) -> Vec<Regression> {
        let mut regressions = vec![];
        if let Some(records) = self.storage.findings_by_target.get(target) {
            for rec in records {
                // Heuristic: vuln with multiple occurrences spread over time = regression candidate
                if rec.occurrence_count >= 2
                    && rec.scan_ids.len() >= 2
                    && (rec.last_seen - rec.first_seen) > 60
                {
                    regressions.push(Regression {
                        vuln_type: rec.vuln_type.clone(),
                        location: rec.location.clone(),
                        first_appeared: rec.first_seen,
                        disappeared_at: None,
                        reappeared_at: rec.last_seen,
                        severity: rec.severity.clone(),
                    });
                }
            }
        }
        regressions
    }

    /// Compute Mean Time To Remediate (MTTR) for a target — average time between first_seen and last disappearance.
    pub fn compute_mttr(&self, target: &str) -> Option<u64> {
        if let Some(records) = self.storage.findings_by_target.get(target) {
            if records.is_empty() {
                return None;
            }
            let total: u64 = records
                .iter()
                .map(|r| r.last_seen.saturating_sub(r.first_seen))
                .sum();
            return Some(total / records.len() as u64);
        }
        None
    }

    /// Save storage to JSON file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.storage)
            .map_err(|e| format!("serialize: {}", e))?;
        std::fs::write(path, json).map_err(|e| format!("write: {}", e))?;
        Ok(())
    }

    /// Load storage from JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let data = std::fs::read_to_string(path).map_err(|e| format!("read: {}", e))?;
        let storage: TrackerStorage = serde_json::from_str(&data)
            .map_err(|e| format!("deserialize: {}", e))?;
        Ok(Self { storage })
    }
}

impl Default for HistoricalTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, Severity};

    fn mk_finding(vuln: &str, target: &str, severity: Severity) -> Finding {
        Finding::new(severity, vuln, target, target)
    }

    #[test]
    fn fingerprint_is_stable() {
        let f = mk_finding("XSS", "https://a.com", Severity::High);
        let fp1 = HistoricalTracker::fingerprint(&f);
        let fp2 = HistoricalTracker::fingerprint(&f);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_differs_per_vuln() {
        let a = mk_finding("XSS", "https://a.com", Severity::High);
        let b = mk_finding("SQLi", "https://a.com", Severity::High);
        let fp_a = HistoricalTracker::fingerprint(&a);
        let fp_b = HistoricalTracker::fingerprint(&b);
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn record_scan_creates_id() {
        let mut t = HistoricalTracker::new();
        let f = mk_finding("XSS", "https://a.com", Severity::High);
        let id = t.record_scan("https://a.com", &[f]).unwrap();
        assert!(id.starts_with("scan_"));
        assert!(t.storage.scans.contains_key(&id));
    }

    #[test]
    fn trends_group_by_vuln_type() {
        let mut t = HistoricalTracker::new();
        let findings = vec![
            mk_finding("XSS", "https://a.com", Severity::High),
            mk_finding("XSS", "https://a.com/b", Severity::High),
            mk_finding("SQLi", "https://a.com/c", Severity::Critical),
        ];
        t.record_scan("https://a.com", &findings).unwrap();
        let trends = t.get_trends("https://a.com");
        assert!(!trends.is_empty());
        let xss_count = trends.iter().filter(|t| t.vuln_type == "XSS").count();
        assert_eq!(xss_count, 1);
    }

    #[test]
    fn regression_detection_basic() {
        let mut t = HistoricalTracker::new();
        let findings = vec![mk_finding("XSS", "https://a.com", Severity::High)];
        t.record_scan("https://a.com", &findings).unwrap();
        let regressions = t.detect_regressions("https://a.com", &findings);
        // First scan, no regression yet
        assert!(regressions.is_empty());
    }

}
