//! Multi-language Reports (i18n)
//!
//! Translations for findings descriptions and report sections.
//! Supports: English (default), Indonesian, Japanese, Chinese.
//!
//! Usage:
//!     let report = I18nReport::generate(&findings, Language::Indonesian);
//!     println!("{}", report);

use crate::types::{Finding, Severity};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    English,
    Indonesian,
    Japanese,
    Chinese,
}

impl Language {
    pub fn code(self) -> &'static str {
        match self {
            Language::English => "en",
            Language::Indonesian => "id",
            Language::Japanese => "ja",
            Language::Chinese => "zh",
        }
    }

    pub fn native_name(self) -> &'static str {
        match self {
            Language::English => "English",
            Language::Indonesian => "Bahasa Indonesia",
            Language::Japanese => "日本語",
            Language::Chinese => "中文",
        }
    }
}

pub struct I18nReport {
    pub language: Language,
    pub translations: HashMap<String, String>,
}

impl I18nReport {
    pub fn new(language: Language) -> Self {
        let mut translations = HashMap::new();

        match language {
            Language::English => {
                translations.insert("title".into(), "Security Scan Report".into());
                translations.insert("summary".into(), "Executive Summary".into());
                translations.insert("findings".into(), "Findings".into());
                translations.insert("severity".into(), "Severity".into());
                translations.insert("critical".into(), "Critical".into());
                translations.insert("high".into(), "High".into());
                translations.insert("medium".into(), "Medium".into());
                translations.insert("low".into(), "Low".into());
                translations.insert("info".into(), "Informational".into());
                translations.insert("total".into(), "Total Findings".into());
                translations.insert("recommendation".into(), "Recommendation".into());
            }
            Language::Indonesian => {
                translations.insert("title".into(), "Laporan Pemindaian Keamanan".into());
                translations.insert("summary".into(), "Ringkasan Eksekutif".into());
                translations.insert("findings".into(), "Temuan".into());
                translations.insert("severity".into(), "Tingkat Keparahan".into());
                translations.insert("critical".into(), "Kritis".into());
                translations.insert("high".into(), "Tinggi".into());
                translations.insert("medium".into(), "Sedang".into());
                translations.insert("low".into(), "Rendah".into());
                translations.insert("info".into(), "Informasi".into());
                translations.insert("total".into(), "Total Temuan".into());
                translations.insert(
                    "recommendation".into(),
                    "Rekomendasi".into(),
                );
            }
            Language::Japanese => {
                translations.insert("title".into(), "セキュリティスキャンレポート".into());
                translations.insert("summary".into(), "エグゼクティブサマリー".into());
                translations.insert("findings".into(), "検出事項".into());
                translations.insert("severity".into(), "重大度".into());
                translations.insert("critical".into(), "緊急".into());
                translations.insert("high".into(), "高".into());
                translations.insert("medium".into(), "中".into());
                translations.insert("low".into(), "低".into());
                translations.insert("info".into(), "情報".into());
                translations.insert("total".into(), "検出総数".into());
                translations.insert(
                    "recommendation".into(),
                    "推奨事項".into(),
                );
            }
            Language::Chinese => {
                translations.insert("title".into(), "安全扫描报告".into());
                translations.insert("summary".into(), "执行摘要".into());
                translations.insert("findings".into(), "发现".into());
                translations.insert("severity".into(), "严重程度".into());
                translations.insert("critical".into(), "严重".into());
                translations.insert("high".into(), "高".into());
                translations.insert("medium".into(), "中".into());
                translations.insert("low".into(), "低".into());
                translations.insert("info".into(), "信息".into());
                translations.insert("total".into(), "发现总数".into());
                translations.insert(
                    "recommendation".into(),
                    "建议".into(),
                );
            }
        }

        Self {
            language,
            translations,
        }
    }

    pub fn t(&self, key: &str) -> String {
        self.translations
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_string())
    }

    pub fn translate_severity(&self, sev: &Severity) -> String {
        let key = match sev {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        };
        self.t(key)
    }

    /// Generate full report in target language.
    pub fn generate(&self, findings: &[Finding], target: &str) -> String {
        let mut out = String::new();
        out.push_str(&format!("# {}\n\n", self.t("title")));
        out.push_str(&format!("**Target**: `{}`\n\n", target));

        out.push_str(&format!("## {}\n\n", self.t("summary")));
        out.push_str(&format!("**{}**: {}\n\n",
            self.t("total"),
            findings.len()
        ));

        // Severity breakdown
        let mut by_sev: HashMap<String, usize> = HashMap::new();
        for f in findings {
            let sev = self.translate_severity(&f.severity);
            *by_sev.entry(sev).or_insert(0) += 1;
        }
        for (sev, count) in by_sev.iter() {
            out.push_str(&format!("- **{}**: {}\n", sev, count));
        }
        out.push('\n');

        // Findings list
        out.push_str(&format!("## {}\n\n", self.t("findings")));
        for (i, f) in findings.iter().enumerate() {
            let sev_label = self.translate_severity(&f.severity);
            out.push_str(&format!(
                "### {}. [{}] {}\n",
                i + 1,
                sev_label,
                f.title
            ));
            out.push_str(&format!("- **{}**: {}\n", self.t("severity"), sev_label));
            out.push_str(&format!("- **Category**: {}\n", f.category));
            out.push_str(&format!("- **Target**: `{}`\n", f.target));
            out.push_str(&format!("- **Confidence**: {}%\n", f.confidence));
            if let Some(ev) = &f.evidence {
                out.push_str(&format!(
                    "- **Evidence**:\n  ```\n  {}\n  ```\n",
                    ev.replace('\n', "\n  ")
                ));
            }
            out.push('\n');
        }

        // Recommendations
        out.push_str(&format!("## {}\n\n", self.t("recommendation")));
        match self.language {
            Language::English => out.push_str(
                "- Patch all Critical and High findings within 7 days.\n\
                 - Validate Medium findings with manual testing.\n\
                 - Add automated scanning to CI/CD pipeline.\n",
            ),
            Language::Indonesian => out.push_str(
                "- Perbaiki semua temuan Kritis dan Tinggi dalam 7 hari.\n\
                 - Validasi temuan Sedang dengan pengujian manual.\n\
                 - Tambahkan pemindaian otomatis ke pipeline CI/CD.\n",
            ),
            Language::Japanese => out.push_str(
                "- 緊急および高の検出事項は7日以内に対応してください。\n\
                 - 中の検出事項は手動テストで検証してください。\n\
                 - CI/CDパイプラインに自動スキャンを追加してください。\n",
            ),
            Language::Chinese => out.push_str(
                "- 在7天内修复所有严重和高危问题。\n\
                 - 用手动测试验证中危问题。\n\
                 - 将自动扫描添加到CI/CD流水线。\n",
            ),
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(cat: &str, target: &str, sev: Severity) -> Finding {
        let mut f = Finding::new(sev, cat, cat, target);
        f.evidence = Some("test evidence".to_string());
        f.confidence = 90;
        f
    }

    #[test]
    fn language_codes() {
        assert_eq!(Language::English.code(), "en");
        assert_eq!(Language::Indonesian.code(), "id");
        assert_eq!(Language::Japanese.code(), "ja");
        assert_eq!(Language::Chinese.code(), "zh");
    }

    #[test]
    fn english_title() {
        let i18n = I18nReport::new(Language::English);
        assert_eq!(i18n.t("title"), "Security Scan Report");
    }

    #[test]
    fn indonesian_title() {
        let i18n = I18nReport::new(Language::Indonesian);
        assert_eq!(i18n.t("title"), "Laporan Pemindaian Keamanan");
    }

    #[test]
    fn japanese_title() {
        let i18n = I18nReport::new(Language::Japanese);
        assert_eq!(i18n.t("title"), "セキュリティスキャンレポート");
    }

    #[test]
    fn chinese_title() {
        let i18n = I18nReport::new(Language::Chinese);
        assert_eq!(i18n.t("title"), "安全扫描报告");
    }

    #[test]
    fn severity_translation() {
        let i18n_en = I18nReport::new(Language::English);
        let i18n_id = I18nReport::new(Language::Indonesian);
        assert_eq!(i18n_en.translate_severity(&Severity::Critical), "Critical");
        assert_eq!(i18n_id.translate_severity(&Severity::Critical), "Kritis");
    }

    #[test]
    fn generate_full_report_indonesian() {
        let i18n = I18nReport::new(Language::Indonesian);
        let findings = vec![
            mk("XSS", "https://a.com", Severity::High),
            mk("SQLi", "https://a.com", Severity::Critical),
        ];
        let report = i18n.generate(&findings, "https://a.com");
        assert!(report.contains("Laporan Pemindaian Keamanan"));
        assert!(report.contains("Ringkasan Eksekutif"));
        assert!(report.contains("Kritis"));
        assert!(report.contains("Tinggi"));
        assert!(report.contains("Rekomendasi"));
    }

    #[test]
    fn fallback_to_key_when_missing() {
        let i18n = I18nReport::new(Language::English);
        assert_eq!(i18n.t("nonexistent_key"), "nonexistent_key");
    }

    #[test]
    fn native_language_names() {
        assert_eq!(Language::English.native_name(), "English");
        assert_eq!(Language::Indonesian.native_name(), "Bahasa Indonesia");
        assert_eq!(Language::Japanese.native_name(), "日本語");
        assert_eq!(Language::Chinese.native_name(), "中文");
    }
}
