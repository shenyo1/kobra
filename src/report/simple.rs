//! Simple Output — Bahasa Indonesia, easy-to-read format for beginners.
//! Activated via --simple flag.

use crate::types::{Finding, Severity};
use std::collections::HashMap;

/// Print findings in simple Bahasa Indonesia format
pub fn print_simple(findings: &[Finding]) {
    let sev_counts: HashMap<&str, usize> = findings.iter().fold(HashMap::new(), |mut acc, f| {
        *acc.entry(f.severity.as_str()).or_insert(0) += 1;
        acc
    });

    let critical = sev_counts.get("CRITICAL").copied().unwrap_or(0);
    let high = sev_counts.get("HIGH").copied().unwrap_or(0);
    let medium = sev_counts.get("MEDIUM").copied().unwrap_or(0);
    let low = sev_counts.get("LOW").copied().unwrap_or(0);
    let info = sev_counts.get("INFO").copied().unwrap_or(0);
    let total = findings.len();

    println!("\n{}", "=".repeat(55));
    println!(" 🐍 KOBRA — HASIL SCAN");
    println!("{}", "=".repeat(55));

    if total == 0 {
        println!(" ✅ Tidak ditemukan celah keamanan.");
        println!();
        return;
    }

    // Summary
    println!();
    println!(" 📊 RINGKASAN:");
    if critical > 0 { println!("    🔴 KRITIS:   {} celah — SANGAT BERBAHAYA!", critical); }
    if high > 0 { println!("    🟠 TINGGI:   {} celah — Berbahaya", high); }
    if medium > 0 { println!("    🟡 SEDANG:   {} celah — Perlu diperhatikan", medium); }
    if low > 0 { println!("    🔵 RENDAH:   {} celah — Informasi tambahan", low); }
    if info > 0 { println!("    ⚪ INFO:     {} celah — Catatan", info); }
    println!("    {} Total celah ditemukan", total);
    println!();

    // Urutkan: Critical → High → Medium → Low → Info
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by_key(|f| match f.severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    });

    println!(" 📋 DAFTAR CELAH:");
    println!("{}", "-".repeat(55));

    for (i, f) in sorted.iter().enumerate() {
        let icon = match f.severity {
            Severity::Critical => "🔴",
            Severity::High => "🟠",
            Severity::Medium => "🟡",
            Severity::Low => "🔵",
            Severity::Info => "⚪",
        };

        let sev_name = match f.severity {
            Severity::Critical => "KRITIS",
            Severity::High => "TINGGI",
            Severity::Medium => "SEDANG",
            Severity::Low => "RENDAH",
            Severity::Info => "INFO",
        };

        println!("\n {} [{}] {}", icon, sev_name, f.title);
        println!("    📍 Target: {}", f.target);
        println!("    🏷️  Kategori: {}", f.category);

        if let Some(p) = &f.param {
            println!("    📎 Parameter: {}", p);
        }
        if let Some(p) = &f.payload {
            println!("    🔧 Payload: {}", truncate(p, 80));
        }
        if let Some(e) = &f.evidence {
            println!("    📋 Bukti: {}", truncate(e, 80));
        }
        if let Some(n) = &f.note {
            println!("    💡 Catatan: {}", truncate(n, 80));
        }
        println!("    🎯 Keyakinan: {}%", f.confidence);
    }

    println!();
    println!("{}", "=".repeat(55));
    println!(" 💡 TIPS:");
    println!("    • Celah KRITIS/TINGGI harus segera diperbaiki");
    println!("    • Gunakan --html report.html untuk laporan HTML");
    println!("    • Gunakan --md report.md untuk laporan Markdown");
    println!("    • Gunakan -o hasil.json untuk menyimpan hasil");
    println!("{}", "=".repeat(55));
    println!();
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}
