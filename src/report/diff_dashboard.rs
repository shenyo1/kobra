//! Diff Dashboard — visual HTML diff between two scans.
//! Shows NEW findings (red), RESOLVED (green), UNCHANGED (gray).
//! Usage: `kobra diff baseline.json current.json -o diff.html`

use crate::engine::diff;
use crate::types::Finding;
#[cfg(test)]
use crate::types::Severity;
use std::fs;

/// Generate visual diff HTML report
pub fn render_diff(baseline: &[Finding], current: &[Finding], engagement: &str) -> String {
    let result = diff::diff_findings(current, baseline);

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str(&format!("<title>KOBRA Diff — {}</title>\n", engagement));
    html.push_str("<style>\n");
    html.push_str(DIFF_CSS);
    html.push_str("</style>\n</head>\n<body>\n");
    html.push_str(&format!(r#"<header><h1>🐍 KOBRA Diff Dashboard</h1><h2>{}</h2></header>"#, engagement));

    // Summary
    html.push_str(&format!(
        r#"<section class="summary">
            <div class="stat new"><span class="count">{}</span><span class="label">NEW</span></div>
            <div class="stat resolved"><span class="count">{}</span><span class="label">RESOLVED</span></div>
            <div class="stat unchanged"><span class="count">{}</span><span class="label">UNCHANGED</span></div>
        </section>"#,
        result.new_findings.len(),
        result.resolved.len(),
        result.unchanged.len()
    ));

    // NEW findings (red)
    if !result.new_findings.is_empty() {
        html.push_str(
            "<section><h2 class=\"section-new\">🆕 NEW FINDINGS (Regressions)</h2>",
        );
        for f in &result.new_findings {
            html.push_str(&finding_card(f, "new"));
        }
        html.push_str("</section>");
    }

    // RESOLVED findings (green)
    if !result.resolved.is_empty() {
        html.push_str(
            "<section><h2 class=\"section-resolved\">✅ RESOLVED FINDINGS</h2>",
        );
        for f in &result.resolved {
            html.push_str(&finding_card(f, "resolved"));
        }
        html.push_str("</section>");
    }

    // UNCHANGED findings (collapsed)
    if !result.unchanged.is_empty() {
        html.push_str(&format!(
            "<section><h2 class=\"section-unchanged\">📋 UNCHANGED ({} findings)</h2>",
            result.unchanged.len()
        ));
        html.push_str("<details><summary>Show all unchanged</summary><div class=\"unchanged-list\">");
        for f in result.unchanged.iter().take(50) {
            html.push_str(&finding_card(f, "unchanged"));
        }
        if result.unchanged.len() > 50 {
            html.push_str(&format!(
                "<p>... and {} more</p>",
                result.unchanged.len() - 50
            ));
        }
        html.push_str("</div></details></section>");
    }

    html.push_str("</body>\n</html>");
    html
}

fn finding_card(f: &Finding, css_class: &str) -> String {
    let mut html = String::new();
    html.push_str(&format!(
        r#"<article class="finding {css_class}">
            <div class="head">
                <span class="badge {sev}">{sev}</span>
                <span class="cat">{cat}</span>
                <h3>{title}</h3>
            </div>
            <div class="meta"><code>{target}</code></div>"#,
        css_class = css_class,
        sev = f.severity.as_str(),
        cat = f.category,
        title = html_escape(&f.title),
        target = html_escape(&f.target),
    ));

    if let Some(p) = &f.param {
        html.push_str(&format!("<div class=\"param\">📎 {}</div>", html_escape(p)));
    }
    if let Some(e) = &f.evidence {
        html.push_str(&format!(
            "<div class=\"evidence\">📋 {}</div>",
            html_escape(&truncate(e, 200))
        ));
    }
    if let Some(n) = &f.note {
        html.push_str(&format!("<div class=\"note\">💡 {}</div>", html_escape(n)));
    }
    html.push_str(&format!(
        "<div class=\"conf\">Confidence: {}%</div>",
        f.confidence
    ));
    html.push_str("</article>");
    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max])
    } else {
        s.to_string()
    }
}

pub fn write(baseline_path: &str, current_path: &str, engagement: &str, output: &str) -> std::io::Result<()> {
    let baseline = load(baseline_path);
    let current = load(current_path);
    let html = render_diff(&baseline, &current, engagement);
    fs::write(output, html)
}

fn load(path: &str) -> Vec<Finding> {
    let content = fs::read_to_string(path).unwrap_or_default();
    // KOBRA saves findings as JSON array
    serde_json::from_str(&content).unwrap_or_default()
}

const DIFF_CSS: &str = r#"
:root { --new:#f85149; --resolved:#3fb950; --unchanged:#8b949e; --bg:#0d1117; --card:#161b22; --border:#30363d; --fg:#e6edf3; }
* { box-sizing: border-box; }
body { margin:0; font:14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,sans-serif; background:var(--bg); color:var(--fg); }
header { padding:24px 32px; border-bottom:1px solid var(--border); background:linear-gradient(180deg,#1a1f2c 0%,#0d1117 100%); }
header h1 { margin:0 0 4px 0; font-size:24px; }
header h2 { margin:0; font-size:14px; color:var(--unchanged); font-weight:normal; }
.summary { display:flex; gap:12px; padding:24px 32px; flex-wrap:wrap; }
.stat { background:var(--card); border:1px solid var(--border); border-radius:6px; padding:12px 20px; min-width:100px; display:flex; flex-direction:column; align-items:center; }
.stat.new { border-left:4px solid var(--new); }
.stat.resolved { border-left:4px solid var(--resolved); }
.stat.unchanged { border-left:4px solid var(--unchanged); }
.stat .count { font-size:32px; font-weight:600; }
.stat.new .count { color:var(--new); }
.stat.resolved .count { color:var(--resolved); }
.stat.unchanged .count { color:var(--unchanged); }
.stat .label { font-size:11px; text-transform:uppercase; letter-spacing:0.5px; }
section { padding:16px 32px; }
section h2 { font-size:18px; margin:16px 0 12px 0; padding-bottom:8px; border-bottom:1px solid var(--border); }
.section-new { color:var(--new); }
.section-resolved { color:var(--resolved); }
.section-unchanged { color:var(--unchanged); }
.finding { background:var(--card); border:1px solid var(--border); border-left:4px solid; border-radius:6px; padding:12px 16px; margin-bottom:8px; }
.finding.new { border-left-color:var(--new); }
.finding.resolved { border-left-color:var(--resolved); opacity:0.6; }
.finding.unchanged { border-left-color:var(--unchanged); opacity:0.5; }
.finding .head { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:6px; }
.finding .head h3 { margin:0; font-size:15px; }
.badge { font-size:10px; padding:2px 8px; border-radius:12px; font-weight:600; }
.badge.Critical { background:#f8514922; color:#f85149; }
.badge.High { background:#ff7b7222; color:#ff7b72; }
.badge.Medium { background:#d2992222; color:#d29922; }
.badge.Low { background:#58a6ff22; color:#58a6ff; }
.badge.Info { background:#8b949e22; color:#8b949e; }
.cat { font-size:11px; color:var(--unchanged); font-family:monospace; }
.meta code { background:#1c2129; padding:2px 6px; border-radius:3px; word-break:break-all; font-size:12px; }
.param, .evidence, .note { font-size:12px; margin-top:6px; color:var(--unchanged); }
.conf { font-size:11px; color:var(--unchanged); margin-top:4px; }
details { margin-top:8px; }
details summary { cursor:pointer; color:var(--unchanged); padding:8px; }
.unchanged-list { max-height:600px; overflow-y:auto; padding:8px; background:#0d1117; border-radius:6px; }
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_diff_basic() {
        let baseline = vec![Finding::new(Severity::High, "XSS", "Old XSS", "https://a.com")];
        let current = vec![
            Finding::new(Severity::High, "XSS", "Old XSS", "https://a.com"),
            Finding::new(Severity::Critical, "SQLi", "New SQLi", "https://a.com"),
        ];
        let html = render_diff(&baseline, &current, "test");
        assert!(html.contains("NEW FINDINGS"));
        assert!(html.contains("New SQLi"));
        assert!(html.contains("RESOLVED"));
        assert!(html.contains("0")); // 0 resolved
    }

    #[test]
    fn render_diff_empty() {
        let html = render_diff(&[], &[], "empty");
        assert!(html.contains("🐍 KOBRA Diff Dashboard"));
        assert!(html.contains("0")); // summary counts
    }

    #[test]
    fn render_diff_resolved() {
        let baseline = vec![Finding::new(Severity::High, "XSS", "Old vuln", "https://a.com")];
        let current = vec![]; // vuln fixed
        let html = render_diff(&baseline, &current, "fixed");
        assert!(html.contains("RESOLVED"));
        assert!(html.contains("Old vuln"));
    }

    #[test]
    fn html_escape_works() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("&amp;"), "&amp;amp;");
    }

    #[test]
    fn truncate_short() {
        assert_eq!(truncate("short", 100), "short");
    }

    #[test]
    fn truncate_long() {
        let long = "a".repeat(200);
        let t = truncate(&long, 50);
        assert!(t.len() <= 53);
        assert!(t.ends_with("..."));
    }
}
