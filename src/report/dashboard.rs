//! HTML Dashboard — single-file, self-contained report with live filter.
//! Renders findings in severity-sorted order with color coding.

use crate::types::{Finding, Severity};
use std::fs;

pub fn render(findings: &[Finding], engagement: &str) -> String {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by_key(|f| match f.severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    });

    let mut counts: std::collections::HashMap<&'static str, usize> = Default::default();
    for f in findings {
        *counts.entry(f.severity.as_str()).or_default() += 1;
    }

    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
    html.push_str("<meta charset=\"utf-8\">\n");
    html.push_str(&format!("<title>KOBRA — {}</title>\n", html_escape(engagement)));
    html.push_str("<style>\n");
    html.push_str(DASHBOARD_CSS);
    html.push_str("</style>\n</head>\n<body>\n");
    html.push_str(&format!("<header><h1>🐍 KOBRA</h1><h2>{}</h2></header>\n", html_escape(engagement)));

    html.push_str("<section class=\"summary\">\n");
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
        let n = counts.get(sev).copied().unwrap_or(0);
        let cls = sev.to_lowercase();
        html.push_str(&format!(
            "<div class=\"stat stat-{} {} zero-{}\"><span class=\"count\">{}</span><span class=\"label\">{}</span></div>\n",
            cls, cls, if n == 0 { "zero" } else { "" }, n, sev
        ));
    }
    html.push_str("</section>\n");

    html.push_str("<section class=\"filter\">\n");
    html.push_str("<input type=\"search\" id=\"q\" placeholder=\"filter…\" autofocus>\n");
    html.push_str("<select id=\"sev\">\n<option value=\"\">all</option>\n");
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] {
        html.push_str(&format!("<option>{}</option>\n", sev));
    }
    html.push_str("</select>\n</section>\n");

    html.push_str("<section class=\"findings\">\n");
    for (i, f) in sorted.iter().enumerate() {
        html.push_str(&format!(
            "<article class=\"finding sev-{}\" data-sev=\"{}\" data-text=\"{}\">\n",
            f.severity.as_str().to_lowercase(),
            f.severity.as_str(),
            html_escape(&format!("{} {} {}", f.title, f.category, f.target))
        ));
        html.push_str(&format!(
            "<div class=\"head\"><span class=\"badge {}\">{}</span> <span class=\"cat\">{}</span> <h3>{}</h3></div>\n",
            f.severity.as_str().to_lowercase(),
            f.severity.as_str(),
            f.category,
            html_escape(&f.title)
        ));
        html.push_str(&format!("<div class=\"meta\"><code>{}</code></div>\n", html_escape(&f.target)));
        if let Some(p) = &f.payload {
            html.push_str(&format!("<pre class=\"payload\">{}</pre>\n", html_escape(p)));
        }
        if let Some(e) = &f.evidence {
            html.push_str(&format!("<div class=\"evidence\">{}</div>\n", html_escape(e)));
        }
        if let Some(n) = &f.note {
            html.push_str(&format!("<div class=\"note\">{}</div>\n", html_escape(n)));
        }
        html.push_str(&format!("<div class=\"conf\">confidence: {}%</div>\n", f.confidence));
        html.push_str(&format!("<details><summary>PoC</summary><pre>curl -sk -X GET '{}'</pre></details>\n", html_escape(&f.target)));
        html.push_str("</article>\n");
        let _ = i;
    }
    html.push_str("</section>\n");

    html.push_str("<script>\n");
    html.push_str(DASHBOARD_JS);
    html.push_str("</script>\n");

    html.push_str("</body>\n</html>\n");
    html
}

pub fn write(findings: &[Finding], engagement: &str, path: &str) -> std::io::Result<()> {
    let html = render(findings, engagement);
    fs::write(path, html)
}

const DASHBOARD_CSS: &str = "
:root { --bg:#0d1117; --card:#161b22; --border:#30363d; --fg:#e6edf3; --muted:#8b949e; }
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.5 -apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif; background: var(--bg); color: var(--fg); }
header { padding: 24px 32px; border-bottom: 1px solid var(--border); background: linear-gradient(180deg, #1a1f2c 0%, #0d1117 100%); }
header h1 { margin: 0 0 4px 0; font-size: 24px; }
header h2 { margin: 0; font-size: 14px; color: var(--muted); font-weight: normal; }
.summary { display: flex; gap: 12px; padding: 24px 32px; flex-wrap: wrap; }
.stat { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 12px 20px; min-width: 100px; display: flex; flex-direction: column; align-items: center; }
.stat .count { font-size: 24px; font-weight: 600; }
.stat .label { font-size: 11px; color: var(--muted); text-transform: uppercase; }
.stat-critical .count { color: #f85149; }
.stat-high .count { color: #ff7b72; }
.stat-medium .count { color: #d29922; }
.stat-low .count { color: #58a6ff; }
.stat-info .count { color: #8b949e; }
.stat.zero { opacity: 0.4; }
.filter { padding: 0 32px 16px; display: flex; gap: 12px; }
.filter input, .filter select { background: var(--card); border: 1px solid var(--border); color: var(--fg); padding: 8px 12px; border-radius: 6px; font-size: 14px; }
.filter input { flex: 1; }
.findings { padding: 0 32px 64px; display: flex; flex-direction: column; gap: 8px; }
.finding { background: var(--card); border: 1px solid var(--border); border-left-width: 4px; border-radius: 6px; padding: 12px 16px; }
.finding.sev-critical { border-left-color: #f85149; }
.finding.sev-high { border-left-color: #ff7b72; }
.finding.sev-medium { border-left-color: #d29922; }
.finding.sev-low { border-left-color: #58a6ff; }
.finding.sev-info { border-left-color: #8b949e; }
.finding .head { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.finding .head h3 { margin: 0; font-size: 15px; }
.badge { font-size: 10px; padding: 2px 8px; border-radius: 12px; font-weight: 600; }
.badge.critical { background: #f8514922; color: #f85149; }
.badge.high { background: #ff7b7222; color: #ff7b72; }
.badge.medium { background: #d2992222; color: #d29922; }
.badge.low { background: #58a6ff22; color: #58a6ff; }
.badge.info { background: #8b949e22; color: #8b949e; }
.cat { font-size: 11px; color: var(--muted); font-family: ui-monospace,monospace; }
.meta { margin-top: 6px; font-size: 12px; }
.meta code { background: #1c2129; padding: 2px 6px; border-radius: 3px; color: #79c0ff; word-break: break-all; }
.payload, .evidence, .note { font-size: 12px; margin-top: 6px; }
.payload { background: #1c2129; padding: 8px 12px; border-radius: 4px; overflow-x: auto; color: #79c0ff; }
.evidence, .note { color: var(--muted); padding: 4px 0; }
.conf { font-size: 11px; color: var(--muted); margin-top: 4px; }
details { margin-top: 6px; }
details summary { cursor: pointer; font-size: 11px; color: var(--muted); }
details pre { background: #1c2129; padding: 6px 10px; border-radius: 3px; font-size: 11px; }
.finding.hidden { display: none; }
";

const DASHBOARD_JS: &str = "
const q = document.getElementById('q');
const sev = document.getElementById('sev');
function filter() {
  const term = q.value.toLowerCase();
  const sval = sev.value;
  document.querySelectorAll('.finding').forEach(el => {
    const text = (el.dataset.text || '').toLowerCase();
    const s = el.dataset.sev;
    const matchT = !term || text.includes(term);
    const matchS = !sval || s === sval;
    el.classList.toggle('hidden', !(matchT && matchS));
  });
}
q.addEventListener('input', filter);
sev.addEventListener('change', filter);
";

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    fn sample() -> Finding {
        Finding {
            severity: Severity::Critical,
            category: "TAKEOVER".into(),
            title: "Subdomain takeover".into(),
            target: "https://sub.target.com/".into(),
            param: None,
            payload: None,
            evidence: Some("GH Pages 404".into()),
            confidence: 95,
            note: Some("Claim subdomain".into()),
            request: None,
            response: None,
        }
    }

    #[test]
    fn render_has_html() {
        let html = render(&[sample()], "test-engagement");
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("KOBRA"));
        assert!(html.contains("CRITICAL"));
    }

    #[test]
    fn render_escapes_target() {
        let html = render(&[sample()], "<script>alert(1)</script>");
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn render_has_css() {
        let html = render(&[], "test");
        assert!(html.contains("--bg"));
        assert!(html.contains(".finding.sev-critical"));
    }

    #[test]
    fn render_has_js() {
        let html = render(&[], "test");
        assert!(html.contains("function filter()"));
    }

    #[test]
    fn html_escape_amp() {
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }
}
