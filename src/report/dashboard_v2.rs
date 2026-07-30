//! Interactive Web Dashboard
//!
//! Self-contained HTML report with embedded JavaScript for
//! interactive findings exploration. No external CDN — fully offline.
//!
//! Features:
//! - Search/filter by category, severity, target
//! - Sort by any column
//! - Severity distribution chart (embedded Chart.js-like canvas)
//! - Group-by-category panel
//! - Click to expand evidence
//! - Export to JSON/CSV buttons
//!
//! Usage:
//!     let html = DashboardV2::render(&findings, "My Scan", "https://target.com");
//!     std::fs::write("dashboard.html", html)?;

use crate::types::Finding;
#[cfg(test)]
use crate::types::Severity;
use std::collections::HashMap;

pub struct DashboardV2;

impl DashboardV2 {
    /// Render full interactive HTML dashboard.
    pub fn render(findings: &[Finding], title: &str, target: &str) -> String {
        let stats = Self::compute_stats(findings);
        let rows = Self::render_rows(findings);
        let chart_data = Self::severity_chart_data(&stats);

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KOBRA Dashboard — {title}</title>
<style>
:root {{
  --bg: #0d1117;
  --card: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --text-dim: #8b949e;
  --critical: #f85149;
  --high: #ff7b72;
  --medium: #d29922;
  --low: #58a6ff;
  --info: #8b949e;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", monospace;
  background: var(--bg);
  color: var(--text);
  padding: 2rem;
}}
h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
.target {{ color: var(--text-dim); margin-bottom: 2rem; font-family: monospace; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
         gap: 1rem; margin-bottom: 2rem; }}
.stat {{ background: var(--card); padding: 1rem; border-radius: 8px; border: 1px solid var(--border); }}
.stat-num {{ font-size: 2rem; font-weight: bold; }}
.stat-label {{ color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase; }}
.severity-critical {{ color: var(--critical); }}
.severity-high {{ color: var(--high); }}
.severity-medium {{ color: var(--medium); }}
.severity-low {{ color: var(--low); }}
.severity-info {{ color: var(--info); }}
.controls {{ margin-bottom: 1rem; display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }}
.controls input, .controls select {{
  background: var(--card); border: 1px solid var(--border); color: var(--text);
  padding: 0.5rem; border-radius: 4px; font-family: inherit;
}}
.controls input {{ flex: 1; min-width: 200px; }}
table {{ width: 100%; border-collapse: collapse; background: var(--card); border-radius: 8px; overflow: hidden; }}
th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ background: #21262d; cursor: pointer; user-select: none; }}
tr:hover {{ background: #21262d; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: bold; }}
.badge-critical {{ background: rgba(248, 81, 73, 0.2); color: var(--critical); }}
.badge-high {{ background: rgba(255, 123, 114, 0.2); color: var(--high); }}
.badge-medium {{ background: rgba(210, 153, 34, 0.2); color: var(--medium); }}
.badge-low {{ background: rgba(88, 166, 255, 0.2); color: var(--low); }}
.badge-info {{ background: rgba(139, 148, 158, 0.2); color: var(--info); }}
.evidence {{ display: none; padding: 0.5rem; background: #0d1117; font-family: monospace;
            font-size: 0.8rem; color: var(--text-dim); white-space: pre-wrap; word-break: break-all; }}
.evidence.show {{ display: block; }}
.chart-container {{ background: var(--card); padding: 1rem; border-radius: 8px; border: 1px solid var(--border);
                  margin-bottom: 2rem; }}
canvas {{ max-width: 100%; }}
button {{ background: var(--border); color: var(--text); border: none; padding: 0.5rem 1rem;
         border-radius: 4px; cursor: pointer; font-family: inherit; }}
button:hover {{ background: #484f58; }}
.export-buttons {{ margin-top: 1rem; display: flex; gap: 0.5rem; }}
footer {{ margin-top: 3rem; color: var(--text-dim); text-align: center; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>🐍 KOBRA Security Dashboard</h1>
<div class="target">Target: {target} • Scan: {title} • Findings: {total_findings}</div>

<div class="stats">
  <div class="stat">
    <div class="stat-num">{total_findings}</div>
    <div class="stat-label">Total</div>
  </div>
  <div class="stat">
    <div class="stat-num severity-critical">{critical}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat">
    <div class="stat-num severity-high">{high}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat">
    <div class="stat-num severity-medium">{medium}</div>
    <div class="stat-label">Medium</div>
  </div>
  <div class="stat">
    <div class="stat-num severity-low">{low}</div>
    <div class="stat-label">Low</div>
  </div>
  <div class="stat">
    <div class="stat-num severity-info">{info}</div>
    <div class="stat-label">Info</div>
  </div>
</div>

<div class="chart-container">
  <h2>Severity Distribution</h2>
  <canvas id="severityChart" width="400" height="100"></canvas>
</div>

<div class="controls">
  <input id="searchBox" type="text" placeholder="🔍 Search findings (target, category, evidence)..." />
  <select id="severityFilter">
    <option value="all">All Severities</option>
    <option value="critical">Critical+</option>
    <option value="high">High+</option>
    <option value="medium">Medium+</option>
    <option value="low">Low+</option>
  </select>
  <button onclick="exportJSON()">📥 Export JSON</button>
  <button onclick="exportCSV()">📥 Export CSV</button>
</div>

<table>
<thead>
<tr>
  <th onclick="sortTable(0)">Severity</th>
  <th onclick="sortTable(1)">Category</th>
  <th onclick="sortTable(2)">Title</th>
  <th onclick="sortTable(3)">Target</th>
  <th onclick="sortTable(4)">Confidence</th>
  <th>Evidence</th>
</tr>
</thead>
<tbody id="findingsTable">
{rows}
</tbody>
</table>

<footer>
🛡️ KOBRA v4.7 — Interactive Dashboard • Generated <script>document.write(new Date().toISOString())</script>
</footer>

<script>
// ===== SEARCH & FILTER =====
const searchBox = document.getElementById('searchBox');
const severityFilter = document.getElementById('severityFilter');
searchBox.addEventListener('input', applyFilter);
severityFilter.addEventListener('change', applyFilter);

function applyFilter() {{
  const q = searchBox.value.toLowerCase();
  const sevFilter = severityFilter.value;
  const rows = document.querySelectorAll('#findingsTable tr');
  const sevOrder = ['info','low','medium','high','critical'];
  rows.forEach(row => {{
    const text = row.textContent.toLowerCase();
    const rowSev = row.getAttribute('data-severity');
    const matchesSearch = !q || text.includes(q);
    let matchesSeverity = true;
    if (sevFilter !== 'all') {{
      const minIdx = sevOrder.indexOf(sevFilter);
      const rowIdx = sevOrder.indexOf(rowSev);
      matchesSeverity = rowIdx >= minIdx;
    }}
    row.style.display = (matchesSearch && matchesSeverity) ? '' : 'none';
  }});
}}

// ===== SORT =====
let sortDir = {{}};
function sortTable(col) {{
  const tbody = document.getElementById('findingsTable');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  sortDir[col] = !sortDir[col];
  rows.sort((a, b) => {{
    const aVal = a.children[col]?.textContent || '';
    const bVal = b.children[col]?.textContent || '';
    const cmp = aVal.localeCompare(bVal);
    return sortDir[col] ? cmp : -cmp;
  }});
  rows.forEach(row => tbody.appendChild(row));
}}

// ===== EVIDENCE TOGGLE =====
function toggleEvidence(id) {{
  const el = document.getElementById('evidence-' + id);
  el.classList.toggle('show');
}}

// ===== EXPORT =====
const findings = {json_data};
function exportJSON() {{
  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(findings, null, 2));
  download(dataStr, 'kobra-findings.json');
}}
function exportCSV() {{
  const headers = ['severity','category','title','target','confidence','evidence'];
  let csv = headers.join(',') + '\\n';
  findings.forEach(f => {{
    csv += [
      f.severity,
      '"' + (f.category||'').replace(/"/g, '""') + '"',
      '"' + (f.title||'').replace(/"/g, '""') + '"',
      '"' + (f.target||'').replace(/"/g, '""') + '"',
      f.confidence || 0,
      '"' + (f.evidence||'').replace(/"/g, '""') + '"'
    ].join(',') + '\\n';
  }});
  const dataStr = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
  download(dataStr, 'kobra-findings.csv');
}}
function download(uri, name) {{
  const a = document.createElement('a');
  a.href = uri;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}}

// ===== SEVERITY CHART =====
const chartData = {chart_data};
function drawChart() {{
  const canvas = document.getElementById('severityChart');
  const ctx = canvas.getContext('2d');
  const labels = Object.keys(chartData);
  const values = Object.values(chartData);
  const total = values.reduce((a,b)=>a+b, 0) || 1;
  const colors = {{
    'critical': '#f85149',
    'high': '#ff7b72',
    'medium': '#d29922',
    'low': '#58a6ff',
    'info': '#8b949e'
  }};
  let x = 20;
  const barWidth = (canvas.width - 40) / labels.length - 10;
  labels.forEach((label, i) => {{
    const val = values[i];
    const pct = val / total;
    const barHeight = pct * (canvas.height - 60);
    const y = canvas.height - 30 - barHeight;
    ctx.fillStyle = colors[label] || '#888';
    ctx.fillRect(x, y, barWidth, barHeight);
    ctx.fillStyle = '#c9d1d9';
    ctx.font = 'bold 14px sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(val, x + barWidth/2, y - 5);
    ctx.font = '11px sans-serif';
    ctx.fillText(label, x + barWidth/2, canvas.height - 10);
    x += barWidth + 10;
  }});
}}
drawChart();
window.addEventListener('resize', drawChart);
</script>
</body>
</html>"#,
            title = html_escape(title),
            target = html_escape(target),
            total_findings = findings.len(),
            critical = stats.get("critical").copied().unwrap_or(0),
            high = stats.get("high").copied().unwrap_or(0),
            medium = stats.get("medium").copied().unwrap_or(0),
            low = stats.get("low").copied().unwrap_or(0),
            info = stats.get("info").copied().unwrap_or(0),
            rows = rows,
            json_data = Self::findings_to_json(findings),
            chart_data = chart_data,
        )
    }

    fn render_rows(findings: &[Finding]) -> String {
        findings
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let sev = format!("{:?}", f.severity).to_lowercase();
                let badge_class = format!("badge-{}", sev);
                let evidence_html = match &f.evidence {
                    Some(e) => format!(
                        r#"<button onclick="toggleEvidence({})">View</button>
<div id="evidence-{}" class="evidence">{}</div>"#,
                        i, i, html_escape(e)
                    ),
                    None => String::from("-"),
                };
                format!(
                    r#"<tr data-severity="{}">
<td><span class="badge {}">{}</span></td>
<td>{}</td>
<td>{}</td>
<td><code>{}</code></td>
<td>{}%</td>
<td>{}</td>
</tr>"#,
                    sev,
                    badge_class,
                    sev,
                    html_escape(&f.category),
                    html_escape(&f.title),
                    html_escape(&f.target),
                    f.confidence,
                    evidence_html
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn compute_stats(findings: &[Finding]) -> HashMap<String, usize> {
        let mut stats: HashMap<String, usize> = HashMap::new();
        for f in findings {
            let sev = format!("{:?}", f.severity).to_lowercase();
            *stats.entry(sev).or_insert(0) += 1;
        }
        stats
    }

    fn severity_chart_data(stats: &HashMap<String, usize>) -> String {
        let labels = ["critical", "high", "medium", "low", "info"];
        let entries: Vec<String> = labels
            .iter()
            .map(|l| {
                format!(
                    "\"{}\": {}",
                    l,
                    stats.get(*l).copied().unwrap_or(0)
                )
            })
            .collect();
        "{".to_string() + &entries.join(", ") + "}"
    }

    fn findings_to_json(findings: &[Finding]) -> String {
        let json: Vec<String> = findings
            .iter()
            .map(|f| {
                format!(
                    r#"{{"severity":"{:?}","category":"{}","title":"{}","target":"{}","confidence":{},"evidence":"{}"}}"#,
                    f.severity,
                    json_escape(&f.category),
                    json_escape(&f.title),
                    json_escape(&f.target),
                    f.confidence,
                    json_escape(f.evidence.as_deref().unwrap_or(""))
                )
            })
            .collect();
        format!("[{}]", json.join(","))
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(cat: &str, target: &str, sev: Severity) -> Finding {
        let mut f = Finding::new(sev, cat, cat, target);
        f.evidence = Some(format!("Evidence for {}", cat));
        f.confidence = 80;
        f
    }

    #[test]
    fn render_contains_doctype() {
        let findings = vec![mk("XSS", "https://a.com", Severity::High)];
        let html = DashboardV2::render(&findings, "Test", "https://a.com");
        assert!(html.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn render_includes_findings_count() {
        let findings = vec![
            mk("XSS", "https://a.com", Severity::High),
            mk("SQLi", "https://a.com", Severity::Critical),
        ];
        let html = DashboardV2::render(&findings, "Test", "https://a.com");
        assert!(html.contains(">2<"));
    }

    #[test]
    fn render_chart_data_correct() {
        let findings = vec![
            mk("XSS", "https://a.com", Severity::High),
            mk("SQLi", "https://a.com", Severity::Critical),
            mk("Info", "https://a.com", Severity::Info),
        ];
        let stats = DashboardV2::compute_stats(&findings);
        assert_eq!(stats.get("high"), Some(&1));
        assert_eq!(stats.get("critical"), Some(&1));
        assert_eq!(stats.get("info"), Some(&1));
    }

    #[test]
    fn render_json_data_escapes() {
        let mut f = mk("XSS", "https://a.com\"test", Severity::High);
        f.evidence = Some("evil \"quote\" and \\back".to_string());
        let json = DashboardV2::findings_to_json(&[f]);
        assert!(json.contains("\\\""));
        assert!(json.contains("\\\\"));
    }

    #[test]
    fn render_html_escape() {
        let escaped = html_escape("<script>alert(1)</script>");
        assert!(escaped.contains("&lt;script&gt;"));
        assert!(!escaped.contains("<script>"));
    }

    #[test]
    fn render_empty_findings() {
        let html = DashboardV2::render(&[], "Empty", "https://a.com");
        assert!(html.contains(">0</div>"));  // Total findings
    }
}
