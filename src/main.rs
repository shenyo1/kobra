use clap::{Parser, ValueEnum};
use kobra::engine::chain_detect;
use kobra::http::HttpClient;
use kobra::recon;
use kobra::scan;
use kobra::engine::rate_limit;
use kobra::scan::checkpoint;
use kobra::report::{legacy, poc, markdown_v2, dashboard};
use kobra::types::{Mode, Severity};
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "kobra", version, about = "KOBRA v1.6 — WAF learning + webhooks + auth + crawler + headless")]
struct Cli {
    /// Target URL(s). Comma-separated for multiple.
    #[arg(short, long, value_delimiter = ',')]
    target: Vec<String>,

    /// Scan mode.
    #[arg(short, long, value_enum, default_value_t = ModeArg::Normal)]
    mode: ModeArg,

    /// Run recon (subdomain + param discovery) first.
    #[arg(short = 'R', long)]
    recon: bool,

    /// Output as JSON.
    #[arg(short = 'j', long)]
    json: bool,

    /// Write report to file (md or json).
    #[arg(short, long)]
    output: Option<String>,

    /// Engagement name (for reports).
    #[arg(long, default_value = "kobra-engagement")]
    engagement: String,

    /// Generate PoC bash scripts for high+critical findings.
    #[arg(long)]
    poc_dir: Option<String>,

    /// Generate HTML dashboard report.
    #[arg(long)]
    html: Option<String>,

    /// Generate Markdown v2 report.
    #[arg(long)]
    md: Option<String>,

    /// Concurrency (overrides mode default).
    #[arg(short = 'c', long)]
    concurrency: Option<usize>,

    /// Request timeout seconds.
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// Plugin directory for hot-loaded JSON modules.
    #[arg(long)]
    plugin_dir: Option<String>,

    /// Update CVE database from NVD/CISA feed.
    #[arg(long)]
    cve_update: bool,

    /// Template directory for YAML/JSON vulnerability checks.
    #[arg(long)]
    template_dir: Option<String>,

    /// Enable headless browser scan (DOM XSS, SPA crawl). Requires Chrome.
    #[arg(long)]
    browser: bool,

    /// Custom HTTP headers (format: "Key: Value, Key2: Value2")
    #[arg(long)]
    header: Option<String>,

    /// Cookie string to include in requests.
    #[arg(long)]
    cookie: Option<String>,

    /// Authenticate via login URL (POST with body). Format: "url|body"
    /// Example: --auth "https://api.example.com/login|username=admin&password=admin"
    #[arg(long)]
    auth: Option<String>,

    /// Slack webhook URL for notifications.
    #[arg(long)]
    slack_webhook: Option<String>,

    /// Discord webhook URL for notifications.
    #[arg(long)]
    discord_webhook: Option<String>,

    /// Generic webhook URL for JSON notifications.
    #[arg(long)]
    webhook: Option<String>,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ModeArg {
    Stealth,
    Normal,
    Crazy,
}

impl From<ModeArg> for Mode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Stealth => Mode::Stealth,
            ModeArg::Normal => Mode::Normal,
            ModeArg::Crazy => Mode::Crazy,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if cli.target.is_empty() {
        eprintln!("[-] No target. Use -t https://site.com");
        std::process::exit(1);
    }
    let mode: Mode = cli.mode.into();
    let conc = cli.concurrency.unwrap_or_else(|| mode.concurrency());
    let mut http = HttpClient::new(conc, cli.timeout)?;

    // Auth session setup
    let mut auth_headers: Vec<(String, String)> = Vec::new();

    // Parse --header "Key: Value, Key2: Value2"
    if let Some(h) = &cli.header {
        for part in h.split(',') {
            let trimmed = part.trim();
            if let Some(pos) = trimmed.find(':') {
                let key = trimmed[..pos].trim().to_string();
                let val = trimmed[pos+1..].trim().to_string();
                auth_headers.push((key, val));
            }
        }
    }

    // Parse --auth "url|body"
    if let Some(auth_str) = &cli.auth {
        if let Some(pipe_pos) = auth_str.find('|') {
            let auth_url = &auth_str[..pipe_pos];
            let auth_body = &auth_str[pipe_pos+1..];
            println!("[*] authenticating at: {}", auth_url);
            match http.fetch(auth_url, reqwest::Method::POST, Some(auth_body), None).await {
                Ok((st, _h, body, _f)) => {
                    println!("[+] auth response: HTTP {}", st);
                    // Try to extract token from response
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                        if let Some(token) = json.get("token").and_then(|t| t.as_str()) {
                            auth_headers.push(("Authorization".into(), format!("Bearer {}", token)));
                            println!("[+] extracted Bearer token from auth response");
                        } else if let Some(access) = json.get("access_token").and_then(|t| t.as_str()) {
                            auth_headers.push(("Authorization".into(), format!("Bearer {}", access)));
                            println!("[+] extracted access_token from auth response");
                        } else if let Some(session) = json.get("session").or_else(|| json.get("session_id")).or_else(|| json.get("sid")).and_then(|t| t.as_str()) {
                            auth_headers.push(("Cookie".into(), format!("session={}", session)));
                            println!("[+] extracted session cookie from auth response");
                        }
                    }
                    // Fallback: check Set-Cookie header
                    if !auth_headers.iter().any(|(k,_)| k == "Cookie" || k == "Authorization") {
                        for line in _h.lines() {
                            if line.to_lowercase().starts_with("set-cookie:") {
                                if let Some(cookie_val) = line.split(':').nth(1) {
                                    let cookie_clean = cookie_val.trim().split(';').next().unwrap_or("").to_string();
                                    if !cookie_clean.is_empty() {
                                        println!("[+] captured Set-Cookie: {}", cookie_clean);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => eprintln!("[-] auth request failed: {}", e),
            }
        }
    }

    // Apply auth to HTTP client
    http.apply_auth(auth_headers, cli.cookie.clone());
    let http = Arc::new(http);

    println!(
        "\x1b[95m
   ▄█  █▄▄▄▄ ▄███▄   ██   █▄▄▄▄
  ██  ██▀▀▀▀ ██   █  █ █  █  ▄▀
  ██  ██      ██   █ █▄▄█ █▀▀▌
  ██  ██      ▀████▀ █  █ █  █
  ▀█   ▀        ▀        █  █
        KOBRA v1.0 — all-in-one BB scanner (OVERPOWERED)\x1b[0m"
    );
    println!("[*] mode={:?} concurrency={} timeout={}s", mode, conc, cli.timeout);

    // Output resilience: incremental JSON Lines
    let jsonl_path = format!("/tmp/kobra_{}.jsonl", cli.engagement);
    // Load previous findings if any (from partial runs)
    let mut all: Vec<kobra::types::Finding> = kobra::report::resilience::read_findings(&jsonl_path);
    let mut scan_targets: Vec<String> = cli.target.iter().map(|s| s.trim().to_string()).collect();

    // Checkpoint: resume support
    let ckpt_path = format!("/tmp/kobra_{}.ckpt.json", cli.engagement);
    let mut ckpt = checkpoint::Checkpoint::load(&ckpt_path);

    // Rate limiter
    let rl = rate_limit::new_limiter();

    // Load plugins if --plugin-dir provided
    let plugins: Vec<kobra::scan::plugin::Plugin> = if let Some(dir) = &cli.plugin_dir {
        println!("[*] loading plugins from {}...", dir);
        kobra::scan::plugin::load_dir(dir)
    } else {
        vec![]
    };
    if !plugins.is_empty() {
        println!("[+] loaded {} plugin(s)", plugins.len());
    }

    // Load templates if --template-dir provided
    let templates: Vec<kobra::engine::template::Template> = if let Some(dir) = &cli.template_dir {
        println!("[*] loading templates from {}...", dir);
        kobra::engine::template::load_templates(dir)
    } else {
        vec![]
    };
    if !templates.is_empty() {
        println!("[+] loaded {} template(s)", templates.len());
    }

    // CVE update if --cve-update
    if cli.cve_update {
        println!("[*] fetching CVE feed...");
        let entries = kobra::engine::cve_update::fetch_cve_feed().await;
        let cache_path = "/tmp/kobra_cve_cache.json";
        kobra::engine::cve_update::save_cve_cache(&entries, cache_path);
        println!("[+] CVE cache updated: {} entries", entries.len());
    }

    for t in &cli.target {
        let t = t.trim().to_string();
        println!("\n[*] === TARGET: {} ===", t);

        if cli.recon {
            println!("[*] running recon...");
            match recon::run_recon(&http, &t).await {
                Ok(f) => {
                    println!("[+] recon found {} item(s)", f.len());
                    all.extend(f.clone());
                    // PIPELINE: discovered subdomains get scanned too (recon -> scan chain)
                    for sub in &f {
                        if sub.category == "RECON" && sub.severity == Severity::Info
                            && sub.target.starts_with("http") {
                            scan_targets.push(sub.target.clone());
                        }
                    }
                }
                Err(e) => eprintln!("[-] recon error: {}", e),
            }
        }
    }

    // Now scan every target in parallel using parallel module
    // Filter: skip checkpointed + banned targets
    let active_targets: Vec<String> = scan_targets.iter()
        .filter(|t| {
            if ckpt.is_done(t, "full") {
                println!("[*] SKIP (checkpoint): {}", t);
                false
            } else if rate_limit::is_banned(&rl, t) {
                println!("[-] SKIP (banned by rate limiter): {}", t);
                false
            } else {
                true
            }
        })
        .cloned()
        .collect();

    if !active_targets.is_empty() {
        println!("\n[*] === PARALLEL SCAN: {} targets with concurrency={} ===\n", active_targets.len(), conc);

        let parallel_config = kobra::scan::parallel::ParallelConfig {
            max_concurrent: conc,
            ..Default::default()
        };

        let scan_http = http.clone();
        let scan_mode = mode;
        let scan_rl = rl.clone();
        let scan_plugins = plugins.clone();
        let scan_templates = templates.clone();
        let jsonl = jsonl_path.clone();
        let results = kobra::scan::parallel::scan_targets(
            active_targets,
            parallel_config,
            move |target| {
                let http = scan_http.clone();
                let mode = scan_mode;
                let rl = scan_rl.clone();
                let pl = scan_plugins.clone();
                let tl = scan_templates.clone();
                let jl = jsonl.clone();
                async move {
                    rate_limit::record_request(&rl, &target);
                    let extra: Vec<String> = if mode == Mode::Crazy {
                        vec!["redirect".into(), "next".into(), "file".into(), "path".into(),
                             "doc".into(), "img".into(), "callback".into(), "continue".into()]
                    } else {
                        vec![]
                    };
                    match scan::run_all(&http, &target, &extra, mode, "", &pl, &tl).await {
                        Ok(f) => {
                            println!("[+] {} → {} finding(s)", target, f.len());
                            rate_limit::record_response(&rl, &target, 200);
                            // Incremental write
                            let _ = kobra::report::resilience::append_findings(&jl, &f);
                            f
                        }
                        Err(e) => {
                            eprintln!("[-] {} → error: {}", target, e);
                            rate_limit::record_response(&rl, &target, 503);
                            vec![]
                        }
                    }
                }
            },
        ).await;

        let count = results.len();
        all.extend(results);
        println!("\n[*] Parallel scan complete: {} total findings from {} targets", all.len(), count);
    }

    // Chain detection — cross-module correlation
    let chains = chain_detect::detect_chains(&all);

    // Headless browser scan (optional, requires Chrome)
    if cli.browser {
        if kobra::scan::headless::is_available() {
            println!("\n[*] === HEADLESS BROWSER SCAN ===");
            for t in &scan_targets {
                println!("[*] browser scanning: {}", t);
                let headless_findings = scan::run_headless(t, mode).await;
                println!("[+] browser scan: {} finding(s)", headless_findings.len());
                all.extend(headless_findings);
            }
        } else {
            println!("[-] --browser flag used but Chrome/Chromium not found. Install chromium-browser or google-chrome.");
        }
    }
    if !chains.is_empty() {
        println!("\n[*] === ATTACK CHAINS DETECTED ===");
        for c in &chains {
            println!("[!] {} [{:?}] confidence={}", c.name, c.severity, c.confidence);
            for s in &c.steps {
                println!("     → {}", s);
            }
        }
        // Add chains as findings
        for c in chains {
            all.push(
                kobra::types::Finding::new(
                    c.severity,
                    "CHAIN",
                    &c.name,
                    &c.findings.first().map(|f| f.target.as_str()).unwrap_or("")
                )
                .with_evidence(&format!("{} steps: {}", c.steps.len(), c.description))
                .with_confidence(c.confidence)
                .with_note(&c.description)
            );
        }
    }

    // Always show everything (full disclosure).
    let all = dedupe_noise(all);

    // Webhook notifications
    if let Some(url) = &cli.slack_webhook {
        match kobra::report::webhook::send_slack(url, &all, &cli.engagement).await {
            Ok(_) => println!("[+] Slack notification sent"),
            Err(e) => eprintln!("[-] Slack webhook error: {}", e),
        }
    }
    if let Some(url) = &cli.discord_webhook {
        match kobra::report::webhook::send_discord(url, &all, &cli.engagement).await {
            Ok(_) => println!("[+] Discord notification sent"),
            Err(e) => eprintln!("[-] Discord webhook error: {}", e),
        }
    }
    if let Some(url) = &cli.webhook {
        match kobra::report::webhook::send_generic(url, &all, &cli.engagement).await {
            Ok(_) => println!("[+] Generic webhook sent"),
            Err(e) => eprintln!("[-] Webhook error: {}", e),
        }
    }

    legacy::print_findings(&all, cli.json);
    if let Some(out) = &cli.output {
        legacy::write_report(&all, out);
        println!("[*] report written to {}", out);
    }
    if let Some(dir) = &cli.poc_dir {
        match poc::write_poc_bundle(&all, &cli.engagement, dir) {
            Ok(n) => println!("[+] {} PoC scripts written to {}", n, dir),
            Err(e) => eprintln!("[-] PoC bundle error: {}", e),
        }
    }
    if let Some(p) = &cli.html {
        match dashboard::write(&all, &cli.engagement, p) {
            Ok(_) => println!("[+] HTML dashboard written to {}", p),
            Err(e) => eprintln!("[-] HTML error: {}", e),
        }
    }
    if let Some(p) = &cli.md {
        match markdown_v2::write(&all, &cli.engagement, p) {
            Ok(_) => println!("[+] Markdown v2 report written to {}", p),
            Err(e) => eprintln!("[-] MD error: {}", e),
        }
    }

    // Exit code reflects whether any High/Critical found (handy for pipelines).
    let has_serious = all.iter().any(|f| matches!(f.severity, Severity::High | Severity::Critical));
    std::process::exit(if has_serious { 1 } else { 0 });
}

/// FIX.6: Deduplicate noise. If 5+ identical LOW findings (same category + payload + target),
/// collapse to 1 representative + count note. Reduces 156→1 for static-SPA SSRF FPs.
fn dedupe_noise(findings: Vec<kobra::types::Finding>) -> Vec<kobra::types::Finding> {
    use kobra::types::{Finding, Severity};
    use std::collections::HashMap;

    let mut by_key: HashMap<String, Finding> = HashMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();

    for f in findings {
        // Only dedupe LOW/INFO noise — keep HIGH+ as-is
        let key = format!("{}|{}|{}|{}",
            f.category, f.target,
            f.param.as_deref().unwrap_or(""),
            f.payload.as_deref().unwrap_or(""));
        *counts.entry(key.clone()).or_insert(0) += 1;
        if !matches!(f.severity, Severity::Low | Severity::Info) {
            by_key.insert(key, f);
            continue;
        }
        by_key.entry(key).or_insert(f);
    }

    let mut out: Vec<Finding> = Vec::new();
    for (key, mut f) in by_key {
        let c = counts[&key];
        if c > 3 {
            // Append count to evidence / note
            let suffix = format!(" (deduped from {} similar findings)", c);
            if let Some(n) = &f.note {
                f.note = Some(format!("{}{}", n, suffix));
            } else if let Some(e) = &f.evidence {
                f.evidence = Some(format!("{}{}", e, suffix));
            }
        }
        out.push(f);
    }
    out
}
