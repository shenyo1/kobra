
# 🐍 KOBRA OVERPOWERED UPGRADE PLAN
**Author**: Sakura-chan | **Date**: 2026-07-28 | **Target**: Make KOBRA the BEST BB scanner

## 🎯 ANALISIS SITUASI (Honest Assessment)

### Current State (STRENGTH)
- ✅ 27 modules, ZERO warnings, binary fresh
- ✅ Negative-control discipline (no FP dari SVG/CF/Kong catch-all)
- ✅ Full disclosure philosophy (info/low shown)
- ✅ 3 modes (stealth/normal/crazy)
- ✅ Cloudflare-aware (cf-ray detection, header bypass)

### Current State (GAPS — Honest)
- ❌ **Tidak ada OOB callback** untuk blind SSRF/RCE/auth
- ❌ **Tidak ada rate-limit aware** — kena ban langsung
- ❌ **Tidak ada payload rotation** — payload hardcoded, signature detected
- ❌ **Tidak ada smart recurssion** — satu target, satu pass
- ❌ **Tidak ada FP learning** — same FP terulang tiap scan
- ❌ **Tidak ada baseline correlation** — module2 jalan sendiri, gak koordinasi
- ❌ **Tidak ada chain detection** — module XSS ketemu + module Authflow ketemu = gak ada yang bilang "ini IDOR -> ATO chain"
- ❌ **User agent 1 doang** — kalau kena fingerprint UA block, scan mati
- ❌ **Tidak ada timing attack** untuk blind SQLi
- ❌ **Tidak ada DOM XSS** detection
- ❌ **Tidak ada JWT exploit** (HS256/RS256 confusion)
- ❌ **Tidak ada OAuth flow** testing
- ❌ **Tidak ada WebSocket** active exploitation (cuma detection)
- ❌ **Tidak ada async race** detection
- ❌ **Tidak ada SSRF cloud-aware** (Cloudflare metadata v2)
- ❌ **Tidak ada subdomain takeover** detection
- ❌ **Tidak ada misconfigured DNS** (CNAME takeover, dangling)
- ❌ **Tidak ada source map leak** detection
- ❌ **Tidak ada exposed .env** / backup files detection
- ❌ **Tidak ada cache deception** / poisoning
- ❌ **Tidak ada HTTP/2 specific attacks**
- ❌ **Tidak ada CVE-specific** detection (Log4Shell, Spring4Shell, dll)
- ❌ **Reporting**: text only, gak ada HTML dashboard, gak ada PoC generator
- ❌ **Tidak ada session resume** — kalau crash, scan ulang dari awal
- ❌ **Tidak ada real-time dashboard** untuk monitor scan progress

## 🔥 UPGRADE TIER (Priority order)

### TIER 1: CORE STRENGTH (Minggu 1 — 2 minggu)
These are MUST-HAVE for competitive scanner. tanpa ini KOBRA masih jadi baby tool.

#### 1.1 Adaptive Payload Engine
**Why**: payload static = fingerprint = bypassed by WAF dalam 1 menit
**What**:
- Mutation engine: comment injection, encoding chain, case-mix, zero-width chars, unicode homoglyphs
- Per-target payload cache: track which payload "kena" sebelum, reuse on similar context
- Random per-request UA + Accept-Language + Accept-Encoding rotation
**Files**:
- `src/engine/mutator.rs` (NEW)
- `src/engine/payload_cache.rs` (NEW)
- `src/http.rs` — extend for UA rotation

#### 1.2 OOB Callback Server
**Why**: blind SSRF, blind RCE, blind XSS butuh proof. Tanpa ini = "suspect" bukan "confirmed"
**What**:
- Built-in HTTP listener on random port
- DNS resolver listener (or use interact.sh-style)
- Each payload gets unique token `k0bra-<uuid>.oob.domain`
- Correlation by token -> confirmed finding
**Files**:
- `src/oob/server.rs` (NEW)
- `src/oob/dns.rs` (NEW)
- `src/scan/ssrf.rs`, `rce.rs`, `xss.rs` — integrate OOB payloads

#### 1.3 Timing Attack Engine
**Why**: blind SQLi, blind RCE, blind command injection gak bisa dideteksi tanpa timing
**What**:
- SLEEP payload variants (per-DB: MySQL/MSSQL/PG/Oracle/MongoDB)
- Time-based differential: if response > baseline + threshold = suspected
- Statistical test (5+ samples, mean + stdev) to reduce FP from network jitter
**Files**:
- `src/engine/timing.rs` (NEW)
- `src/scan/sqli.rs` — add timing payloads
- `src/scan/rce.rs` — add time-based payloads

#### 1.4 Rate-Limit Aware + Retry
**Why**: target dengan WAF kasih 429/403 IP-ban = scan gagal total
**What**:
- Detect 429/503 responses, exponential backoff
- Detect IP ban patterns, switch to header rotation
- Per-host request counter with adaptive delay
- Resume from checkpoint after ban
**Files**:
- `src/engine/rate_limit.rs` (NEW)
- `src/http.rs` — middleware
- `src/main.rs` — checkpoint resume

#### 1.5 Smart FP Filter (ML-ish rule-based)
**Why**: KOBRA punya banyak FP rules, tapi gak centralized. Tiap module reimplement
**What**:
- Centralized FP rules database
- Cross-module correlation: "if /admin 200 + cf-ray present = CF catch-all, not real admin"
- Track CF/Kong/CloudFront/Imperva/Akamai signatures in one place
- Auto-suppress known-FP combos
**Files**:
- `src/engine/fp_filter.rs` (NEW)
- All modules — use centralized filter

### TIER 2: SMART MODULES (Minggu 2 — 4 minggu)
Make modules actually USEFUL, not just detectors.

#### 2.1 JWT Exploitation Module
**Why**: 2026 masih banyak JWT vulns — alg:none, RS256->HS256 confusion, weak secret
**What**:
- Detect JWT in headers/cookies/responses
- Try alg:none bypass
- Try HS256/RS256 confusion (server uses RSA public as HMAC secret)
- Weak secret brute with rockyou.txt + seclists
- jwk/jku/x5u injection
**Files**:
- `src/scan/jwt.rs` (NEW)
- 150 LOC est

#### 2.2 OAuth/OIDC Flow Tester
**Why**: redirect_uri bypass, state fixation, PKCE downgrade, open redirect in OAuth
**What**:
- Detect /oauth/* /auth/* endpoints
- Test redirect_uri: domain.tld.attacker.com, @attacker.com, /\evil.com
- Test state missing/reusable
- Test PKCE downgrade
- Test scope escalation
**Files**:
- `src/scan/oauth.rs` (NEW)
- 200 LOC est

#### 2.3 DOM XSS Sink Detection
**Why**: KOBRA sekarang cuma reflected/stored XSS — DOM XSS beda teknik
**What**:
- Crawl JS bundles, AST parse, find sinks: innerHTML, document.write, eval, Function()
- Find sources: location.hash, document.referrer, postMessage
- Static taint flow: source -> sink
- Dynamic: Puppeteer/playwright probe payloads
**Files**:
- `src/scan/dom_xss.rs` (NEW)
- 250 LOC est (AST parsing is heavy)

#### 2.4 Race Condition Engine
**Why**: TOCTOU bugs (coupon apply, withdraw, vote) = $$$ in bug bounty
**What**:
- Detect interesting endpoints (POST /apply, /transfer, /vote, /coupon)
- Fire N parallel requests (50+ concurrent), measure if state mutation happens >1 times
- Diff responses: if 2x success when should be 1x = race
**Files**:
- `src/scan/race.rs` (NEW)
- 100 LOC est

#### 2.5 Subdomain Takeover
**Why**: dangling DNS = full subdomain control = cookie theft for parent domain
**What**:
- crt.sh enum subdomains
- Resolve CNAME for each
- Match against takeover fingerprints (GitHub Pages: 404 + "There isn't a GitHub Pages site here", Heroku: "no such app", S3: "NoSuchBucket", Azure: "404 Web Site not found", Vercel, Netlify, Pantheon, etc.)
**Files**:
- `src/scan/takeover.rs` (NEW)
- 150 LOC est

#### 2.6 Exposed Sensitive Files
**Why**: .env, .git, backups = instant credentials
**What**:
- Wordlist of 500+ sensitive paths: .env, .env.local, .git/config, .git/HEAD, wp-config.php.bak, database.sql, server.key, debug.log, phpinfo.php, etc.
- Per-CMS fingerprints (WordPress, Laravel, Drupal, Magento, Django)
- HEAD-first then GET for 200
**Files**:
- `src/scan/exposed_files.rs` (NEW)
- 200 LOC est + wordlist `assets/sensitive_paths.txt`

#### 2.7 Source Map Leak
**Why**: .js.map = original TypeScript code = API endpoints, secrets in comments
**What**:
- For every .js discovered, try .js.map
- Parse source map JSON, extract sources[] array
- Curl each source, look for API endpoints, secrets, debug code
**Files**:
- `src/scan/source_map.rs` (NEW)
- 100 LOC est

#### 2.8 HTTP Request Smuggling v2
**Why**: CL.TE/TE.CL/H2 downgrade = bypass all front-end controls
**What**:
- Detect front-end (HAProxy, nginx, Apache, CloudFront)
- Timing-based CL.TE detection (response delay with conflicting Content-Length + Transfer-Encoding)
- T-E chunk size manipulation
**Files**:
- `src/scan/smuggle_v2.rs` (NEW)
- 200 LOC est

### TIER 3: REPORTING + UX (Minggu 4 — 5 minggu)

#### 3.1 PoC Auto-Generator
**What**: setiap finding = curl command siap pakai untuk re-test & report
- Generate curl from finding's target + payload + headers
- Save PoC script per finding as bash file
- Include in markdown report

#### 3.2 HTML Dashboard
**What**: real-time web UI untuk monitor scan progress
- SSE-based live updates
- Severity color-coded
- Filter by category, severity, target
- Click finding -> expand for full evidence

#### 3.3 Markdown Report v2
**What**: professional report per engagement
- Executive summary
- Findings sorted by CVSS
- Per-finding: description, impact, PoC, remediation, references (OWASP/CWE)
- Auto-screenshots via headless Chromium on proof URLs

### TIER 4: ADVANCED (Minggu 5 — ongoing)

#### 4.1 CVE-Specific Modules
- Log4Shell detector (JNDI in headers/URLs)
- Spring4Shell detector
- Confluence CVE-2023-22515
- Fortinet CVE-2024-21762
- Ivanti CVE-2024-1709
- Auto-update via CVE feed RSS

#### 4.2 Multi-Target Pipeline (Parallel)
- Scan N targets concurrently, share rate-limit budget across targets
- Pool of HTTP clients, semaphore-based

#### 4.3 Resume from Checkpoint
- Persist state after each module completion
- On crash/reconnect, skip already-scanned (target, module, payload)
- Save to `~/.kobra/checkpoints/<engagement_id>.db`

#### 4.4 Plugin System
- Hot-load .so modules at runtime
- Allow community modules (TomNomNom-style)

#### 4.5 AI Triage
- Local LLM (ollama — but failed in sandbox per memory, so use remote or skip)
- Feed raw findings, get categorized + severity-adjusted + report-ready text
- Out of scope if no LLM available — flag in plan

## 📊 EFFORT ESTIMATE

| Tier | Tasks | LOC est | Time |
|------|-------|---------|------|
| 1 | 5 | 800 | 2 weeks |
| 2 | 8 | 1500 | 3 weeks |
| 3 | 3 | 1200 | 1 week |
| 4 | 5 | 800+ | ongoing |
| **Total** | **21** | **~4300** | **6+ weeks** |

## 🎬 RECOMMENDED ORDER (dimulai dari mana)

**Start with Tier 1.1 (Adaptive Payload) + 1.2 (OOB) + 1.5 (FP Filter)** —
these 3 unlock 80% of value gain. Yang lain bisa incremental.

**Why this order**:
1. Adaptive payload = bypass more WAFs = more findings reach you
2. OOB = blind vulns become confirmed = higher payout on report
3. FP filter = less noise = less time filtering manually = higher hit rate

After Tier 1 done, KOBRA is ALREADY competitive dengan Nuclei/Dalfox. Tier 2+3 = moat.

## 💡 HONEST TAKE

KOBRA sekarang fungsional tapi masih **entry-level** dibanding Nuclei (3000+ templates),
Dalfox (XSS specialized), Burp Pro (full proxy). Differentiation-nya:
- Single binary, no deps (Rust ✓)
- All-in-one (vs Nuclei + Dalfox + sqlmap + ssrf-king)
- Full disclosure philosophy (vs Burp's "filter noise")
- Negative-control baked in

To be **BEST**, butuh Tier 1 selesai. To be **competitive**, udah sekarang pun bisa.
Onii-chan mau gas Tier 1 dulu, atau ada bagian spesifik yang lo mau prioritaskan?
