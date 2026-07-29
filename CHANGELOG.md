# Changelog

All notable changes to KOBRA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]


## [4.4.0] - 2026-07-29 — Sumopod Lessons

### Added
- **cloudflare_ranges.rs** — detects 14 Cloudflare IP ranges, downgrades subdomain takeover FPs (Lesson 1 — Sumopod api-gate-v2 false positive)
- **ai_gateway.rs** — detects LiteLLM/vLLM/OpenAI-compatible gateways (Lesson 4 — Sumopod ai.sumopod.com)
- **dns_pivot.rs** — groups subdomains by IP, probes direct-origin infrastructure (Lesson 3 + origin probe Lesson 5)
- **auth_flow.rs** — classifies JWT/cookie/Basic/OAuth/API-key auth schemes (Lesson 2 — beyond Bearer tokens)

### Fixed
- **v4.4.0 hotfix** — ai_gateway base URL parsing + severity calibration

### Stats
- 91 modules total: 59 scan + 19 engine + 12 report (+4 from v4.3.0)
- 313 tests passing (+24 from v4.3.0)
- ~25,500 LOC

## [4.3.0] - 2026-07-29 — Auth-aware + Stack payloads

### Added
- **auth_aware.rs** — probes 27 auth-protected paths when `--auth` configured (closes gap where flag was extracted but unused)
- **stack_payloads.rs** — 4 framework-specific payload categories (magic-link, sqli, graphql, xss)
  - Angular: `/api/v1/auth/magic` + `data:text/html`
  - React: `data:text/html` payload
  - PHP: UNION SELECT variants
- **stack_fingerprint.rs integration** — `run_all()` calls fingerprint FIRST, logs `framework_hint` to stderr

### Stats
- 87 modules total (+2 from v4.2.0): 55 scan + 19 engine + 12 report
- 286 tests passing (+19 from v4.2.0)

## [4.2.0] - 2026-07-29 — SPA Fallback + Auto-triage

### Added
- **exposed_files.rs** — FNV-1a body hash vs `/` baseline; SPA fallback skip (eliminates ~10% FPs)
- **research2026.rs** — Magic-link payload JSON-only trigger (skips HTML)
- **multitenant.rs** — Cross-tenant probe skips HTML responses
- **Stack Fingerprint** — detects SPA framework (Angular/React/Next.js/Vue/Nuxt/Svelte/Ember) + server + API style
- **Auto-Triage** — runs automatically in crazy mode (no `--triage` flag); stealth/normal still opt-in

### Fixed
- **ai_triage.rs** — new FP patterns for SPA fallback (EXPOSED, AUTH, GRAPHQL, OAUTH, MULTITENANT)

### Verified
- Juice Shop benchmark: 3 magic-link FPs eliminated, security.txt downgraded Critical→Medium, `/metrics` correctly identified as real Prometheus exposure

### Stats
- 85 modules total (+2 from v4.1.0): 53 scan + 19 engine + 13 report
- 267 tests passing (+43 from v4.1.0)

## [4.1.0] - 2026-07-29 — Extensions

### Added
- **Historical Tracking** (`src/engine/historical.rs`) — scan history DB with fingerprint dedup + time-series + regression detection (5 tests)
- **Smart Dedup** (`src/engine/dedup.rs`) — within-scan similarity grouping with severity preservation (9 tests)
- **Dashboard v2** (`src/report/dashboard_v2.rs`) — interactive HTML with live search, filter, sort, chart, JSON/CSV export, fully offline (6 tests)
- **Plugin Marketplace** (`src/engine/plugin_v2.rs`) — install/uninstall/load plugins in 4 categories × 4 pattern kinds (8 tests)
- **Multi-language Reports** (`src/report/i18n.rs`) — English, Indonesian, Japanese, Chinese translations (9 tests)

### Stats
- 56 scan + 20 engine + 12 report = 88 modules (+8 from v4.0)
- 267 tests passing (+35 from v4.0)
- 17 releases (was 16)

[4.1.0]: https://github.com/shenyo1/kobra/compare/v4.0.0...v4.1.0

## [4.0.0] - 2026-07-29 — Intelligence Layer

### Added
- **OOB Callback Engine** (`src/oob/mod.rs`) — blind SSRF/RCE/XXE/SQLi detection via DNS/HTTP callbacks
- **Smart Mutation Engine v2** (`src/engine/mutator_v2.rs`) — context-aware payload mutation with WAF bypass
- **Exploit Verification Engine** (`src/engine/exploit_verify.rs`) — non-destructive vuln verification

### Stats
- 54 scan + 16 engine + 10 report = 80 modules
- 232 tests passing (was 194)
- 16 releases (was 15)

[4.0.0]: https://github.com/shenyo1/kobra/compare/v3.3.2...v4.0.0

## [3.3.2] - 2026-07-29 — CI/SARIF Hotfix

### Fixed
- **CI workflow**: added `security-events: write` permission (was causing SARIF upload failures)
- **SARIF URI scheme**: now uses `file://` per SARIF spec (was `https://` which GitHub Code Scanning rejects)
- **CodeQL action**: upgraded v3 → v4 (v3 deprecated Dec 2026)
- **Workflow guards**: added `hashFiles()` check before SARIF upload
- **JSON parsing**: handle dict vs list format in results.json
- **Tag without release**: GitHub Actions now downloads proper binary (real release created)

### Verified
- CI passing in 1m16s (was failing 10+ consecutive runs)

## [3.3.1] - 2026-07-29 — SQLi False Positive Hotfix

### Fixed
- **Time-based SQLi detection**: was using p90 (single outlier poisoned result)
- Now uses **median + 3-of-5 slow samples** rule (anti-FP)

### Verified
- Manual 20-iter timing test: ai.sumopod.com SQLi = FALSE POSITIVE confirmed
- New statistical method eliminates this FP

## [3.3.0] - 2026-07-29 — AI Triage + JS Deep + PostgREST

### Added
- **Statistical SQLi detection** (`is_delayed_strong` in `src/engine/timing.rs`)
- **Supabase JWT regex** in `src/scan/js_secret_mine.rs`
- **New module**: `src/scan/postgrest.rs` — PostgREST/Supabase table disclosure scanner (41 probes)
- **Cron job**: auto CVE updates

## [3.2.0] - 2026-07-29 — Diff Dashboard + WS Deep + Profiles

### Added
- **Diff Dashboard HTML** (`src/report/diff_dashboard.rs`) — visual before/after comparison
- **WS Fuzzing v2** (`src/scan/ws_deep.rs`) — WebSocket deep analysis
- **Scan Profiles** (`src/engine/profiles.rs`) — bb/pentest/quick/ci presets
- **CLI flags**: `--profile`, `--profile-list`

## [3.1.0] - 2026-07-29 — Takeover v2 + Rate Bypass + CI/CD + Docker

### Added
- **Subdomain Takeover v2** — 70+ provider fingerprints
- **Rate Limit Bypass Engine** — IP/method/path/encoding tricks
- **GitHub Actions CI** (`.github/workflows/kobra-scan.yml`)
- **Docker containerization** (`Dockerfile` — multi-stage build)

### Changed
- v3.0.0 → v3.1.0: 12→13 engine modules

## [3.0.0] - 2026-07-29 — AI Triage + JS Deep + API Schema Fuzzing

### Added
- **AI Triage Engine** (`src/engine/ai_triage.rs`) — FP filter + CWE/CVSS/fix suggestions
- **JS Deep Analysis** (`src/scan/js_deep.rs`) — webpack/vite bundle parsing
- **API Schema Fuzzing** (`src/scan/api_schema_fuzz.rs`) — OpenAPI/Swagger auto-test
- **CLI flag**: `--triage`

### Changed
- Major version bump — AI-powered features

## [2.0.0] - 2026-07-28 — ROADMAP 100% COMPLETE

### Added
- **Diff-Based Scan** (`--diff-baseline`)
- **Cross-Target Chain Detection**
- **Watch Mode** (`--watch`)
- All 18 roadmap features complete

## [1.0.0] - 2026-07-27 — Initial Release

### Added
- 39 scan modules + 5 engine + 7 report formats
- 89 tests passing
- Basic CLI, JSON output, MCP server integration

---

## Types of Changes

- `Added` — new features
- `Changed` — changes in existing functionality
- `Deprecated` — soon-to-be removed features
- `Removed` — now removed features
- `Fixed` — any bug fixes
- `Security` — vulnerability fixes

[Unreleased]: https://github.com/shenyo1/kobra/compare/v3.3.2...HEAD
[3.3.2]: https://github.com/shenyo1/kobra/compare/v3.3.1...v3.3.2
[3.3.1]: https://github.com/shenyo1/kobra/compare/v3.3.0...v3.3.1
[3.3.0]: https://github.com/shenyo1/kobra/compare/v3.2.0...v3.3.0
[3.2.0]: https://github.com/shenyo1/kobra/compare/v3.1.0...v3.2.0
[3.1.0]: https://github.com/shenyo1/kobra/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/shenyo1/kobra/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/shenyo1/kobra/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/shenyo1/kobra/releases/tag/v1.0.0
[4.4.0]: https://github.com/shenyo1/kobra/compare/v4.3.0...v4.4.0
[4.3.0]: https://github.com/shenyo1/kobra/compare/v4.2.0...v4.3.0
[4.2.0]: https://github.com/shenyo1/kobra/compare/v4.1.1...v4.2.0
[4.0.0]: https://github.com/shenyo1/kobra/compare/v3.3.2...v4.0.0