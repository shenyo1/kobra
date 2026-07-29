# Changelog

All notable changes to KOBRA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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