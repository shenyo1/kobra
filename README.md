<div align="center">

```
   ▄█  █▄▄▄▄ ▄███▄   ██   █▄▄▄▄
  ██  ██▀▀▀▀ ██   █  █ █  █  ▄▀
  ██  ██      ██   █ █▄▄█ █▀▀▌
  ██  ██      ▀████▀ █  █ █  █
  ▀█   ▀        ▀        █  █
```

# 🐍 KOBRA — Bug Bounty Scanner

### The Overpowered All-in-One Scanner for Authorized Security Testing

[![Version](https://img.shields.io/badge/version-v4.7.0-blue.svg)](https://github.com/shenyo1/kobra/releases/tag/v4.7.0)
[![Tests](https://img.shields.io/badge/tests-402%20passing-brightgreen.svg)]()
[![Warnings](https://img.shields.io/badge/warnings-0-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org/)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](https://github.com/shenyo1/kobra/actions)

**63 scan modules** · **22 engines** · **13 report formats** · **4 attack plugins** · **402 tests** · **~19,500 LOC**

[Features](#-features) · [Quick Start](#-quick-start) · [Usage](#-usage) · [MCP](#-mcp-integration) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

---

## 🎯 What is KOBRA?

KOBRA is a **defensive security scanner** designed for authorized bug bounty hunters and penetration testers. Built in Rust for performance and reliability, KOBRA combines vulnerability scanning, attack chain detection, and intelligent triage into a single binary.

```
Target → KOBRA → Findings (JSON/MD/HTML/SARIF)
                    ↓
              MCP Server → AI Agents (auto-exploit chains)
```

### Why KOBRA?

| Other scanners | KOBRA |
|---|---|
| ❌ Single vulnerability class per tool | ✅ **63 scan modules** in one binary |
| ❌ Need multiple separate tools | ✅ Recon → Scan → Triage → Report |
| ❌ Tons of false positives | ✅ **AI Triage** + statistical detection |
| ❌ Manual report writing | ✅ Multi-format output (SARIF, HTML, MD, JSON) |
| ❌ CI integration is hard | ✅ **Native MCP** + GitHub Actions |
| ❌ Manual exploitation chains | ✅ **Auto chain detection** |

---

## ✨ Features

### 🔍 Scan Modules (58)
- **Web**: XSS, SQLi, SSRF, SSTI, RCE, XXE, Command Injection
- **API**: IDOR, Mass Assignment, GraphQL, OAuth, JWT, OpenAPI/Swagger
- **Auth**: Magic-link ATO, Multi-tenant, Session, Cookie
- **Modern**: HTTP Smuggling v2, WebSocket, gRPC, Prototype Pollution
- **Recon**: Subdomain Takeover (70+ providers), JS Bundle Analysis, Source Maps
- **Specialized**: AI Prompt Injection, Payment Logic, Email-only ATO

### ⚙️ Engines (14)
- **AI Triage** — LLM-powered FP filter + fix suggestions
- **Statistical Detection** — anti-False Positive timing analysis
- **Attack Chains** — auto-detect XSS→ATO, SSRF→cloud, etc.
- **Template Engine** — YAML/JSON vuln checks
- **Nuclei Compat** — run existing nuclei templates
- **Diff Engine** — compare scans over time
- **Watch Mode** — periodic rescan + webhook alerts

### 📊 Reports (10)
JSON · Markdown · HTML Dashboard · SARIF v2.1 · PoC Bash Scripts · Webhooks (Slack/Discord/Generic) · Diff Dashboard · Plain Output · Simple (Bahasa ID)

---

## 🚀 What's New in v4.4.0

### 🛡️ **5 Lessons from Real-World Sumopod Engagement** (2026-07-29)
v4.3.0 missed several findings during real-world bug-bounty engagement. v4.4.0 fixes all 5:
- **`cloudflare_ranges.rs`** (NEW): detects Cloudflare-fronted IPs and DOWNGRADES subdomain takeover FPs (Lesson 1 — Sumopod api-gate-v2 false positive)
- **`ai_gateway.rs`** (NEW): detects LiteLLM/vLLM/OpenAI-compatible gateways (Lesson 4 — Sumopod ai.sumopod.com LiteLLM discovery)
- **`dns_pivot.rs`** (NEW): groups subdomains by IP, probes direct-origin infrastructure (Lesson 3 + 5 — Sumopod separate infra on different IPs)
- **`auth_flow.rs`** (NEW): classifies JWT/cookie/Basic/OAuth/API-key auth (Lesson 2 — beyond just Bearer tokens)
- All modules wired into main scan pipeline + have tests (310 total, +43 vs v4.3.0)

### 🔐 **Auth-Aware Probing (v4.3.0)**
Closes the gap where --auth flag was extracted but never used by modules:
- **`auth_aware.rs`** (NEW): probes 27 auth-protected paths when --auth configured
- Detects IDOR/BAC surface in authenticated endpoints
- Emits informational finding when --auth NOT configured (so user knows to opt in)
- Tests: 2 new (paths_count, paths_have_api_prefix)

### 🎯 **Stack-Specific Payloads (new module)**
Tailors payloads to detected framework instead of generic:
- **`stack_payloads.rs`** (NEW): 4 payload categories (magic-link, sqli, graphql, xss)
- Framework-specific: Angular uses `/api/v1/auth/magic`, React uses `data:text/html`, PHP uses UNION SELECT
- Used by downstream scanners to pick right payloads
- Tests: 7 new (Angular, PHP, default UNION, Angular `/gql`, React `data:`, MAGIC-LINK routing, unknown=None)

### 🔬 **Stack Fingerprint Wired**
- `run_all()` now calls fingerprint FIRST, logs `framework_hint` to stderr
- Stack-aware payload database ready for full integration

## 🚀 What's New in v4.2.0

### 🛡️ **SPA Fallback Detection (Negative-Control)**
Eliminates ~10% false positives caused by SPA frameworks (Angular/Vue/React) returning 200 + HTML for any unknown path:
- `exposed_files.rs`: FNV-1a body hash compared against `/` baseline — if hash matches, it's SPA fallback, skip
- `research2026.rs`: Magic-link payload now skips HTML responses (only JSON triggers)
- `multitenant.rs`: Cross-tenant probe skips HTML responses
- `ai_triage.rs`: New FP patterns for SPA fallback across EXPOSED, AUTH, GRAPHQL, OAUTH, MULTITENANT

### 🤖 **Auto-Triage (crazy mode)**
AI Triage now runs automatically in crazy mode (no `--triage` flag needed). Stealth/normal still require explicit opt-in. Filters out FP patterns learned from Juice Shop benchmark.

### 🧬 **Stack Fingerprint (new module)**
Detects SPA framework (Angular, React, Next.js, Vue, Nuxt, Svelte, Ember) + server (Express, nginx, Apache, PHP) + API style. Used by downstream modules to select stack-specific payloads instead of generic ones.

### 🧪 **Benchmark Validation**
Re-tested vs OWASP Juice Shop: **3 magic-link FPs eliminated**, security.txt correctly downgraded from Critical to Medium, /metrics correctly identified as REAL Prometheus exposure.

---

## 🚀 Quick Start

### One-line install

```bash
# Download latest release
curl -L https://github.com/shenyo1/kobra/releases/download/v4.7.0/kobra -o ~/.local/bin/kobra
chmod +x ~/.local/bin/kobra

# Verify
kobra --version
# 🐍 kobra 4.4.0
```

### First scan (1 minute)

```bash
# ⚠️ ONLY on authorized targets (bug bounty programs, your own lab)
kobra -t https://your-authorized-target.com -m crazy --no-confirm --simple
```

Sample output:
```
🐍 KOBRA v4.4.0 — all-in-one BB scanner (OVERPOWERED)
[*] mode=Crazy concurrency=60 timeout=15s

[+] https://target.com → 23 finding(s)
  🔴 2 High
  🟠 5 Medium
  🟡 10 Low
  ℹ️  6 Info

[*] report written to ./kobra-results.json
[+] HTML dashboard written to ./report.html
[+] SARIF report written to ./kobra.sarif
```

---

## 📖 Usage

### Basic

```bash
# Mode selection
kobra -t https://target.com -m stealth    # Slow, low-detection
kobra -t https://target.com -m normal     # Balanced
kobra -t https://target.com -m crazy      # Aggressive (recommended for BB)

# Multiple targets
kobra -t https://a.com,https://b.com -m crazy

# Output formats
kobra -t https://target.com -m crazy \
  --json -o results.json \
  --html report.html \
  --md report.md \
  --sarif kobra.sarif
```

### Authenticated Scanning

```bash
# Single auth
kobra -t https://api.target.com \
  --auth "https://api.target.com/login|username=admin@test.com&password=***"

# Multi-session (IDOR detection)
kobra -t https://api.target.com \
  --auth "https://api/login|user=A" \
  --auth2 "https://api/login|user=B"
```

### Advanced

```bash
# Use nuclei templates
kobra -t https://target.com --nuclei-dir ~/nuclei-templates/

# Custom wordlist
kobra -t https://target.com --wordlist ~/SecLists/common.txt

# Browser scan (DOM XSS, SPA crawl)
kobra -t https://target.com --browser --screenshot-dir ./evidence

# AI Triage (auto-filter FP)
kobra -t https://target.com --triage

# Scan profiles (preset configs)
kobra -t https://target.com --profile bb       # Bug bounty
kobra -t https://target.com --profile pentest  # Pen test
kobra -t https://target.com --profile quick    # Quick triage
kobra -t https://target.com --profile ci       # CI/CD

# Diff against previous scan
kobra -t https://target.com --diff-baseline previous.json

# Watch mode (periodic rescan)
kobra -t https://target.com --watch --watch-interval 15 --discord-webhook <URL>

# Beginner-friendly output (Bahasa Indonesia)
kobra -t https://target.com --simple --no-confirm
```

**Full flag list:** see [`HERMES_SETUP.md`](HERMES_SETUP.md)

---

## 🤖 MCP Integration

KOBRA exposes 8 tools via [Model Context Protocol](https://modelcontextprotocol.io/) for AI agents:

| Tool | Function |
|------|----------|
| `scan_target` | Run full scan (all flags exposed) |
| `idor_scan` | Multi-session IDOR testing |
| `diff_scan` | Compare with previous baseline |
| `run_orchestrator` | Full pipeline (recon → scan → nuclei → ffuf → dalfox) |
| `chain_report` | Compose attack chains from findings |
| `api_break` | API-specific testing (REST/GraphQL) |
| `cloud_enum` | Cloud metadata enumeration (AWS/Azure/GCP) |
| `ctf_payloads` | Generate CTF payloads |

### Setup

```bash
pip install mcp
hermes mcp add kobra --command python3 --args ~/.local/opt/kobra/kobra_mcp.py
hermes mcp test kobra
# ✓ Connected (700ms)
# ✓ Tools discovered: 8
```

Then in your AI agent:
> "Pindai https://target.com pakai KOBRA"

---

## 🐳 Docker

```bash
docker build -t kobra:latest .
docker run -v $(pwd)/results:/workspace kobra:latest \
  -t https://target.com -m crazy --triage \
  -o /workspace/results.json
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│  CLI (clap) / MCP Server (Python)            │
└─────────────────┬───────────────────────────┘
                  ↓
┌─────────────────────────────────────────────┐
│  Recon Module (crt.sh + subfinder + httpx)   │
└─────────────────┬───────────────────────────┘
                  ↓
┌─────────────────────────────────────────────┐
│  Parallel Scan Engine                        │
│  ┌─────────┬─────────┬─────────┬─────────┐    │
│  │ Module1 │ Module2 │ Module3 │  ...   │    │
│  │  XSS    │  SQLi   │  SSRF   │        │    │
│  └─────────┴─────────┴─────────┴─────────┘    │
└─────────────────┬───────────────────────────┘
                  ↓
┌─────────────────────────────────────────────┐
│  AI Triage + Chain Detection                  │
└─────────────────┬───────────────────────────┘
                  ↓
┌─────────────────────────────────────────────┐
│  Reports (JSON/MD/HTML/SARIF/Webhooks)        │
└─────────────────────────────────────────────┘
```

---

## 📊 Stats

```
🐍 KOBRA v4.4.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scan modules:    59 (+4 v4.4.0: cloudflare_ranges, ai_gateway, dns_pivot, auth_flow)
Payload modules: 1 (stack_payloads)
Engine modules:  19
Report formats:  12
Tests:           313 (+24 since v4.3.0)
Source LOC:      ~25,500
Binary size:     ~19MB
CI:              ✓ passing (GitHub Actions)
Releases:        21 (v1.0.0 → v4.4.0)
License:         MIT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## ⚠️ Ethics & Legal Use

> **KOBRA is for AUTHORIZED security testing ONLY.**

✅ Authorized use cases:
- Official bug bounty programs (HackerOne, Bugcrowd, Sumopod, etc.)
- Penetration tests with written authorization
- CTF competitions
- Educational lab environments

❌ Unauthorized use is:
- **ILLEGAL** (CFAA, UU ITE, Computer Misuse Act, etc.)
- Subject to criminal prosecution
- A violation of platform Terms of Service

**Always obtain written authorization BEFORE testing.**

See [LICENSE](LICENSE) for full ethical use notice and [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Mandatory rules for PRs:**
1. Follow the **negative-control discipline** (always fetch baseline before flagging)
2. Update all 13 documentation points (see UPDATE RULE in CONTRIBUTING.md)
3. Add unit tests (positive + negative cases)
4. Zero warnings, zero old version refs

---

## 📜 License

[MIT License](LICENSE) — see file for full text.

---

## 🙏 Acknowledgments

- Inspired by **nuclei**, **ffuf**, **dalfox**, **sqlmap**, and **burp suite**
- Built with **Rust** + ❤️
- Thanks to all **bug bounty hunters** keeping the internet safer

---

<div align="center">

**[⬆ Back to Top](#-kobra--bug-bounty-scanner)**

Made with 🐍 + ☕ + 🌸 by [shenyo1](https://github.com/shenyo1)

</div>