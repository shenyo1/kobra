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

[![Version](https://img.shields.io/badge/version-v4.0.0-blue.svg)](https://github.com/shenyo1/kobra/releases/tag/v4.0.0)
[![Tests](https://img.shields.io/badge/tests-194%20passing-brightgreen.svg)]()
[![Warnings](https://img.shields.io/badge/warnings-0-brightgreen.svg)]()
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org/)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](https://github.com/shenyo1/kobra/actions)

**56 scan modules** · **20 engines** · **12 report formats** · **267 tests** · **~22,500 LOC**

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
| ❌ Single vulnerability class per tool | ✅ **56 modules** in one binary |
| ❌ Need multiple separate tools | ✅ Recon → Scan → Triage → Report |
| ❌ Tons of false positives | ✅ **AI Triage** + statistical detection |
| ❌ Manual report writing | ✅ Multi-format output (SARIF, HTML, MD, JSON) |
| ❌ CI integration is hard | ✅ **Native MCP** + GitHub Actions |
| ❌ Manual exploitation chains | ✅ **Auto chain detection** |

---

## ✨ Features

### 🔍 Scan Modules (56)
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

## 🚀 Quick Start

### One-line install

```bash
# Download latest release
curl -L https://github.com/shenyo1/kobra/releases/download/v4.0.0/kobra -o ~/.local/bin/kobra
chmod +x ~/.local/bin/kobra

# Verify
kobra --version
# 🐍 kobra 3.3.2
```

### First scan (1 minute)

```bash
# ⚠️ ONLY on authorized targets (bug bounty programs, your own lab)
kobra -t https://your-authorized-target.com -m crazy --no-confirm --simple
```

Sample output:
```
🐍 KOBRA v4.0.0 — all-in-one BB scanner (OVERPOWERED)
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
🐍 KOBRA v4.0.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scan modules:    56
Engine modules:  20
Report formats:  12
Tests:           194 (0 failed, 0 warnings)
Source LOC:      ~22,500
Binary size:     ~19MB
CI:              ✓ passing (GitHub Actions)
Releases:        16+ (v1.0.0 → v4.0.0)
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