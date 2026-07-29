# Contributing to KOBRA

First off, thank you for considering contributing to KOBRA! 🐍

## 🎯 Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct.
By participating, you are expected to uphold this code.

## 🚀 How to Contribute

### Reporting Bugs
- Use the GitHub Issues tracker
- Use the **Bug Report** issue template
- Include KOBRA version (`kobra --version`)
- Include command + output that reproduces the bug
- Include target type (if reporting FP/TP)

### Suggesting Features
- Use the **Feature Request** template
- Explain the use case (not just "add X module")
- Consider if it fits the **negative-control discipline** principle

### Pull Requests
1. **Fork** the repo
2. **Create a branch** from `master`: `git checkout -b feature/amazing-thing`
3. **Follow the rules** below
4. **Run tests**: `cargo test --release`
5. **Run audit**: zero warnings, zero old version refs
6. **Submit PR** with clear description

## 📋 KOBRA Development Rules (MANDATORY)

### 1. Negative-Control Discipline (FP prevention)
EVERY detection module MUST:
- Fetch a **baseline** (same URL, no payload/inert marker) FIRST
- Only flag if evidence appears in PAYLOAD response but NOT baseline
- Use unique markers (not common in static HTML like "49", "7*7")

```rust
// ❌ WRONG
if body.contains("49") { Finding::new(...); }

// ✅ RIGHT
let baseline = http.get(&url).await?;
let probe = http.get(&url_with_payload).await?;
if probe.body.contains(MARKER) && !baseline.body.contains(MARKER) {
    Finding::new(...);
}
```

### 2. UPDATE RULE 13 TITIK (Enforced since 2026-07-29)
Every change MUST update ALL of these (or your PR will be rejected):
- [ ] `Cargo.toml` — version bump
- [ ] `src/main.rs` — `#[command(... about = ...)]` AND ASCII banner
- [ ] `src/report/webhook.rs` — `"footer": "KOBRA vX.Y"`
- [ ] `README.md` — module counts + version
- [ ] `HERMES_SETUP.md` — download URL tag + tool count
- [ ] `kobra_mcp.py` — tool list + new params
- [ ] `kobra-orchestrator.py` — vuln modules count
- [ ] Skill `kobra-bb-scanner` — version, modules, MCP tools
- [ ] Skill `kobra-lessons` — module count
- [ ] Skill `kobra-operations` — version refs
- [ ] `MEMORY.md` + `USER.md` (Hermes profile)
- [ ] `git tag vX.Y.Z && git push --tags`
- [ ] `gh release create vX.Y.Z --notes-file ... <binary>`

**Final gate:** `grep -rn "v1\.[0-9]\|6 tools\|9 vuln\|5 engine" .` must return ZERO.

### 3. Test Coverage
Every module MUST have at least 1-2 unit tests:
- Positive case (detects real vuln)
- Negative case (no FP on clean URL)

### 4. Naming Conventions
- Modules: `snake_case.rs`
- Functions: `snake_case`
- Constants: `SCREAMING_SNAKE_CASE`
- Findings: `Severity::High/Medium/Low/Info`, `category` = `SCREAMING_SNAKE_CASE`

## 🧪 Testing Locally

```bash
# Build
source $HOME/.cargo/env
cargo build --release

# Test (must pass: 100% green)
cargo test --release

# Verify zero warnings
cargo build --release 2>&1 | grep -c "^warning:"   # should be 0

# Run audit
grep -rn "v[0-9]\.[0-9]\.[0-9]" --include="*.rs" --include="*.md" src/ README.md
# Verify all references match current version

# Test on vulnerable target (use authorized targets only!)
./target/release/kobra -t https://your-target.com -m normal --no-confirm
```

## 📚 Code Style

- Rust: Follow standard rustfmt (`cargo fmt`)
- Comments: explain WHY, not WHAT
- Public APIs: document with doc comments
- Error handling: use `anyhow::Result` for module scan fns

## 🎯 Areas Looking for Contribution

- 🟢 **EASY**: New module for specific vuln class (follow existing patterns)
- 🟡 **MEDIUM**: Improve FP rate for existing modules
- 🔴 **HARD**: New detection technique (e.g. taint tracking, ML-based)

## 📞 Questions?

Open a GitHub Discussion or contact via:
- GitHub: https://github.com/shenyo1
- Issues: Use bug/feature templates

---

**By contributing, you agree that your contributions will be licensed under MIT License.**