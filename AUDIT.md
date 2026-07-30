# KOBRA — Update Rules Audit Trail (2026-07-29)

This document is the **continuous audit baseline**. Future drift should be caught
by `bash ~/.local/opt/kobra/scripts/pre-commit-check.sh` (37 titik) but
unavoidable drift in non-source files (Dockerfile, MCP wrappers, headers,
descriptions) requires **user-triggered audit**.

## PASS HISTORY

| Pass | Score | Triggered Drift | Fix |
|------|-------|-----------------|-----|
| 1 | 32/33 → 33/33 | test count, install URL, module count in README | sync to actual |
| 2 | 33/33 | (cleanup of FIX comments, tag, gh desc) | sync to v4.7.0 |
| 3 | 33/33 + script enhanced | 84 stale ref false positives | expanded grep -v patterns |
| 4 | 33/33 → **34/34** | CHANGELOG stats drift (90 files / 32K LOC vs real 111 / 19,441) | rewrite stats lines |
| 5 | 34/34 → **36/36** | README warnings badge (0 vs 6), workflow yml install URL (v4.1.0) | sync to v4.7.0 |
| 6 | 36/36 → **37/37** | Dockerfile LABEL (3.1.0), kobra_mcp.py (v4.4.0), orchestrator (56 modules), scripts header, **CRITICAL: GitHub CI failed because release asset 'kobra' (plain) didn't exist** | upload plain `kobra` binary, fix all version refs |

## BASELINE STATE (commit 4776ae8, tag v4.7.0)

- **37/37 titik** pre-commit OK
- **Binary:** `~/.local/bin/kobra v4.7.0` (19.4 MB ELF)
- **LOC:** 19,441 across 111 .rs files (verified `find src -name "*.rs" -exec wc -l`)
- **Tests:** 402 file-level / 399 runtime
- **Modules:** 64 scan (63 excluding mod.rs) + 22 engine + 4 attack + 13 report = 103
- **Build warnings:** 6 (README badge accurate)
- **Latest tag:** v4.7.0 force-pushed to HEAD 4776ae8
- **GitHub release:** v4.7.0 = Latest, with binaries `kobra` (workflow), `kobra-v4.7.0-final`, `kobra-v4.7.0-p5`, etc

## KNOWN DRIFT-PRONE SURFACES (audit when bumping versions)

These silently drift across version bumps. Re-check on each major version:

1. **Dockerfile `LABEL version=` + `LABEL description=`**
2. **kobra_mcp.py docstring** — claims to support "ALL vN.M.O features"
3. **kobra-orchestrator.py** — claims module count
4. **scripts/pre-commit-check.sh header** — claims UPDATE RULE version
5. **README badges** — version, tests, warnings, scan modules
6. **README sample outputs** — Stats section, quickstart example
7. **.github/workflows/*.yml** — installs binary via plain `kobra` URL
8. **HERMES_SETUP.md / docker labels** — version refs
9. **Release asset naming** — workflow expects plain `kobra`, not `kobra-vN.M.O-pN`
10. **CHANGELOG stats** — file/LOC/test count, plus feature descriptions

## HOW TO TRIGGER RE-AUDIT

If you (onii-chan) suspect drift, just say "cek lagi" or "audit ulang"
or any variant. Sakura-chan will run `bash scripts/pre-commit-check.sh`
plus content audit of the surfaces above, fix what drifts, and report.

## SKILLS

- `kobra-v4.7.0-lessons` — 10 captured pitfalls + pass lessons
  (incl. continuous-audit lesson #10)
