---
name: Bug Report
about: Report a bug in KOBRA scanner
title: '[BUG] '
labels: bug
assignees: ''
---

## 🐛 Bug Description

Clear and concise description of what the bug is.

## 📋 Environment

- **KOBRA version**: (`kobra --version`)
- **OS**: (e.g., Ubuntu 22.04, macOS 14, Windows 11)
- **Target type**: (e.g., public website, lab target, CTF)
- **Mode**: (stealth / normal / crazy)

## 🔄 Steps to Reproduce

```bash
kobra -t https://target.com -m crazy --no-confirm [other flags]
```

## ✅ Expected Behavior

What you expected to happen.

## ❌ Actual Behavior

What actually happened. Include full error output.

## 📸 Evidence (if applicable)

- Module name that misbehaved
- Finding payload
- Raw HTTP request/response if relevant

## 🎯 Severity Assessment

- [ ] False Positive (KOBRA flagged something that isn't a vuln)
- [ ] False Negative (KOBRA missed a real vuln)
- [ ] Bug in code/CLI
- [ ] Bug in documentation
- [ ] Other (describe)

## 💭 Additional Context

Any other context, screenshots, or related issues.