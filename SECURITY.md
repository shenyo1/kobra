# Security Policy

## ⚠️ Reporting a Vulnerability

If you discover a security vulnerability in **KOBRA itself**, please report it **privately**:

- **GitHub Security Advisories**: https://github.com/shenyo1/kobra/security/advisories/new
- **Email**: Use GitHub private vulnerability reporting (preferred)

**Please DO NOT open public issues for security bugs.**

## 🔒 What to Include

When reporting a vulnerability, please include:

1. **Description** of the vulnerability
2. **Steps to reproduce** with example commands
3. **Impact assessment** (what can attacker do?)
4. **Affected versions** (which KOBRA versions are vulnerable?)
5. **Suggested fix** (if you have one)

## ⏱️ Response Timeline

- **Initial response**: within 48 hours
- **Triage**: within 1 week
- **Fix released**: within 2-4 weeks (severity dependent)

## 🛡️ Security Considerations When Using KOBRA

### Legal Use Only
KOBRA is a **defensive security tool** intended for:
- ✅ Authorized penetration testing
- ✅ Bug bounty programs (HackerOne, Bugcrowd, etc.)
- ✅ CTF competitions
- ✅ Educational lab environments

### ⚠️ Unauthorized Use is Illegal
Using KOBRA against systems you do not own or have **explicit written permission** to test is:
- Illegal in most jurisdictions (CFAA, UU ITE, Computer Misuse Act, etc.)
- A violation of Sumopod, HackerOne, Bugcrowd Terms of Service
- Subject to criminal prosecution

**Always obtain written authorization BEFORE testing.**

### 🛡️ Operational Security (OpSec)

When using KOBRA:

1. **Isolate your testing** — use VPN/Tor when appropriate
2. **Respect rate limits** — don't DoS the target
3. **Handle data carefully** — findings may contain sensitive info
4. **Don't exfiltrate** — only verify existence, don't download user data
5. **Follow responsible disclosure** — give maintainers time to fix before public disclosure

### 🤝 Coordinated Disclosure

We follow **90-day coordinated disclosure**:
1. Day 0: Vulnerability reported privately
2. Day 1-7: Triage + initial fix
3. Day 8-89: Patch development + testing
4. Day 90: Public disclosure + CVE if applicable

## 📋 Security Updates

Security fixes are released as:
- **Patch versions** (v3.3.2 → v3.3.3) for low/medium severity
- **Minor versions** (v3.3 → v3.4) for high/critical severity
- Announced in GitHub Releases + Security Advisories

Subscribe to releases: https://github.com/shenyo1/kobra/releases

## 🏆 Hall of Fame

Security researchers who reported vulnerabilities in KOBRA itself:
- (None yet — be the first!)

---

**Thank you for helping keep KOBRA and its users safe! 🛡️**