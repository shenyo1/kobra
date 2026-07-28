#!/usr/bin/env python3
"""
KOBRA Web-Pro — Vulnerability Chain Composer
Reads report.json from kobra-orchestrator.py, correlates findings into attack
chains (low-sev -> critical). Rule-based, from web-hacking-pro methodology.

Usage:
  python3 chain.py --report engagement/report.json --out engagement/chains.md

Rules (entry -> pivot -> impact):
  XSS (HIGH)            -> steal admin cookie / CSRF token        -> Account Takeover
  SSRF + 169.254.169.254-> IMDS role credentials                  -> Full Cloud Compromise
  Traversal/LFI (HIGH)  -> read /etc/passwd / log poison         -> RCE Prep
  AUTH JWT alg:none     -> forge admin claims                    -> Privilege Escalation
  Source-leak (.git)    -> secrets -> DB creds                   -> Data Breach
  IDOR (HIGH)           -> cross-tenant data access              -> Data Breach
"""
import argparse
import json
from collections import defaultdict


# (matches category/substr, pivot description, impact, severity_boost)
RULES = [
    ("XSS", "steal admin session cookie via injected JS", "Account Takeover", "CRITICAL"),
    ("SSRF", "probe cloud metadata 169.254.169.254 for IMDS creds", "Full Cloud Compromise", "CRITICAL"),
    ("TRAVERSAL", "read sensitive files (/etc/passwd) or poison logs", "RCE Prep", "CRITICAL"),
    ("RCE", "direct OS command execution confirmed", "Remote Code Execution", "CRITICAL"),
    ("AUTH", "bypass auth / forge JWT (alg:none) / IDOR on privileged path", "Privilege Escalation", "CRITICAL"),
    ("GRAPHQL", "introspection exposes full schema -> query arbitrary data", "Information Disclosure", "HIGH"),
    ("PROTOPOLL", "prototype pollution -> client-side RCE / auth bypass", "Client-Side RCE", "HIGH"),
    ("NUCLEI", "known CVE / misconfig detected by template", "Known Vulnerability", "HIGH"),
    ("FUZZ", "hidden endpoint/param discovered", "Attack Surface Expansion", "MEDIUM"),
]


def load(report_path):
    with open(report_path) as f:
        return json.load(f)


def compose(report):
    findings = report.get("findings", [])
    by_host = defaultdict(list)
    for f in findings:
        by_host[f.get("target", "?")].append(f)

    chains = []
    for host, fList in by_host.items():
        cats = {f.get("category", "").upper() for f in fList}
        for trigger, pivot, impact, sev in RULES:
            if trigger in cats:
                # find the specific finding(s) that triggered
                trig = [f for f in fList if f.get("category", "").upper() == trigger]
                poc = trig[0].get("payload", "") if trig else ""
                chains.append({
                    "host": host,
                    "entry": trigger,
                    "pivot": pivot,
                    "impact": impact,
                    "severity": sev,
                    "poc": poc,
                    "evidence_count": len(trig),
                })
    return chains


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", required=True)
    ap.add_argument("--out", default="chains.md")
    a = ap.parse_args()

    report = load(a.report)
    chains = compose(report)

    lines = ["# Attack Chains (composed by KOBRA Web-Pro)\n"]
    lines.append(f"Source: {a.report}\n")
    lines.append(f"Total chains: {len(chains)}\n")
    for i, c in enumerate(chains, 1):
        lines.append(f"## Chain {i} — {c['impact']} [{c['severity']}]\n")
        lines.append(f"- **Host:** {c['host']}")
        lines.append(f"- **Entry point:** {c['entry']} (x{c['evidence_count']} finding)")
        lines.append(f"- **Pivot:** {c['pivot']}")
        lines.append(f"- **Impact:** {c['impact']}")
        if c["poc"]:
            lines.append(f"- **PoC payload:** `{c['poc']}`")
        lines.append("")

    out = "\n".join(lines)
    with open(a.out, "w") as f:
        f.write(out)
    print(out)
    print(f"[+] chains written to {a.out}")


if __name__ == "__main__":
    main()
