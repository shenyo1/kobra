#!/usr/bin/env python3
"""
KOBRA Web-Pro Orchestrator
Glue between web-hacking-pro (brain) and available engines (KOBRA + nuclei + ffuf + dalfox).

Pipeline (all authorized targets only):
  1. Recon        -> crt.sh subdomains (via KOBRA recon) + httpx probe
  2. KOBRA crazy -> 56 vuln modules, full disclosure
  3. Nuclei       -> template CVE/tech detection
  4. FFUF         -> path/param fuzzing
  5. DalFox       -> XSS deep scan
  6. Merge        -> single JSON + markdown report

Usage:
  python3 kobra-orchestrator.py --target example.com --out engagement
  python3 kobra-orchestrator.py --target https://a.com,https://b.com -m crazy

Tools used (must be in PATH): kobra, nuclei, ffuf, dalfox, httpx
Missing tools are skipped with a warning (graceful degradation).
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import shutil
from datetime import datetime


def run(cmd, timeout=300):
    """Run a command, return (rc, stdout). Never raises."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return 124, "[timeout]"
    except Exception as e:
        return 1, str(e)


def have(tool):
    return shutil.which(tool) is not None


def recon_crt(domain):
    """Passive subdomain enum via crt.sh. Returns list of hosts (https://...)."""
    hosts = set()
    rc, out = run(f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json'")
    if rc == 0 and out.strip():
        try:
            import json as J
            for e in J.loads(out):
                nm = e.get("name_value", "")
                for part in nm.split("\n"):
                    part = part.strip()
                    if part.endswith(domain):
                        hosts.add(part)
        except Exception:
            pass
    # build https URLs
    return [f"https://{h}" for h in sorted(hosts)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="domain or comma-sep URLs")
    ap.add_argument("--out", default="engagement", help="output dir")
    ap.add_argument("-m", "--mode", default="crazy", help="kobra mode")
    ap.add_argument("--skip-recon", action="store_true")
    ap.add_argument("--skip-ffuf", action="store_true", help="skip ffuf content discovery")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    findings = []

    # Normalize targets
    raw = [t.strip() for t in a.target.split(",") if t.strip()]
    # If a bare domain given, treat as https URL
    targets = []
    for t in raw:
        if t.startswith("http"):
            targets.append(t)
        else:
            targets.append(f"https://{t}")
            # also remember domain for recon
    domains = [t.split("//")[-1].split("/")[0] for t in targets]

    print(f"[*] KOBRA Web-Pro Orchestrator | targets={targets}")

    # ---- Phase 1: Recon ----
    recon_hosts = list(targets)
    if not a.skip_recon:
        for d in set(domains):
            # crt.sh passive
            print(f"[*] recon {d} (crt.sh)...")
            subs = recon_crt(d)
            print(f"[+] crt.sh: {len(subs)} subdomains")
            recon_hosts.extend(subs)
            # subfinder if present (more complete)
            if have("subfinder"):
                rc, out = run(f"subfinder -d {d} -silent", timeout=180)
                if rc == 0:
                    for line in out.splitlines():
                        line = line.strip()
                        if line and line.endswith(d):
                            recon_hosts.append(f"https://{line}")
                    print(f"[+] subfinder added more")
            # wayback/gau path mining
            if have("waybackurls"):
                rc, out = run(f"echo {d} | waybackurls", timeout=120)
                if rc == 0:
                    for line in out.splitlines():
                        line = line.strip()
                        if line.startswith("http") and d in line:
                            recon_hosts.append(line)
                    print(f"[+] waybackurls paths added")
            # gau path mining (alt to waybackurls)
            if have("gau"):
                rc, out = run(f"gau {d} --blacklist js,png,css,svg", timeout=120)
                if rc == 0:
                    for line in out.splitlines():
                        line = line.strip()
                        if line.startswith("http") and d in line:
                            recon_hosts.append(line)
                    print(f"[+] gau paths added")
            # JS endpoint + secret grep
            if have("subjs"):
                js_urls = []
                rc, out = run(f"echo '{d}' | subjs", timeout=120)
                if rc == 0:
                    for line in out.splitlines():
                        line = line.strip()
                        if line.endswith(".js") and d in line:
                            js_urls.append(line)
                if js_urls:
                    with open(f"{a.out}/scope_js.txt", "w") as jf:
                        jf.write("\n".join(js_urls) + "\n")
                    # grep secrets in JS
                    secrets = []
                    import re as _re
                    SECRET_RE = _re.compile(
                        r"(?i)(api[_-]?key|secret|token|password|aws_access_key_id|"
                        r"AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|eyJ[A-Za-z0-9_-]+\.eyJ)"
                    )
                    for js in js_urls[:30]:
                        rc2, body = run(f"curl -s '{js}'", timeout=30)
                        for m in SECRET_RE.findall(body):
                            secrets.append((js, m))
                    if secrets:
                        with open(f"{a.out}/scope_secrets.txt", "w") as sf:
                            for js, m in secrets:
                                sf.write(f"{js}: {m}\n")
                        print(f"[+] subjs: {len(js_urls)} JS, {len(secrets)} secret hints")
                        for js, m in secrets[:10]:
                            findings.append({
                                "category": "SECRET", "severity": "HIGH",
                                "title": f"Possible secret in JS: {m}",
                                "target": js, "payload": m,
                                "evidence": "regex match in static JS", "confidence": 60,
                            })
    recon_hosts = list(dict.fromkeys(recon_hosts))  # dedupe
    with open(f"{a.out}/scope_hosts.txt", "w") as f:
        f.write("\n".join(recon_hosts) + "\n")

    # Probe alive with httpx if present
    alive = recon_hosts
    if have("httpx"):
        print("[*] probing alive hosts (httpx)...")
        rc, out = run(f"httpx -silent -l {a.out}/scope_hosts.txt", timeout=180)
        if rc == 0 and out.strip():
            alive = [l.strip() for l in out.strip().splitlines() if l.strip()]
    print(f"[+] {len(alive)} alive hosts")

    # ---- Phase 1.5: Naabu port scan (per domain) ----
    if have("naabu"):
        for d in set(domains):
            print(f"[*] naabu port scan {d}...")
            rc, out = run(f"naabu -host {d} -top-ports 1000 -silent", timeout=200)
            if rc == 0 and out.strip():
                # naabu prints "host:port"
                ports = []
                for l in out.strip().splitlines():
                    l = l.strip()
                    if ":" in l:
                        port = l.split(":")[-1]
                        ports.append(port)
                with open(f"{a.out}/scope_ports.txt", "a") as pf:
                    for p in ports:
                        pf.write(f"{d}:{p}\n")
                print(f"[+] naabu found {len(ports)} ports for {d}")
                for p in ports[:20]:
                    findings.append({
                        "category": "PORT", "severity": "INFO", "title": f"Open port {p}",
                        "target": d, "payload": p, "evidence": "naabu", "confidence": 50,
                    })

    # ---- Phase 2: KOBRA crazy on every alive host ----
    if have("kobra"):
        for t in alive:
            print(f"[*] KOBRA {a.mode} -> {t}")
            rc, out = run(f"kobra -t '{t}' -m {a.mode} --no-confirm -j -o {a.out}/kobra_{t.split('//')[-1].split('/')[0]}.json", timeout=400)
            # kobra writes its own json; also parse stdout summary
            jf = f"{a.out}/kobra_{t.split('//')[-1].split('/')[0]}.json"
            if os.path.exists(jf):
                try:
                    data = json.load(open(jf))
                    findings.extend(data)
                except Exception:
                    pass
    else:
        print("[!] kobra missing — skipping vuln scan")

    # ---- Phase 3: Nuclei (if present) ----
    if have("nuclei"):
        print("[*] nuclei templates scan...")
        rc, out = run(f"nuclei -l {a.out}/scope_hosts.txt -silent -json -o {a.out}/nuclei.jsonl", timeout=400)
        if os.path.exists(f"{a.out}/nuclei.jsonl"):
            for line in open(f"{a.out}/nuclei.jsonl"):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    findings.append({
                        "category": "NUCLEI",
                        "severity": (d.get("info", {}).get("severity") or "info").upper(),
                        "title": d.get("template-id", "n/a"),
                        "target": d.get("matched-at", ""),
                        "payload": d.get("template-id", ""),
                        "evidence": "",
                        "confidence": 70,
                    })
                except Exception:
                    pass

    # ---- Phase 4: FFUF path fuzz (if present) ----
    if have("ffuf") and not a.skip_ffuf:
        # Prefer bundled KOBRA wordlist, fall back to common system paths.
        candidate = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "wordlists", "common.txt")
        for wl in (candidate,
                   "/usr/share/seclists/Discovery/Web-Content/common.txt",
                   "/usr/share/wordlists/dirb/common.txt"):
            if os.path.exists(wl):
                wordlist = wl
                break
        else:
            wordlist = None
        if wordlist:
            print(f"[*] ffuf using {wordlist}")
            for t in alive[:8]:  # limit to avoid huge runs
                print(f"[*] ffuf fuzz {t}")
                rc, out = run(f"ffuf -u '{t}/FUZZ' -w {wordlist} -mc 200,201,403 -t 40 -s", timeout=200)
                for line in out.splitlines():
                    line = line.strip()
                    if line:
                        findings.append({
                            "category": "FUZZ", "severity": "INFO", "title": "Path discovered",
                            "target": t, "payload": line, "evidence": "", "confidence": 30,
                        })
        else:
            print("[!] no wordlist found — skipping ffuf")
    elif a.skip_ffuf:
        print("[*] ffuf skipped (--skip-ffuf)")

    # ---- Phase 5: DalFox XSS (if present) ----
    if have("dalfox"):
        for t in alive[:5]:
            print(f"[*] dalfox {t}")
            rc, out = run(f"dalfox url '{t}' --silence --format json", timeout=300)
            # dalfox json is a stream; try parse
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    try:
                        d = json.loads(line)
                        findings.append({
                            "category": "XSS", "severity": "HIGH", "title": "XSS (dalfox)",
                            "target": d.get("url", t), "payload": d.get("payload", ""),
                            "evidence": "", "confidence": 85,
                        })
                    except Exception:
                        pass

    # ---- Merge report ----
    report = {
        "generated": datetime.utcnow().isoformat(),
        "targets": targets,
        "total": len(findings),
        "findings": findings,
    }
    with open(f"{a.out}/report.json", "w") as f:
        json.dump(report, f, indent=2)

    # Markdown summary
    from collections import Counter
    sev_counts = Counter(f.get("severity", "INFO") for f in findings)
    cat_counts = Counter(f.get("category", "?") for f in findings)
    with open(f"{a.out}/report.md", "w") as f:
        f.write(f"# KOBRA Web-Pro Report\n\nGenerated: {report['generated']}\n\n")
        f.write(f"**Targets:** {', '.join(targets)}\n\n")
        f.write(f"**Total findings:** {len(findings)}\n\n")
        f.write(f"**By severity:** {dict(sev_counts)}\n\n")
        f.write(f"**By category:** {dict(cat_counts)}\n\n")
        f.write("## Findings\n\n")
        for fi in findings:
            f.write(f"- [{fi.get('severity','INFO')}] {fi.get('category','?')}: {fi.get('title','')} @ {fi.get('target','')}\n")
            if fi.get("payload"):
                f.write(f"  - payload: `{fi['payload']}`\n")

    print(f"\n[+] DONE. {len(findings)} findings -> {a.out}/report.json + report.md")
    print(f"[+] severity: {dict(sev_counts)}")


if __name__ == "__main__":
    main()
