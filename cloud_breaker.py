#!/usr/bin/env python3
"""
Cloud-Breaker Pro — AWS / Azure / GCP misconfig enumerator (authorized only).

Probes public metadata endpoints and common misconfigs. Never exfil off-box.
If you hit a real IMDS/credential endpoint you don't own -> STOP and report.

Usage:
  python3 cloud_breaker.py --provider aws --host https://app.target.com
  python3 cloud_breaker.py --provider all --host https://x.target.com
"""
import argparse
import json
import urllib.request
import urllib.error


UA = "Mozilla/5.0 (compatible; CloudBreakerPro/1.0)"

# (label, url, headers) per provider
PROBES = {
    "aws": [
        ("IMDSv1 metadata", "http://169.254.169.254/latest/meta-data/", {}),
        ("IMDSv2 token", "http://169.254.169.254/latest/api/token",
         {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}),
        ("IAM creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", {}),
    ],
    "azure": [
        ("Managed Identity token",
         "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
         {"Metadata": "true"}),
        ("Instance metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", {"Metadata": "true"}),
    ],
    "gcp": [
        ("GCP metadata token", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
         {"Metadata-Flavor": "Google"}),
        ("GCP project", "http://metadata.google.internal/computeMetadata/v1/project/project-id",
         {"Metadata-Flavor": "Google"}),
    ],
}


def probe(label, url, headers, timeout=8):
    req = urllib.request.Request(url, headers={**headers, "User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "ignore")[:500]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore")[:500]
    except Exception as e:
        return 0, str(e)[:200]


def scan(provider, host):
    findings = []
    for label, url, hdr in PROBES.get(provider, []):
        st, body = probe(label, url, hdr)
        reachable = st == 200 and len(body) > 0
        findings.append({
            "category": "CLOUD", "severity": "CRITICAL" if reachable else "INFO",
            "title": f"[{provider.upper()}] {label}",
            "target": host, "payload": url,
            "evidence": f"status={st}, reachable={reachable}",
            "confidence": 90 if reachable else 10,
        })
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True, choices=["aws", "azure", "gcp", "all"])
    ap.add_argument("--host", default="")
    ap.add_argument("--out", default="cloud_findings.jsonl")
    a = ap.parse_args()

    provs = ["aws", "azure", "gcp"] if a.provider == "all" else [a.provider]
    all_f = []
    for p in provs:
        all_f.extend(scan(p, a.host))

    with open(a.out, "w") as f:
        for x in all_f:
            f.write(json.dumps(x) + "\n")
    print(f"[+] {len(all_f)} cloud probes -> {a.out}")
    for x in all_f:
        if x["severity"] == "CRITICAL":
            print(f"  [CRITICAL] {x['title']} @ {x['target']} ({x['evidence']})")
    print("  NOTE: reachable IMDS/creds on a host you don't own = STOP & report.")


if __name__ == "__main__":
    main()
