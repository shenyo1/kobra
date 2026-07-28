#!/usr/bin/env python3
"""CVSS 3.1 base score calculator (simplified but real vector math)."""
import math

# AV, AC, PR, UI, S scope; C/I/A
WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # changed by scope below
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

def pr_weight(pr, scope):
    if pr == "N":
        return 0.85
    return 0.68 if scope == "C" else 0.62

def base_score(vec):
    """vec: dict with keys AV,AC,PR,UI,S,C,I,A (S=Scope U/C)."""
    S = vec.get("S", "U")
    PRw = pr_weight(vec["PR"], S)
    iss = 1 - (1 - WEIGHTS["C"][vec["C"]]) * (1 - WEIGHTS["I"][vec["I"]]) * (1 - WEIGHTS["A"][vec["A"]])
    if iss <= 0:
        return 0.0
    if S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    expl = 8.22 * WEIGHTS["AV"][vec["AV"]] * WEIGHTS["AC"][vec["AC"]] * PRw * WEIGHTS["UI"][vec["UI"]]
    if impact <= 0:
        return 0.0
    if S == "U":
        base = min(impact + expl, 10.0)
    else:
        base = min(1.08 * (impact + expl), 10.0)
    return math.ceil(base * 10) / 10.0

def rate(score):
    if score == 0: return "None"
    if score < 4: return "Low"
    if score < 7: return "Medium"
    if score < 9: return "High"
    return "Critical"

# Default vectors per category (reasonable for bug-bounty context)
DEFAULT_VEC = {
    "SSRF": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "SSTI": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "RCE":  {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "SQLI": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "XSS":  {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    "AUTH": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "AUTHFLOW": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "L"},
    "MULTITENANT": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "XXE":  {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "L"},
    "NOSQL":{"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "TRAVERSAL": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "H"},
    "WAF":  {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
    "CORS": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    "GRAPHQL": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
    "DESER": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "SSRF_OOB": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
}

def score_for_category(cat):
    c = cat.upper()
    for k, v in DEFAULT_VEC.items():
        if k in c:
            s = base_score(v)
            return s, rate(s), v
    v = DEFAULT_VEC["AUTH"]
    s = base_score(v)
    return s, rate(s), v

if __name__ == "__main__":
    s, r, vec = score_for_category("SSRF")
    print(f"SSRF -> CVSS {s} ({r}) vector CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
