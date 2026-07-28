#!/usr/bin/env python3
"""
KOBRA -> Laporan Bug Bounty Profesional (siap kirim)
Baca JSON hasil KOBRA, hasilkan markdown laporan lengkap:
  - Ringkasan
  - Per finding: severity, CVSS est, steps-to-reproduce (curl), impact, remediation
  - Etika & disclaimer

Pakai: python3 make_report.py hasil.json -o laporan.md
"""
import json, sys, argparse, datetime

SEV_CVSS = {"Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 3.0, "Info": 0.5}

IMPACT = {
    "XSS": "Penyerang dapat menjalankan JavaScript di browser korban -> curi cookie/session, deface, phishing.",
    "SQLI": "Penyerang dapat membaca/modifikasi database (user, password, data bisnis).",
    "SSRF": "Penyerang dapat mengakses server internal / cloud metadata (IMDS) -> privilege escalation.",
    "SSTI": "Template engine mengeksekusi input -> berpotensi Remote Code Execution (RCE).",
    "AUTH": "Akses tanpa izin ke fitur/halaman sensitif (Broken Access Control).",
    "AUTHFLOW": "Account takeover via magic-link/OTP tampering (pre-auth).",
    "MULTITENANT": "Kebocoran data antar tenant (pelanggan lain).",
    "WAF": "Pembatas WAF dapat dilewati -> serangan lain lebih mudah.",
    "CORS": "Cross-origin request berbahaya -> eksfiltrasi data via browser.",
    "XXE": "XML external entity -> baca file lokal / SSRF.",
    "NOSQL": "NoSQL injection -> bypass auth / data leak.",
    "TRAVERSAL": "Path traversal -> baca file sistem di luar webroot.",
    "RCE": "Eksekusi kode arbitrer di server.",
    "GRAPHQL": "Introspection/DoS/IDOR via GraphQL.",
    "DESER": "Insecure deserialization -> RCE.",
    "SSRF_OOB": "Blind SSRF dengan callback -> akses internal terkonfirmasi.",
    "RESEARCH2026": "Temuan riset 2026 (cf-error / magic-link / graphql batch).",
}

REMEDIATION = {
    "XSS": "Escape output, Content-Security-Policy, jangan reflect user input ke HTML.",
    "SQLI": "Gunakan parameterized query / ORM, jangan concat SQL.",
    "SSRF": "Allowlist URL/internal IP, blok 169.254.169.254, disable redirect ke internal.",
    "SSTI": "JANGAN kirim user input ke template engine; sandbox; allowlist.",
    "AUTH": "Cek otorisasi per-request (object-level), jangan cuma auth login.",
    "AUTHFLOW": "Token magic-link harus sekali-pakai + terikat session; jangan kembalikan di response.",
    "MULTITENANT": "Isolasi tenant ketat di query DB (tenant_id wajib di WHERE semua query).",
    "WAF": "Perketat rule WAF, jangan andalkan header spoof.",
    "CORS": "Restrict Allow-Origin ke domain sendiri.",
    "XXE": "Disable external entity di XML parser.",
    "NOSQL": "Validasi tipe input, jangan terima operator Mongo mentah.",
    "TRAVERSAL": "Normalisasi path, blok '../'.",
    "RCE": "Sandbox eksekusi, validasi input ketat.",
    "GRAPHQL": "Matikan introspection di prod, batasi depth/alias (anti batching).",
    "DESER": "Jangan deserialisasi input untrusted; allowlist class.",
    "SSRF_OOB": "Sama seperti SSRF + monitor DNS callback.",
    "RESEARCH2026": "Sesuai kategori spesifik.",
}

def cat_key(cat):
    c = cat.upper()
    for k in IMPACT:
        if k in c:
            return k
    return "RESEARCH2026"

def curl_cmd(f):
    t = f.get("target", "")
    p = f.get("param") or "q"
    pay = f.get("payload") or "PAYLOAD"
    return f'curl -s "{t}/?{p}={pay}"'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("json_file")
    ap.add_argument("-o", "--out", default="laporan_kobra.md")
    a = ap.parse_args()

    data = json.load(open(a.json_file))
    if isinstance(data, dict):
        data = data.get("findings", [])
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    by_sev = {}
    for f in data:
        by_sev.setdefault(f["severity"], []).append(f)

    md = []
    md.append("# Laporan Kerentanan — Hasil Pemindaian KOBRA\n")
    md.append(f"*Dibuat otomatis: {ts}*\n")
    md.append("\n## Ringkasan\n")
    md.append(f"- Total temuan: **{len(data)}**")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev in by_sev:
            md.append(f"  - {sev}: {len(by_sev[sev])}")
    md.append("\n> ⚠️ Laporan ini hanya untuk target berizin (bug bounty / lab). Sesuai RoE: non-destructive, stop before RCE.\n")

    md.append("\n---\n")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        for i, f in enumerate(by_sev.get(sev, []), 1):
            cat = cat_key(f.get("category", ""))
            cvss = SEV_CVSS.get(sev, 3.0)
            md.append(f"## {sev} — {f.get('title','')}\n")
            md.append(f"- **Kategori**: {f.get('category','')}")
            md.append(f"- **Target**: `{f.get('target','')}`")
            if f.get("param"): md.append(f"- **Parameter**: `{f['param']}`")
            if f.get("payload"): md.append(f"- **Payload**: `{f['payload']}`")
            if f.get("evidence"): md.append(f"- **Bukti**: {f['evidence']}")
            md.append(f"- **Confidence**: {f.get('confidence',0)}%")
            md.append(f"- **Estimasi CVSS**: {cvss}\n")
            md.append("### Cara Reproduksi\n")
            md.append("```bash")
            md.append(curl_cmd(f))
            md.append("```\n")
            md.append("### Dampak\n")
            md.append(IMPACT.get(cat, "Lihat kategori terkait."))
            md.append("\n### Rekomendasi Perbaikan\n")
            md.append(REMEDIATION.get(cat, "Validasi & sanitasi input."))
            md.append("\n")

    open(a.out, "w").write("\n".join(md))
    print(f"[+] Laporan profesional ditulis: {a.out} ({len(data)} temuan)")

if __name__ == "__main__":
    main()
