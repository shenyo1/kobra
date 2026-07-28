#!/usr/bin/env python3
"""
KOBRA -> Laporan Bug Bounty Profesional (v2)
Fitur: CVSS 3.1 beneran, raw HTTP request/response, template per-program (Sumopod), PDF export.
Pakai: python3 make_report.py hasil.json -o laporan.md [--program sumopod] [--pdf laporan.pdf]
"""
import json, sys, argparse, datetime, os, subprocess

try:
    from cvss import score_for_category
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from cvss import score_for_category

PROGRAM_TEMPLATES = {
    "sumopod": {
        "intro": "Halo Tim Keamanan Sumopod,\n\nSaya peneliti dari program Bug Bounty Sumopod. "
                  "Laporan ini memenuhi RoE: non-destructive, pre-auth (tanpa akun), stop before RCE.\n",
        "contact_note": "Sesuai aturan: rahasiakan sebelum patch. First-come-first-served.",
        "email": "security@sumopod.com",
    },
    "generic": {
        "intro": "Halo Tim Keamanan,\n\nLaporan hasil pemindaian KOBRA (bug bounty / authorized test).\n",
        "contact_note": "Sesuai RoE program.",
        "email": "security@target.com",
    },
}

IMPACT = {
    "XSS": "Penyerang menjalankan JS di browser korban -> curi session, deface, phishing.",
    "SQLI": "Baca/modifikasi database (user, credential, data bisnis).",
    "SSRF": "Akses server internal / cloud metadata (IMDS) -> privilege escalation.",
    "SSTI": "Template engine mengeksekusi input -> berpotensi RCE.",
    "AUTH": "Akses tanpa izin ke fitur sensitif (Broken Access Control).",
    "AUTHFLOW": "Account takeover via magic-link/OTP tampering (pre-auth).",
    "MULTITENANT": "Kebocoran data antar tenant (pelanggan lain).",
    "WAF": "WAF dapat dilewati -> serangan lain lebih mudah.",
    "CORS": "Cross-origin berbahaya -> eksfiltrasi via browser.",
    "XXE": "XML external entity -> baca file lokal / SSRF.",
    "NOSQL": "NoSQL injection -> bypass auth / data leak.",
    "TRAVERSAL": "Path traversal -> baca file di luar webroot.",
    "RCE": "Eksekusi kode arbitrer di server.",
    "GRAPHQL": "Introspection/DoS/IDOR via GraphQL.",
    "DESER": "Insecure deserialization -> RCE.",
    "SSRF_OOB": "Blind SSRF terkonfirmasi via callback.",
}

REMEDIATION = {
    "XSS": "Escape output + CSP; jangan reflect user input ke HTML.",
    "SQLI": "Parameterized query / ORM; jangan concat SQL.",
    "SSRF": "Allowlist URL/IP internal; blok 169.254.169.254; disable redirect internal.",
    "SSTI": "JANGAN kirim user input ke template engine; sandbox; allowlist.",
    "AUTH": "Cek otorisasi object-level tiap request.",
    "AUTHFLOW": "Token magic-link sekali-pakai + terikat session; jangan kembalikan di response.",
    "MULTITENANT": "Isolasi tenant ketat (tenant_id wajib di WHERE semua query).",
    "WAF": "Perketat rule; jangan andalkan header spoof.",
    "CORS": "Restrict Allow-Origin ke domain sendiri.",
    "XXE": "Disable external entity di XML parser.",
    "NOSQL": "Validasi tipe; jangan terima operator Mongo mentah.",
    "TRAVERSAL": "Normalisasi path; blok '../'.",
    "RCE": "Sandbox + validasi input ketat.",
    "GRAPHQL": "Matikan introspection di prod; batasi depth/alias.",
    "DESER": "Jangan deserialisasi untrusted; allowlist class.",
    "SSRF_OOB": "Sama seperti SSRF + monitor DNS callback.",
}

def curl_cmd(f):
    t = f.get("target", "")
    p = f.get("param") or "q"
    pay = f.get("payload") or "PAYLOAD"
    return f'curl -s "{t}/?{p}={pay}"'

def cat_key(cat):
    c = cat.upper()
    for k in IMPACT:
        if k in c:
            return k
    return "AUTH"

def build_markdown(data, program="generic"):
    tpl = PROGRAM_TEMPLATES.get(program, PROGRAM_TEMPLATES["generic"])
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    by_sev = {}
    for f in data:
        by_sev.setdefault(f.get("severity", "Info"), []).append(f)

    md = []
    md.append(f"# Laporan Kerentanan — KOBRA\n\n{tpl['intro']}")
    md.append(f"*Dibuat: {ts}*\n")
    md.append("## Ringkasan\n")
    md.append(f"- Total: **{len(data)}**")
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev in by_sev:
            md.append(f"  - {sev}: {len(by_sev[sev])}")
    md.append("\n> ⚠️ Hanya untuk target berizin. RoE: non-destructive, stop before RCE.\n")
    md.append("---\n")

    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        for f in by_sev.get(sev, []):
            cat = cat_key(f.get("category", ""))
            cvss, rate, vec = score_for_category(f.get("category", ""))
            vec_str = f"CVSS:3.1/AV:{vec['AV']}/AC:{vec['AC']}/PR:{vec['PR']}/UI:{vec['UI']}/S:{vec['S']}/C:{vec['C']}/I:{vec['I']}/A:{vec['A']}"
            md.append(f"## [{sev}] {f.get('title','')}\n")
            md.append(f"- **Kategori**: {f.get('category','')}")
            md.append(f"- **Target**: `{f.get('target','')}`")
            if f.get("param"): md.append(f"- **Parameter**: `{f['param']}`")
            if f.get("payload"): md.append(f"- **Payload**: `{f['payload']}`")
            if f.get("evidence"): md.append(f"- **Bukti**: {f['evidence']}")
            md.append(f"- **Confidence**: {f.get('confidence',0)}%")
            md.append(f"- **CVSS**: {cvss} ({rate}) — `{vec_str}`\n")
            # Raw HTTP jika ada
            if f.get("request"):
                md.append("### Raw Request\n```http\n" + f["request"] + "\n```")
            if f.get("response"):
                md.append("### Raw Response\n```http\n" + f["response"][:2000] + "\n```")
            md.append("### Cara Reproduksi\n```bash\n" + curl_cmd(f) + "\n```\n")
            md.append("### Dampak\n" + IMPACT.get(cat, "Lihat kategori.") + "\n")
            md.append("### Rekomendasi\n" + REMEDIATION.get(cat, "Validasi input.") + "\n\n")

    md.append(f"---\n{tpl['contact_note']}\nLaporan otomatis KOBRA.\n")
    return "\n".join(md)

def build_pdf(md_text, pdf_path):
    # Try pandoc -> wkhtmltopdf -> reportlab fallback
    if subprocess.run("which pandoc", shell=True).returncode == 0:
        r = subprocess.run(f"pandoc -o {pdf_path} -f markdown", input=md_text.encode(), shell=True)
        if r.returncode == 0:
            return True
    if subprocess.run("which wkhtmltopdf", shell=True).returncode == 0:
        r = subprocess.run(f"wkhtmltopdf - {pdf_path}", input=md_text.encode(), shell=True)
        if r.returncode == 0:
            return True
    # reportlab fallback
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
        from reportlab.lib.styles import getSampleStyleSheet
        from xml.sax.saxutils import escape
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        mono = styles["Code"]
        story = []
        for line in md_text.split("\n"):
            if line.startswith("```"):
                continue  # skip code fences for PDF simplicity
            if line.strip() == "":
                story.append(Spacer(1, 6))
            else:
                story.append(Paragraph(escape(line), styles["Normal"]))
        doc.build(story)
        return True
    except Exception as e:
        print(f"[!] PDF failed: {e}")
        return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("json_file")
    ap.add_argument("-o", "--out", default="laporan_kobra.md")
    ap.add_argument("--program", default="generic", choices=["generic", "sumopod"])
    ap.add_argument("--pdf", default="")
    a = ap.parse_args()
    data = json.load(open(a.json_file))
    if isinstance(data, dict):
        data = data.get("findings", [])
    md = build_markdown(data, a.program)
    open(a.out, "w").write(md)
    print(f"[+] Markdown: {a.out} ({len(data)} temuan)")
    if a.pdf:
        if build_pdf(md, a.pdf):
            print(f"[+] PDF: {a.pdf}")
        else:
            print("[!] PDF gagal, pakai markdown saja")

if __name__ == "__main__":
    main()
