# KOBRA — Pemindai Kerentanan Web untuk Semua

KOBRA adalah alat bantu untuk mencari celah keamanan pada situs web (bug bounty).
Alat ini bisa dipakai oleh pemula maupun ahli.

---

## ⚠️ ATURAN PENTING (BACA DULU)

Gunakan KOBRA **HANYA** di situs yang memberi Anda izin, misalnya:
- Program bug bounty resmi (contoh: Sumopod, HackerOne, Bugcrowd)
- Lab latihan (contoh: OWASP Juice Shop, PortSwigger Web Security Academy)

**JANGAN** pakai ke situs orang lain tanpa izin. Itu melanggar hukum.

---

## Cara Pakai (Paling Gampang)

Buka terminal, lalu ketik:

```bash
# Lihat bantuan
./kobra-cli.sh bantuan

# Pindai 1 situs (mode agresif)
./kobra-cli.sh scan https://contoh.com

# Pindai pelan (susah ketahuan)
./kobra-cli.sh scan aman https://contoh.com

# Pindai semua subdomain perusahaan
./kobra-cli.sh borong perusahaan.com

# Cek cepat 1 halaman
./kobra-cli.sh cek https://api.contoh.com

# Lihat hasil
./kobra-cli.sh hasil
```

Hasil pindai ada di folder: **`~/kobra-hasil`**

---

## Cara Pakai Lanjut (Command Asli)

Jika Anda sudah biasa terminal:

```bash
# Mode normal
kobra -t https://contoh.com

# Mode gila (lebih banyak tes)
kobra -t https://contoh.com -m crazy

# Simpan hasil ke file
kobra -t https://contoh.com -m crazy -j -o hasil.json
```

Mode:
- `stealth` → pelan, sulit terdeteksi
- `normal` → biasa
- `crazy` → agresif, banyak tes (disarankan untuk bug bounty)

---

## Pakai dari dalam Hermes Agent (AI Assistant)

KOBRA bisa dikendalikan oleh AI (Hermes Agent) lewat MCP.

1. Pastikan `mcp` sudah terpasang:
   ```bash
   pip install mcp
   ```
2. Hubungkan Hermes ke `kobra_mcp.py` (tanyakan pembuat bot Anda).
3. Lalu Anda cukup bilang ke bot:
   *"Pindai https://contoh.com pakai KOBRA"*
   Bot akan menjalankan alat ini untuk Anda.

Tools yang tersedia di MCP:
- `scan_target` — pindai 1 situs
- `run_orchestrator` — pindai lengkap (subdomain + fuzz)
- `chain_report` — gabungkan celah jadi rantai serangan
- `api_break` — tes API (IDOR, JWT, dll)
- `cloud_enum` — cek salah config cloud
- `ctf_payloads` — buat payload latihan CTF

---

## Apa yang KOBRA Cek?

KOBRA memeriksa banyak jenis celah, di antaranya:
- XSS (script disuntik ke halaman)
- SQL Injection (curi data database)
- SSRF (akses server dalam)
- SSTI (eksekusi kode di template)
- Auth/Login lemah (akses tanpa izin)
- WAF bypass (lewati pembatas)
- Multi-tenant (bocor data pengguna lain)
- **Email-only Login Mass ATO** (endpoint `/login` yang kasih token tanpa password/OTP)
- Dan 36 jenis lainnya (total 52 modul scan + 14 engine + 10 report)

Semua hasil ditampilkan jujur (tidak disembunyikan).

---

## Modul: Email-Only Login Mass ATO (`email_ato`)

Mendeteksi pola Mass ATO yang ditemukan di wibuku.app:

- **Apa:** Endpoint `/login` (atau `/api/login`, `/auth/login`, dll) yang menerima hanya `{"email": "..."}` dan membalas dengan session/token — tanpa password, tanpa OTP, tanpa email-verification link.
- **Bahaya:** Penyerang bisa enumerasi email lalu mendapat sesi sah untuk setiap akun.
- **Cara cek KOBRA:**
  1. Kirim 2 email acak (`kobra_probe_<random>@example.com`) → kalau balasannya identik dan ada field `session`/`token` → **CRITICAL** (Mass ATO confirmed).
  2. Kirim `notanemail` (kontrol negatif) → kalau tetap dapat token → **CRITICAL** (tanpa validasi sama sekali).
  3. Kalau balasannya hanya berisi string panjang tak bernama → **HIGH** (perlu tinjauan manual).
- **Endpoint yang diuji:** `/login`, `/api/login`, `/auth/login`, `/api/auth/login`, `/api/v1/login`, `/api/v1/auth/login`, `/signin`, `/api/signin`, `/session`, `/api/session`, `/authenticate`.
- **Confidence:** 70 (heuristik string) → 90 (kedua email sah identik) → 95 (input tanpa email diterima juga).

---

## Tips Aman

- Selalu minta izin dulu.
- Jangan kirim terlalu banyak request cepat (bisa merusak situs).
- Laporkan temuan lewat jalur resmi program bug bounty.
- Jangan akses data orang lain.

---

## Folder Proyek

- `src/` → kode pemindai (bahasa Rust)
- `kobra-cli.sh` → pembungkus ramah pemula
- `kobra_mcp.py` → penghubung ke AI (Hermes)
- `kobra-orchestrator.py` → pindai otomatis lengkap
- `sumopod_technique_playbook.md` → catatan teknik 2026

Selamat mencoba, dan pakai dengan bertanggung jawab! 🛡️
