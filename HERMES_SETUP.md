# Cara Pakai KOBRA di Hermes Agent LAIN

## Ada 3 Cara — Pilih Sesuai Kebutuhan

---

## 🚀 CARA 1: Copy Binary + MCP (Termudah, 2 Menit)

**Cocok buat:** Lo sendiri mau pake di profile Hermes lain, atau kirim ke temen.

```bash
# 1. Copy binary KOBRA
scp user@server-utama:~/.local/bin/kobra ~/.local/bin/
# atau download dari release: 
# curl -L https://github.com/shenyo1/kobra/releases/download/v4.4.0/kobra -o ~/.local/bin/kobra
chmod +x ~/.local/bin/kobra

# 2. Copy MCP server
mkdir -p ~/.local/opt/kobra
scp -r user@server-utama:~/.local/opt/kobra/kobra_mcp.py ~/.local/opt/kobra/
scp -r user@server-utama:~/.local/opt/kobra/*.py ~/.local/opt/kobra/ 2>/dev/null

# 3. Install dependensi Python
pip install mcp

# 4. Daftarkan ke Hermes
hermes mcp add kobra --command python3 --args ~/.local/opt/kobra/kobra_mcp.py
# → Ketik Y untuk enable semua 8 tools

# 5. Tes
hermes mcp test kobra
# Output: ✓ Connected ... ✓ Tools discovered: 6

# 6. Copy plugins (opsional)
mkdir -p ~/.config/kobra/plugins
scp -r user@server-utama:~/.config/kobra/plugins/* ~/.config/kobra/plugins/ 2>/dev/null
```

**Selesai!** Mulai session Hermes baru → tinggal bilang "Pindai https://target.com pakai KOBRA".

---

## 🛠️ CARA 2: Build dari Source (Full Control)

**Cocok buat:** Mau modifikasi, kontribusi, atau Rust developer.

```bash
# 1. Install Rust (kalo belum)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# 2. Clone repo
git clone https://github.com/shenyo1/kobra.git ~/.local/opt/kobra
cd ~/.local/opt/kobra

# 3. Build
cargo build --release
cp target/release/kobra ~/.local/bin/

# 4. MCP + Hermes setup
pip install mcp
hermes mcp add kobra --command python3 --args $(pwd)/kobra_mcp.py

# 5. Tes
hermes mcp test kobra
```

---

## 📦 CARA 3: Via Docker (Isolasi)

**Cocok buat:** Pengguna non-Rust, atau mau isolasi lingkungan.

```dockerfile
# Dockerfile
FROM rust:latest AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM python:3.11-slim
COPY --from=builder /app/target/release/kobra /usr/local/bin/kobra
COPY --from=builder /app/kobra_mcp.py /opt/kobra/kobra_mcp.py
COPY --from=builder /app/*.py /opt/kobra/
RUN pip install mcp
CMD ["python3", "/opt/kobra/kobra_mcp.py"]
```

```bash
docker build -t kobra-mcp .
docker run -d --name kobra-mcp kobra-mcp
# Lalu register MCP di Hermes dengan command docker
```

---

## 🎮 Cara Pake di Chat Hermes

Setelah setup, **mulai session baru** lalu:

| Chat | Yang Terjadi |
|------|-------------|
| "Pindai https://contoh.com pakai KOBRA" | `scan_target` mode crazy |
| "Scan target ini pelan-pelan" | `scan_target` mode stealth |
| "Borong sumopod.com" | `run_orchestrator` → recon + scan lengkap |
| "Cek API endpoint ini" | `api_break` → IDOR, JWT, mass-assign |
| "Cek cloud config target" | `cloud_enum` → AWS/Azure/GCP |
| "Buat chain report dari hasil tadi" | `chain_report` → gabung temuan jadi attack chain |
| "Gas KOBRA dengan plugins" | Scan pake `--plugin-dir` (kalo plugin udah di-copy) |

---

## ⚙️ 6 MCP Tools yang Tersedia

| Tool | Fungsi |
|------|--------|
| `scan_target` | Scan 1 target (stealth/normal/crazy) |
| `run_orchestrator` | Full pipeline: recon → KOBRA → nuclei → ffuf → dalfox |
| `chain_report` | Gabung temuan jadi attack chain (XSS+Authflow=ATO, dll) |
| `api_break` | Tes API: IDOR, mass-assignment, JWT bypass |
| `cloud_enum` | Enum cloud metadata (AWS/Azure/GCP) |
| `ctf_payloads` | Generate payload buat CTF (SQLi, XSS, SSTI, dll) |

---

## 🔧 Yang Perlu Dicopy ke Hermes Lain

Kalau mau **persis sama** kayak setup Sakura-chan:

```
~/.local/bin/kobra                    → Binary KOBRA v4.4.0
~/.local/opt/kobra/kobra_mcp.py       → MCP server
~/.local/opt/kobra/kobra_orchestrator.py  → Orchestrator (opsional)
~/.local/opt/kobra/*.py               → Helper scripts
~/.config/kobra/plugins/              → Plugin JSON files (opsional)
~/.local/opt/kobra/Cargo.toml         → Source (kalo mau build ulang)
```

**Size binary:** ~9MB (ringan)

---

## ⚠️ Troubleshoot

| Masalah | Solusi |
|---------|--------|
| `hermes: command not found` | Install Hermes Agent dulu |
| `ModuleNotFoundError: mcp` | `pip install mcp` |
| `kobra: command not found` di MCP | Binary gak ada di PATH. Edit `kobra_mcp.py` baris 20, ganti `shutil.which("kobra")` jadi path lengkap |
| Tools gak muncul di chat | Mulai **session baru** setelah `hermes mcp add` |
| MCP timeout | Target lambat. Cobain mode stealth dulu |
| Binary beda arsitektur | Build dari source di mesin target (Cara 2) |
