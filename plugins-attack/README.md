# 🐍 KOBRA Attack Plugins

Plugin-based attack layer untuk KOBRA. Drops ke `~/.local/share/kobra/plugins/exploit/` — KOBRA auto-discover.

## 📦 Plugins Tersedia

| File | Fungsi | Depends on |
|------|--------|-----------|
| `sqlmap-auto.json` | Auto-exploit SQLi findings via sqlmap | sqlmap binary |
| `jwt-attack.json` | JWT exploitation suite (alg:none, weak secret, RS256 confusion, jwk injection, kid traversal) | - |
| `oob-c2-bridge.json` | OOB blind SSRF/RCE → C2 pivot | built-in listener or interact.sh |
| `postgrest-pwn.json` | PostgREST/Supabase auto-exploit (Sumopod-class) | - |
| `chain-orchestrator.json` | Full kill-chain state machine | all of the above |

## 🚀 Cara Pakai

### 1. Drop plugin ke direktori
```bash
cp exploit/*.json ~/.local/share/kobra/plugins/exploit/
```

### 2. Run KOBRA dengan attack mode
```bash
kobra -t https://target.com --mode crazy --attack-suite
```

### 3. Auto-trigger
- `sqlmap-auto` triggered setiap finding SQLi terdeteksi
- `jwt-attack` triggered setiap auth_flow detects JWT
- `postgrest-pwn` triggered saat PostgREST endpoint found
- `chain-orchestrator` triggered saat ≥3 chainable findings

## 🔧 Customization

Edit JSON plugin untuk:
- Tambahin wordlist custom
- Set Tor/proxy untuk stealth
- Custom output dir
- Adjust timeout

## ⚠️ CATATAN

**INI TOOLS UNTUK AUTHORIZED TESTING ONLY.** Sebelum pake:
- ✅ Written authorization (bug bounty program)
- ✅ Scope sesuai rules
- ❌ JANGAN pake di target tanpa izin

## 📋 TODO (Future)

- [ ] Integrate ke KOBRA main binary (via plugin_v2)
- [ ] Tambah `Attack` mode ke Mode enum
- [ ] UI buat manage plugins dari CLI
- [ ] Auto-evade detection (UA rotation, jitter)
- [ ] Encrypted C2 channel
- [ ] PoC generator per vuln type
