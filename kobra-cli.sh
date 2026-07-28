#!/bin/bash
# KOBRA CLI untuk orang awam — bahasa Indonesia, gampang.
# Cara pakai:
#   ./kobra-cli.sh bantuan          -> lihat semua perintah
#   ./kobra-cli.sh scan https://x.com -> scan satu situs (mode crazy)
#   ./kobra-cli.sh scan aman https://x.com -> scan pelan (stealth)
#   ./kobra-cli.sh borong sumopod.com -> scan semua subdomain + fuzzing
#   ./kobra-cli.sh cek api-pay.sumopod.com -> cek satu endpoint penting
#
# CATATAN PENTING: hanya pakai di situs yang ANDA beri izin (bug bounty / lab).
# Jangan pakai ke situs orang tanpa izin. Itu ilegal.

set -e
KOBRA=$(command -v kobra || echo "$HOME/.local/bin/kobra")
OUT="${KOBRA_OUT:-$HOME/kobra-hasil}"

mkdir -p "$OUT"

tampilkan_bantuan() {
  cat <<'EOF'
============================================
KOBRA — Pemindai Kerentanan Web (Bug Bounty)
============================================
Untuk pemula. Semua perintah aman jika dipakai di situs berizin.

Perintah:
  bantuan
      Lihat daftar perintah ini.

  scan <URL>
      Pindai 1 situs dengan mode agresif (crazy).
      Contoh: ./kobra-cli.sh scan https://contoh.com

  scan aman <URL>
      Pindai 1 situs dengan mode pelan (stealth) — lebih sulit ketahuan.
      Contoh: ./kobra-cli.sh scan aman https://contoh.com

  borong <domain>
      Pindai semua subdomain + cari jalur tersembunyi (butuh tools tambahan).
      Contoh: ./kobra-cli.sh borong sumopod.com

  cek <URL>
      Cek cepat 1 endpoint (header, auth, WAF).
      Contoh: ./kobra-cli.sh cek https://api-pay.sumopod.com

  hasil
      Buka folder hasil pindai.
      Lokasi: ~/kobra-hasil

Contoh nyata:
  ./kobra-cli.sh scan https://situz-saya.com
  ./kobra-cli.sh borong perusahaan.com

Hasil disimpan di: ~/kobra-hasil (format .json dan .md)
============================================
EOF
}

perintah="$1"
case "$perintah" in
  bantuan|--help|-h|"")
    tampilkan_bantuan
    ;;
  scan)
    mode="crazy"
    url="$2"
    if [ "$url" = "aman" ]; then mode="stealth"; url="$3"; fi
    if [ -z "$url" ]; then echo "Error: URL kosong. Coba: ./kobra-cli.sh scan https://contoh.com"; exit 1; fi
    echo ">> Memindai $url (mode: $mode)..."
    "$KOBRA" -t "$url" -m "$mode" -j -o "$OUT/scan_$(echo "$url" | sed 's#[^a-zA-Z0-9]#_#g').json"
    echo ">> Selesai. Lihat hasil di $OUT/"
    ;;
  borong)
    domain="$2"
    if [ -z "$domain" ]; then echo "Error: domain kosong."; exit 1; fi
    echo ">> Borong scan $domain (recon + kobra + fuzz)..."
    python3 "$(dirname "$0")/kobra-orchestrator.py" --target "$domain" --out "$OUT/borong_$(echo "$domain" | sed 's#[^a-zA-Z0-9]#_#g')" -m crazy 2>&1 | tail -20
    echo ">> Selesai. Lihat $OUT/"
    ;;
  cek)
    url="$2"
    if [ -z "$url" ]; then echo "Error: URL kosong."; exit 1; fi
    echo ">> Cek $url ..."
    "$KOBRA" -t "$url" -m normal 2>&1 | grep -iE "HIGH|CRITICAL|MEDIUM|WAF|AUTH|CLOUDFLARE|ATO|MASS" | head -20
    ;;
  hasil)
    echo "Buka folder: $OUT"
    ls -la "$OUT" 2>/dev/null | head -20
    ;;
  *)
    echo "Perintah tidak dikenal: $perintah"
    tampilkan_bantuan
    ;;
esac
