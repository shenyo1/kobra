#!/bin/bash
# Deep recon: find REAL paths via gau/waybackurls/subjs, then KOBRA crazy.
OUT=/tmp/sumopod_deep
mkdir -p "$OUT"
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.cargo/bin:/home/shenyo1/.local/bin
D=sumopod.com

echo "=== [1] gau paths ==="
if command -v gau >/dev/null 2>&1; then
  echo "$D" | gau --blacklist js,png,css,svg,woff,ico --fc 404 2>/dev/null | grep "$D" | sort -u > "$OUT/gau.txt"
  echo "gau lines: $(wc -l < "$OUT/gau.txt" 2>/dev/null)"
else
  echo "gau missing"; : > "$OUT/gau.txt"
fi

echo "=== [2] waybackurls paths ==="
if command -v waybackurls >/dev/null 2>&1; then
  echo "$D" | waybackurls 2>/dev/null | grep "$D" | sort -u > "$OUT/wayback.txt"
  echo "wayback lines: $(wc -l < "$OUT/wayback.txt" 2>/dev/null)"
else
  echo "waybackurls missing"; : > "$OUT/wayback.txt"
fi

echo "=== [3] subjs (JS endpoints + secret grep) ==="
if command -v subjs >/dev/null 2>&1; then
  echo "$D" | subjs 2>/dev/null | grep -E "\.js" | sort -u > "$OUT/js.txt"
  echo "js lines: $(wc -l < "$OUT/js.txt" 2>/dev/null)"
  : > "$OUT/secrets.txt"
  while read -r js; do
    [ -z "$js" ] && continue
    curl -s --max-time 20 "$js" 2>/dev/null | grep -oiE "(api[_-]?key|secret|token|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|eyJ[A-Za-z0-9_-]+\.eyJ)" >> "$OUT/secrets.txt" 2>/dev/null
  done < "$OUT/js.txt"
  echo "secret hints: $(wc -l < "$OUT/secrets.txt" 2>/dev/null)"
else
  echo "subjs missing"; : > "$OUT/js.txt"; : > "$OUT/secrets.txt"
fi

echo "=== [4] Merge unique paths ==="
cat "$OUT/gau.txt" "$OUT/wayback.txt" 2>/dev/null | sed -E 's#https?://##; s#/[?].*##' | sort -u > "$OUT/paths_unique.txt"
echo "unique paths: $(wc -l < "$OUT/paths_unique.txt" 2>/dev/null)"

echo "=== [5] KOBRA crazy on discovered paths (max 40) ==="
n=0
while read -r path; do
  [ -z "$path" ] && continue
  n=$((n+1))
  if [ "$n" -gt 40 ]; then break; fi
  url="https://$path"
  echo ">> $url"
  timeout 90 kobra -t "$url" -m crazy -o "$OUT/scan_$(echo "$path" | sed 's#/#_#g').json" 2>/dev/null
done < "$OUT/paths_unique.txt"

echo "DEEP_DONE"