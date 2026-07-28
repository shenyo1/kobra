#!/usr/bin/env bash
set +e
H="${1:?host}"
OUT="probes/${H}.txt"
{
  echo "================================="
  echo "= $H : NORMAL GET /"
  echo "================================="
  curl -sk -o /dev/null -w "code=%{http_code} size=%{size_download} time=%{time_total}\n" --max-time 6 "https://${H}/" || true
  echo "--- response headers ---"
  curl -sk --max-time 6 -D - -o /dev/null "https://${H}/" 2>/dev/null | sed -n '1,40p'
  echo
  echo "================================="
  echo "= $H : WRONG HOST (CF error diagnostic)"
  echo "================================="
  curl -sk --max-time 6 -D - -o /dev/null "https://${H}/" -H "Host: nonexistent.invalid" 2>/dev/null | sed -n '1,30p'
  echo
} > "$OUT"
echo "wrote $OUT"
