#!/bin/bash
# Per-host probe: GraphQL + actuator + admin + API discovery
H="$1"
PROTO="https"
BASE="$PROTO://$H"
OUT="$2"
mkdir -p "$OUT"
> "$OUT/probes.tsv"
> "$OUT/graphql_hits.txt"
> "$OUT/actuator_hits.txt"
> "$OUT/admin_hits.txt"
> "$OUT/api_hits.txt"
> "$OUT/bypass_hits.txt"

probe() {
    local p="$1"
    local kind="$2"
    local code ct size redir
    read -r code size ct redir < <(curl -sk -o "$OUT/${p//\//_}.body" -w "%{http_code} %{size_download} %{content_type} %{redirect_url}" --max-time 10 "$BASE$p" 2>/dev/null | tr '|' ' ')
    [ -z "$code" ] && return
    echo -e "$H\t$p\t$code\t$size\t$ct\t$redir\t$kind" >> "$OUT/probes.tsv"
    case "$kind" in
        graphql)
            if [ "$code" != "404" ] && [ "$code" != "000" ]; then
                echo -e "$H\t$p\t$code\tGET" >> "$OUT/graphql_hits.txt"
            fi
            # POST introspection
            pcode=$(curl -sk -o "$OUT/${p//\//_}_post.body" -w "%{http_code}" -H "Content-Type: application/json" -X POST --data '{"query":"{__schema{types{name}}}"}' --max-time 8 "$BASE$p" 2>/dev/null)
            if [ -n "$pcode" ] && [ "$pcode" != "404" ] && [ "$pcode" != "405" ] && [ "$pcode" != "000" ]; then
                echo -e "$H\t$p\t$pcode\tPOST" >> "$OUT/graphql_hits.txt"
            fi
            # GET introspection
            gcode=$(curl -sk -o "$OUT/${p//\//_}_getq.body" -w "%{http_code}" -H "Content-Type: application/json" -G --data-urlencode 'query={__schema{types{name}}}' --max-time 8 "$BASE$p" 2>/dev/null)
            if [ -n "$gcode" ] && [ "$gcode" != "404" ] && [ "$gcode" != "000" ]; then
                echo -e "$H\t$p\t$gcode\tGET-INTRO" >> "$OUT/graphql_hits.txt"
            fi
            # batch query
            bcode=$(curl -sk -o "$OUT/${p//\//_}_batch.body" -w "%{http_code}" -H "Content-Type: application/json" -X POST --data '[{"query":"{__schema{queryType{name}}}"}]' --max-time 8 "$BASE$p" 2>/dev/null)
            if [ -n "$bcode" ] && [ "$bcode" != "404" ] && [ "$bcode" != "405" ] && [ "$bcode" != "000" ]; then
                echo -e "$H\t$p\t$bcode\tBATCH" >> "$OUT/graphql_hits.txt"
            fi
            # field suggestion
            scode=$(curl -sk -o "$OUT/${p//\//_}_sugg.body" -w "%{http_code}" -H "Content-Type: application/json" -X POST --data '{"query":"{ user { id emaail }}"}' --max-time 8 "$BASE$p" 2>/dev/null)
            if [ -n "$scode" ] && [ "$scode" != "404" ] && [ "$scode" != "000" ]; then
                echo -e "$H\t$p\t$scode\tSUGG" >> "$OUT/graphql_hits.txt"
            fi
            # deep recursion
            dcode=$(curl -sk -o "$OUT/${p//\//_}_deep.body" -w "%{http_code}" -H "Content-Type: application/json" -X POST --data "{\"query\":\"{__schema{types{fields{type{ofType{ofType{ofType{ofType{name}}}}}}}}}\"}" --max-time 8 "$BASE$p" 2>/dev/null)
            if [ -n "$dcode" ] && [ "$dcode" != "404" ] && [ "$dcode" != "000" ]; then
                echo -e "$H\t$p\t$dcode\tDEEP" >> "$OUT/graphql_hits.txt"
            fi
            ;;
        actuator)
            if [ "$code" != "404" ] && [ "$code" != "000" ]; then
                echo -e "$H\t$p\t$code" >> "$OUT/actuator_hits.txt"
            fi
            ;;
        admin)
            if [ "$code" != "404" ] && [ "$code" != "000" ]; then
                echo -e "$H\t$p\t$code" >> "$OUT/admin_hits.txt"
            fi
            # X-Original-URL bypass
            bcode=$(curl -sk -o "$OUT/${p//\//_}_bypass1.body" -H "X-Original-URL: $p" -w "%{http_code}" --max-time 8 "$BASE/" 2>/dev/null)
            if [ -n "$bcode" ] && [ "$bcode" != "404" ] && [ "$bcode" != "000" ] && [ "$bcode" != "$code" ]; then
                echo -e "$H\t$p\t$bcode\tX-Original-URL" >> "$OUT/bypass_hits.txt"
            fi
            bcode2=$(curl -sk -o "$OUT/${p//\//_}_bypass2.body" -H "X-Rewrite-URL: $p" -w "%{http_code}" --max-time 8 "$BASE/" 2>/dev/null)
            if [ -n "$bcode2" ] && [ "$bcode2" != "404" ] && [ "$bcode2" != "000" ] && [ "$bcode2" != "$code" ]; then
                echo -e "$H\t$p\t$bcode2\tX-Rewrite-URL" >> "$OUT/bypass_hits.txt"
            fi
            ;;
        api)
            if [ "$code" != "404" ] && [ "$code" != "000" ]; then
                echo -e "$H\t$p\t$code" >> "$OUT/api_hits.txt"
            fi
            ;;
    esac
}

# --- GraphQL ---
for g in "/graphql" "/api/graphql" "/gql" "/v1/graphql" "/graphql/v1" "/api/v1/graphql" "/api/v1/graphql/" "/query" "/schema" "/api/query" "/gql/v1" "/api/gql" "/api/graphql/v1" "/api/schema" "/graphql/schema" "/api/gql/v1" "/graphql/playground" "/graphiql" "/explorer" "/api/explorer"; do
    probe "$g" "graphql"
done

# --- Actuator / Debug / Health / Swagger ---
for a in "/actuator" "/actuator/" "/actuator/env" "/actuator/mappings" "/actuator/heapdump" "/actuator/health" "/actuator/info" "/actuator/beans" "/actuator/configprops" "/actuator/loggers" "/actuator/metrics" "/actuator/trace" "/actuator/threaddump" "/actuator/conditions" "/actuator/caches" "/actuator/auditevents" "/actuator/scheduledtasks" "/actuator/httptrace" "/actuator/jolokia" "/actuator/prometheus" "/actuator/sessions" "/actuator/shutdown" "/debug" "/debug/vars" "/debug/pprof" "/_debug" "/_debugbar" "/admin/debug" "/admin/health" "/admin/info" "/health" "/info" "/status" "/ready" "/live" "/liveness" "/readiness" "/startup" "/swagger-ui.html" "/swagger" "/api-docs" "/api-docs/swagger.json" "/v2/api-docs" "/v3/api-docs" "/v3/api-docs/swagger-ui" "/swagger-ui/swagger-ui.html" "/openapi.json" "/openapi.yaml" "/swagger.json" "/swagger.yaml" "/swagger/v1/swagger.json" "/swagger/v2/swagger.json" "/.well-known/openid-configuration" "/.well-known/openapi" "/sitemap.xml" "/robots.txt" "/humans.txt" "/security.txt" "/trace" "/trace.axd" "/server-status" "/server-info" "/api/swagger" "/api/swagger-ui" "/api/openapi.json" "/api/v1/swagger.json" "/api/v1/openapi.json" "/api/v2/swagger.json" "/api/v2/openapi.json"; do
    probe "$a" "actuator"
done

# --- Admin panels ---
for p in "/admin" "/admin/" "/administrator" "/administrator/" "/admin.php" "/admin/login" "/admin/index" "/admin/dashboard" "/admin/index.php" "/admin/index.html" "/admin/home" "/admin/console" "/admin/panel" "/admin/cp" "/admin/management" "/admin/manage" "/wp-admin" "/wp-admin/" "/wp-login.php" "/dashboard" "/panel" "/panel/" "/management" "/management/" "/backoffice" "/backoffice/" "/cpanel" "/cpanel/" "/manager" "/manager/" "/console" "/controlpanel" "/cp" "/moderator" "/superadmin" "/siteadmin" "/user/login" "/login" "/login/" "/login.php" "/admin/config" "/admin/config.php" "/admin/config.json" "/admin/setting" "/api/admin" "/api/user" "/api/users" "/api/me" "/api/account"; do
    probe "$p" "admin"
done

# --- API discovery ---
for r in "/api" "/api/" "/api/v1" "/api/v2" "/api/v3" "/v1" "/v2" "/v3" "/rest" "/rest/v1" "/rest/v2" "/rest/api" "/api/rest" "/json" "/api/json" "/api/health" "/api/ping" "/api/status" "/api/info" "/api/version" "/api/me" "/api/user" "/api/users" "/api/posts" "/api/comments" "/api/search" "/api/login" "/api/auth" "/api/token" "/api/session" "/oauth/token" "/oauth/authorize" "/.well-known/openid-configuration" "/.well-known/oauth-authorization-server" "/.well-known/jwks.json" "/auth" "/auth/" "/auth/v1" "/auth/v1/authorize" "/auth/v1/token" "/api/auth/login" "/api/auth/register" "/api/auth/me" "/auth/login" "/auth/register"; do
    probe "$r" "api"
done

sort -u "$OUT/probes.tsv" -o "$OUT/probes.tsv" 2>/dev/null
sort -u "$OUT/graphql_hits.txt" -o "$OUT/graphql_hits.txt" 2>/dev/null
sort -u "$OUT/actuator_hits.txt" -o "$OUT/actuator_hits.txt" 2>/dev/null
sort -u "$OUT/admin_hits.txt" -o "$OUT/admin_hits.txt" 2>/dev/null
sort -u "$OUT/api_hits.txt" -o "$OUT/api_hits.txt" 2>/dev/null
sort -u "$OUT/bypass_hits.txt" -o "$OUT/bypass_hits.txt" 2>/dev/null
echo "DONE $H -> $OUT"
