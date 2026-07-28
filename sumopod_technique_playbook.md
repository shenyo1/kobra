# SUMOPOD 2026 TECHNIQUE PLAYBOOK (dari riset web/X/GitHub 2026-07-26)
# Ilmu terbaru + cara test di sumopod (RoE: pre-auth, non-destructive, stop before RCE)

============================================================
A. CLOUDFLARE ERROR HEADERS (dok Apr 2026)
============================================================
- Header `cf-error-type` + `cf-error-origin` muncul HANYA di CF-generated error.
- Nilai: 1000 (DNS fail), 1016 (origin DNS), 1101 (Worker exception), 52x (origin conn).
- Test: curl -v https://<host>/<random> -> cek header cf-error-type.
- Sumopod: kalau balikin error CF (bukan Kong), header ini kasih tau origin system.
- Gunanya: origin IP discovery / infra mapping.

============================================================
B. MAGIC-LINK PRE-ACCOUNT HIJACKING (GHSA-qq9h-g4jm-xgf3, better-auth)
============================================================
- Sumopod pakai magic-link OTP -> SANGAT RELEVAN.
- Teknik: attacker signup dgn email KORBAN. Kalau server balikin magic-link/token
  di RESPONSE BODY (bukan cuma email), attacker bisa login SEBELUM korban = ATO.
- Test (non-destructive): POST /api/auth/sign-up {"email":"victim@sumopod.com"}
  -> cek response body ada "token"/"link"/"magic" -> PRE-ACCOUNT HIJACK.
- Catatan: ini pre-auth, gak butuh akun. RoE izinin (gak merusak).

============================================================
C. KONG API GATEWAY
============================================================
- Sumopod pakai Kong (response "no Route matched" dari round-4).
- Header `X-Kong-Upstream-Latency` / `X-Kong-Proxy-Latency` -> leak upstream timing/infra.
- CVE-2026-6338: HTTP Request Smuggling di kong-enterprise-gateway.
- Test: curl -I https://<host>/ -> cek X-Kong-* headers.

============================================================
D. PAYMENT LOGIC (api-pay, P1 program)
============================================================
- Price manipulation via broken checkout logic: tamper param `price`/`quantity`/
  `payment_method_id`/`user_id` di request checkout.
- Butuh akun (magic-link OTP ke email sendiri) -> test antar akun sendiri.
- Non-destructive: jangan bikin transaksi beneran, cuma observasi response.

============================================================
E. GRAPHQL BATCHING ATTACK (rate-limit bypass)
============================================================
- Kirim array of queries [{query},{query}...] ke /graphql.
- Kalau server terima -> batching abuse (bypass rate-limit, alias DoS).
- Test: POST /graphql [{"query":"{__typename}"}] -> 200 + data = vulnerable.

============================================================
F. MULTI-TENANT IDOR (UUID swap)
============================================================
- Ganti object ID (UUID) di URL/body dgn punya akun lain -> akses data tenant lain.
- Butuh akun (test antar akun sendiri, safe).
- CVE-2026-41948 (DifyTap): unencoded ../ di task_id/file/tenant.

============================================================
STATUS KOBRA: module research2026.rs DITAMBAH (cf_probe + magiclink + graphql_batch).
Build + test di sumopod sedang jalan.
