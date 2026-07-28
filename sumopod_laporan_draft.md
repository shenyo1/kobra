# Laporan Bug Bounty Sumopod — Final (2026-07-26)
**Peneliti:** Afif (authorized BB program)
**Scope:** sumopod.com + *.sumopod.com
**Akun test:** kobrasumopod1785066601@web-library.net (temp mail)

---

## Temuan Valid

### 1. 🔴 Profile Email Manipulation (Medium-High)
**Severity:** Medium-High | **CVSS:** 6.5
**Target:** `dhsrwbufpdvuptdzeieo.supabase.co/rest/v1/profiles`

User dapat mengubah `profiles.email` ke email siapapun (termasuk `admin@sumopod.com`) tanpa verifikasi. Auth email tidak ikut berubah.

**Bukti:**
```bash
PATCH /rest/v1/profiles?id=eq.<user_id>
Authorization: Bearer <token>
{"email":"admin@sumopod.com"}
→ 204 Success
```

**Dampak:** Impersonation, privilege escalation jika backend menggunakan `profiles.email` untuk permission check.

**Remediation:** Hapus `email` dari UPDATE columns di RLS policy, atau sync dengan `auth.users.email`.

**Status:** Email sudah di-revert.

---

### 2. 🟡 Schema Leak via PostgREST Error (Low-Medium)
**Severity:** Low-Medium | **CVSS:** 5.3

PostgREST error messages membocorkan nama kolom tabel:
- `payments`: id, amount, status, created_at, user_id, payment_method, currency
- `transactions`: id, amount, created_at, user_id, description
- `templates`: id, name, description, price, category
- `profiles`: id, first_name, last_name, full_name, company, website, billing_address, email, email_marketing, city, province, address, country, phone_country_code, phone_number, postal_code, mobile_number, mobile_country_code

**Remediation:** Nonaktifkan detail error di PostgREST (`db-error-handler` minimal).

---

### 3. 🟢 Kong Header Info Leak (Info)
`X-Kong-Upstream-Latency`, `X-Kong-Proxy-Latency`, `X-Kong-Request-Id`, `RateLimit-*` exposed.

---

## Yang Aman (Dibuktikan)

| Check | Status |
|-------|--------|
| RLS profiles/payments/transactions | ✅ 0 rows to anon |
| RLS INSERT payments | ✅ 42501 blocked |
| IDOR profiles (access other user) | ✅ Blocked |
| IDOR payments (`user_id=neq.own`) | ✅ 0 rows |
| Mass assignment (role/is_admin/balance) | ✅ Column not in schema |
| Admin endpoint | ✅ 403 |
| Captcha (all auth endpoints) | ✅ Required |
| Realtime | ✅ Disabled |
| Storage buckets | ✅ Empty (no public) |
| RPC (stored procedures) | ✅ None exposed |
| Edge functions | ✅ None exposed |
| OpenAPI spec | ✅ service_role only |
| Direct SQL execution | ✅ Not available |

---

## Endpoint Surface (Authenticated)

### Supabase (dhsrwbufpdvuptdzeieo.supabase.co)
- `GET /rest/v1/profiles` — data sendiri (RLS)
- `GET /rest/v1/payments` — kosong
- `GET /rest/v1/transactions` — kosong
- `GET /rest/v1/templates` — kosong
- `PATCH /rest/v1/profiles` — email manipulation ✅ FINDING

### api-pay.sumopod.com (Kong gateway)
- `GET /api/v1/merchant/access` — `not_registered`
- `POST /api/v1/merchant/payments/{id}/simulate-xenith` — `MERCHANT_NOT_FOUND`
- `POST /api/v1/merchant/payments/{id}/cancel` — `MERCHANT_NOT_FOUND`
- `GET/POST /api/v1/merchant/payments` — `MERCHANT_NOT_FOUND`
- `GET /api/v1/merchant/withdrawals` — `MERCHANT_NOT_FOUND`

### api-pay-sandbox.sumopod.com
- Sama seperti api-pay (sandbox environment)

---

## Keterbatasan
- **Merchant onboarding**: endpoint tidak ditemukan via API (butuh UI dashboard)
- **AI (ai.sumopod.com)**: endpoint AI tidak ditemukan di pre-auth maupun authenticated
- **Multi-tenant**: butuh 2 akun authenticated (akun ke-2 bisa dibuat dengan flow yang sama)
- **Browser**: tidak stabil (CDP WebSocket 502), session harus di-refresh manual

---

## Rekomendasi
1. **Prioritaskan fixing Profile Email Manipulation** — bisa jadi privilege escalation
2. **Nonaktifkan PostgREST error detail** di production
3. **Strip internal Kong headers** di Cloudflare
4. **Audit merchant onboarding flow** — pastikan tidak ada IDOR/price tamper di simulate-xenith
