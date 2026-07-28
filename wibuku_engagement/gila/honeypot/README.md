# wibuku.app Honeypot — Local Defensive Trap

A Flask-based honeypot that mimics the wibuku.app attack surface to detect
retaliatory scans, curious attackers, or anyone probing the discovered
Mass-ATO surface after our bug-bounty report goes public.

**LOCAL ONLY.** Binds `127.0.0.1:9999`. Do NOT expose publicly.

## Features

- **Decoy endpoints** that look vulnerable:
  - `GET /` — homepage
  - `GET /login` — sign-in HTML form (POSTs to `/api/auth/login`)
  - `GET /signup`, `GET /forgot` — registration / password-reset pages
  - `POST /api/auth/login` — fake login; logs email + length + IP + UA
  - `POST /api/auth/forgot` — fake forgot-password; logs email
  - `GET|POST /api/user/profile` — fake user profile JSON
  - `GET|POST /api/admin` — fake admin endpoint (403)
  - `GET /admin/login.html` — WordPress-style admin login form
  - `POST /admin/login.html` — fake WP login submit (records creds)
  - `GET /wp-admin` — redirects to admin login
  - `GET /.env` — fake leaked Laravel `.env`
  - `GET /config.json` — fake client config
  - `GET /api/debug/console?_t=TOKEN` — **canary** tracking endpoint
- **SQLite logging** at `hits.db`: every request captures timestamp, IP,
  country (best-effort GeoIP2), UA, method, path, query, referer, content-type,
  full headers, body, alert flag, alert reason, tracking id.
- **Per-request tracking IDs** (16-hex) embedded in fake JWTs and canary URLs
  — link a stolen token back to its originating request.
- **Honey credentials**: any login attempt or password-reset email is flagged
  as an alert (`is_alert=1`, `alert_reason` populated).
- **Dashboard** at `/dashboard` (basic auth: `honeypot_admin` / `trap_password`)
  with stats, recent hits, top paths / countries / user-agents, and a
  `/dashboard/export` markdown report download.
- **Deception**: Cloudflare-like headers (Server, CF-Ray, CF-Cache-Status,
  Expect-CT, NEL, Report-To, HSTS), ~150ms artificial latency, HTML pages
  styled like wibuku.app dark theme.

## Install

```bash
# optional: GeoIP country lookup
pip install geoip2

# required
pip install flask
```

The honeypot is fully functional without `geoip2` — country column shows `XX`.

## Run

```bash
cd /home/shenyo1/.local/opt/kobra/wibuku_engagement/gila/honeypot
python3 app.py
```

Then open <http://127.0.0.1:9999/dashboard> with creds
`honeypot_admin` / `trap_password`.

## File layout

```
honeypot/
├── app.py              # Flask app + decoy routes + SQLite logging
├── hits.db             # auto-created on first run
├── static/
│   └── style.css       # login-page CSS (mimics wibuku dark theme)
└── README.md           # this file
```

## Database schema

```sql
CREATE TABLE hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    ip TEXT NOT NULL,
    country TEXT,
    ua TEXT,
    method TEXT,
    path TEXT,
    query TEXT,
    referer TEXT,
    content_type TEXT,
    headers TEXT,
    body TEXT,
    is_alert INTEGER DEFAULT 0,
    alert_reason TEXT,
    tracking_id TEXT
);
```

## Alert taxonomy

| Alert reason | Trigger |
|---|---|
| `login_attempt: <email>` | POST to `/api/auth/login` |
| `forgot_password: <email>` | POST to `/api/auth/forgot` |
| `wp_admin_login_attempt` | POST to `/admin/login.html` |
| `admin_login_html_view` | GET `/admin/login.html` |
| `admin_endpoint_access` | GET or POST `/api/admin` |
| `dotenv_recon` | GET `/.env` |
| `config_recon` | GET `/config.json` |
| `canary_hit: token=...` | GET `/api/debug/console?_t=...` |

## How to use the canary

The `/api/debug/console` endpoint is a tracking trap. Anyone who hits it
gets recorded as an alert with `alert_reason="canary_hit: token=..."`.
Embed it as a hidden pixel in documents or share it as a "secret" URL.
Any request to that URL with a unique `_t` token will appear in the dashboard.

Example:

```html
<img src="http://127.0.0.1:9999/api/debug/console?_t=VICTIM-LEAK-2026-001"
     width="1" height="1" alt="">
```

Each visit to that URL creates a hit with `is_alert=1` and
`alert_reason="canary_hit: token=VICTIM-LEAK-2026-001 event=console_visit"`.

## Dashboard query examples

```bash
# Last 20 alerts
sqlite3 hits.db "SELECT ts, ip, country, alert_reason, tracking_id FROM hits WHERE is_alert=1 ORDER BY id DESC LIMIT 20"

# All hits from a specific IP
sqlite3 hits.db "SELECT * FROM hits WHERE ip='1.2.3.4' ORDER BY id DESC"

# Top attacker IPs
sqlite3 hits.db "SELECT ip, country, COUNT(*) c FROM hits WHERE is_alert=1 GROUP BY ip ORDER BY c DESC LIMIT 20"
```

## Warnings

- **Do NOT** change `BIND_HOST` to `0.0.0.0` without explicit authorization.
  This honeypot exists for local research only.
- `trap_password` is hardcoded for local use. Change `DASH_USER`/`DASH_PASS`
  if shipping.
- All "leaked" credentials (`.env`, fake AWS keys, fake Stripe keys) are
  obvious decoys (`AKIAFAKEHONEYPOTKEY`, `sk_live_fake_honeypot`).