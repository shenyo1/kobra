#!/usr/bin/env python3
"""
wibuku.app Honeypot - Local defensive/research trap.

PURPOSE: Detect retaliatory scans / curious attackers probing the discovered
Mass ATO surface. Binds 127.0.0.1:9999 ONLY. DO NOT EXPOSE PUBLICLY.

Features:
  - Decoy endpoints mimicking wibuku.app + typical recon targets
  - SQLite logging of every request (timestamp, ip, ua, headers, body)
  - Per-request unique session tokens (tracking IDs)
  - Canary URLs for tracking who visits
  - Honey credentials: any login attempt creates an alert
  - /dashboard (basic auth)
  - Cloudflare-like response headers + ~150ms artificial latency
"""

import base64
import json
import os
import random
import secrets
import sqlite3
import string
import sys
import time
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, Response, abort, g, jsonify, render_template_string, request,
)

BIND_HOST = "127.0.0.1"
BIND_PORT = 9999
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "hits.db")

DASH_USER = "honeypot_admin"
DASH_PASS = "trap_password"

GEOIP_CANDIDATES = [
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/var/lib/GeoIP/GeoLite2-Country.mmdb",
    os.path.expanduser("~/.local/share/GeoIP/GeoLite2-Country.mmdb"),
]

_geoip_reader = None
try:
    import geoip2.database  # type: ignore
    for _c in GEOIP_CANDIDATES:
        if os.path.exists(_c):
            try:
                _geoip_reader = geoip2.database.Reader(_c)
                print(f"[honeypot] GeoIP2 loaded: {_c}", file=sys.stderr)
                break
            except Exception as e:
                print(f"[honeypot] GeoIP2 init failed: {e}", file=sys.stderr)
except ImportError:
    pass


def lookup_country(ip):
    if not _geoip_reader or not ip:
        return "XX"
    try:
        if ip.startswith("127.") or ip == "::1":
            return "LO"
        r = _geoip_reader.country(ip)
        return r.country.iso_code or "XX"
    except Exception:
        return "XX"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS hits (
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
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hits_ts ON hits(ts)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hits_ip ON hits(ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_hits_alert ON hits(is_alert)")
    conn.commit()
    conn.close()


def get_client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_tracking_id():
    return secrets.token_hex(8)


def fake_session_token(tracking_id):
    # JWT-ish lookalike that encodes our tracking id
    rand = secrets.token_urlsafe(24)
    payload = base64.urlsafe_b64encode(
        json.dumps({"tid": tracking_id, "jti": secrets.token_hex(8)}).encode()
    ).rstrip(b"=").decode()
    return f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{payload}.{secrets.token_hex(16)}"


def cloudflare_headers():
    """Build Cloudflare-like response headers to blend with real CF traffic."""
    h = {
        "Server": "cloudflare",
        "CF-Ray": f"{secrets.token_hex(8)}-FRA",
        "CF-Cache-Status": random.choice(["DYNAMIC", "MISS", "HIT", "BYPASS"]),
        "CF-Request-Id": secrets.token_hex(8),
        "Expect-CT": f'max-age=86400, enforce, report-uri="https://wibuku.app/ct-report"',
        "Report-To": '{"group":"cf-nel","max_age":604800,"endpoints":[{"url":"https://a.nel.cloudflare.com/report/v3?s=wibuku"}]}',
        "NEL": '{"report_to":"cf-nel","max_age":604800}',
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    }
    return h


def artificial_latency():
    """Mimic real wibuku.app ~150ms response time."""
    delay = random.gauss(0.15, 0.04)
    if delay < 0.02:
        delay = 0.02
    time.sleep(delay)


def log_hit(*, ip, ua, method, path, query, referer, content_type,
            headers, body, is_alert=0, alert_reason="", tracking_id=""):
    country = lookup_country(ip)
    try:
        body_str = body if isinstance(body, str) else str(body)
        if len(body_str) > 65536:
            body_str = body_str[:65536] + "...[truncated]"
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            """INSERT INTO hits
               (ts, ip, country, ua, method, path, query, referer,
                content_type, headers, body, is_alert, alert_reason, tracking_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (now_iso(), ip, country, ua, method, path, query, referer,
             content_type, json.dumps(dict(headers)), body_str,
             is_alert, alert_reason, tracking_id),
        )
        conn.commit()
        conn.close()
        try:
            from flask import g as _g
            _g.honeypot_already_logged = True
        except Exception:
            pass
    except Exception as e:
        print(f"[honeypot] log_hit failed: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Flask app + request hooks
# ---------------------------------------------------------------------------

app = Flask(
    __name__,
    static_folder=os.path.join(BASE_DIR, "static"),
)


@app.before_request
def _before():
    g.t0 = time.time()
    g.tracking_id = new_tracking_id()
    g.honeypot_already_logged = False
    request.environ["honeypot_tid"] = g.tracking_id


@app.after_request
def _after(resp):
    try:
        artificial_latency()
        cf = cloudflare_headers()
        for k, v in cf.items():
            resp.headers.setdefault(k, v)
        resp.headers.setdefault("X-Powered-By", "Express")
        # Only auto-log if the handler didn't already log explicitly
        if not g.get("honeypot_already_logged", False):
            body = ""
            try:
                body = request.get_data(cache=True, as_text=True)
            except Exception:
                body = ""
            log_hit(
                ip=get_client_ip(),
                ua=request.headers.get("User-Agent", ""),
                method=request.method,
                path=request.path,
                query=request.query_string.decode("utf-8", errors="replace"),
                referer=request.headers.get("Referer", ""),
                content_type=request.headers.get("Content-Type", ""),
                headers=request.headers,
                body=body,
                tracking_id=g.tracking_id,
            )
    except Exception as e:
        print(f"[honeypot] _after failed: {e}", file=sys.stderr)
    return resp


@app.errorhandler(404)
def _not_found(e):
    body = ""
    try:
        body = request.get_data(cache=True, as_text=True)
    except Exception:
        pass
    log_hit(
        ip=get_client_ip(), ua=request.headers.get("User-Agent", ""),
        method=request.method, path=request.path,
        query=request.query_string.decode("utf-8", errors="replace"),
        referer=request.headers.get("Referer", ""),
        content_type=request.headers.get("Content-Type", ""),
        headers=request.headers, body=body, tracking_id=g.tracking_id,
    )
    html = """<!DOCTYPE html><html><head><title>404 Not Found | wibuku</title>
<style>body{font-family:-apple-system,Segoe UI,sans-serif;background:#0f1419;color:#e7e9ea;
margin:0;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}
.box{max-width:480px;padding:32px}h1{font-size:96px;margin:0;color:#1d9bf0}
p{color:#71767b;line-height:1.5}a{color:#1d9bf0;text-decoration:none}
a:hover{text-decoration:underline}.logo{font-weight:700;color:#1d9bf0;font-size:28px;margin-bottom:24px}
</style></head><body><div class="box"><div class="logo">wibuku</div>
<h1>404</h1><p>The page you're looking for doesn't exist or has been moved.</p>
<p><a href="/">Go home</a> &middot; <a href="/login">Sign in</a></p></div></body></html>"""
    return Response(html, status=404, content_type="text/html; charset=utf-8")


# ---------------------------------------------------------------------------
# Decoy endpoints
# ---------------------------------------------------------------------------

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to wibuku</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="container">
  <div class="card">
    <div class="logo">wibuku</div>
    <h1>Sign in</h1>
    <form method="POST" action="/api/auth/login" id="loginForm">
      <input type="email" name="email" placeholder="Email or username" required autocomplete="username">
      <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
    <div class="links"><a href="/forgot">Forgot password?</a> &middot; <a href="/signup">Sign up</a></div>
    <div class="legal">By signing in you agree to our Terms and Privacy Policy.</div>
  </div>
</div>
<script>
document.getElementById('loginForm').addEventListener('submit', function(e) {
  try {
    var img = new Image();
    img.src = '/api/debug/console?_t={{TID}}&event=login_submit';
  } catch(_) {}
});
</script>
</body>
</html>"""


@app.route("/", methods=["GET"])
def index():
    html = """<!DOCTYPE html><html><head><title>wibuku</title>
<style>body{font-family:-apple-system,sans-serif;background:#0f1419;color:#e7e9ea;
margin:0;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center}
.box{max-width:600px;padding:32px}.logo{font-size:48px;color:#1d9bf0;font-weight:800;margin-bottom:16px}
.tagline{color:#71767b;font-size:18px;margin-bottom:32px}
.cta{display:inline-block;margin:8px;padding:12px 24px;border-radius:24px;
text-decoration:none;font-weight:700}.cta-primary{background:#1d9bf0;color:#fff}
.cta-secondary{border:1px solid #536471;color:#e7e9ea}
</style></head><body><div class="box">
<div class="logo">wibuku</div>
<div class="tagline">See what's happening in the world right now.</div>
<a class="cta cta-primary" href="/login">Sign in</a>
<a class="cta cta-secondary" href="/signup">Create account</a>
</div></body></html>"""
    return Response(html, status=200, content_type="text/html; charset=utf-8")


@app.route("/login", methods=["GET"])
def login_get():
    html = LOGIN_HTML.replace("{{TID}}", g.tracking_id)
    return Response(html, status=200, content_type="text/html; charset=utf-8")


@app.route("/signup", methods=["GET"])
def signup_get():
    html = LOGIN_HTML.replace("Sign in", "Sign up").replace("{{TID}}", g.tracking_id)
    return Response(html, status=200, content_type="text/html; charset=utf-8")


@app.route("/forgot", methods=["GET"])
def forgot_get():
    html = """<!DOCTYPE html><html><head><title>Reset password | wibuku</title>
<style>body{font-family:-apple-system,sans-serif;background:#0f1419;color:#e7e9ea;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#16202c;padding:32px;border-radius:16px;width:360px}
.logo{color:#1d9bf0;font-weight:700;font-size:24px;margin-bottom:16px}
input{width:100%;padding:12px;margin:8px 0;background:#0f1419;border:1px solid #2f3336;
border-radius:8px;color:#e7e9ea;box-sizing:border-box}
button{width:100%;padding:12px;background:#1d9bf0;color:#fff;border:none;
border-radius:8px;font-weight:700;cursor:pointer;margin-top:8px}
</style></head><body><div class="box"><div class="logo">wibuku</div>
<h2>Find your account</h2>
<form method="POST" action="/api/auth/forgot">
<input type="email" name="email" placeholder="Email" required>
<button type="submit">Send reset link</button>
</form></div></body></html>"""
    return Response(html, status=200, content_type="text/html; charset=utf-8")


@app.route("/api/auth/forgot", methods=["POST"])
def auth_forgot_post():
    email = ""
    if request.is_json:
        try:
            email = (request.json or {}).get("email", "")
        except Exception:
            email = ""
    if not email:
        email = request.form.get("email", "")
    log_hit(
        ip=get_client_ip(), ua=request.headers.get("User-Agent", ""),
        method="POST", path=request.path, query="",
        referer=request.headers.get("Referer", ""),
        content_type=request.headers.get("Content-Type", ""),
        headers=request.headers, body=email,
        is_alert=1, alert_reason=f"forgot_password: {email}",
        tracking_id=g.tracking_id,
    )
    return jsonify({"ok": True, "message": "If that email exists, a reset link has been sent."}), 200


@app.route("/api/auth/login", methods=["POST"])
def auth_login_post():
    email = password = ""
    if request.is_json:
        try:
            data = request.json or {}
            email = data.get("email", "") or data.get("username", "")
            password = data.get("password", "")
        except Exception:
            pass
    if not email:
        email = request.form.get("email", "") or request.form.get("username", "")
        password = request.form.get("password", "")
    log_hit(
        ip=get_client_ip(), ua=request.headers.get("User-Agent", ""),
        method="POST", path=request.path, query="",
        referer=request.headers.get("Referer", ""),
        content_type=request.headers.get("Content-Type", ""),
        headers=request.headers,
        body=json.dumps({"email": email, "password_len": len(password)}),
        is_alert=1, alert_reason=f"login_attempt: {email}",
        tracking_id=g.tracking_id,
    )
    token = fake_session_token(g.tracking_id)
    return jsonify({
        "ok": True, "token": token, "session_id": g.tracking_id,
        "user": {"id": 1, "email": email,
                 "username": email.split("@")[0] if "@" in email else email},
    }), 200


@app.route("/api/user/profile", methods=["GET", "POST"])
def user_profile():
    tid = g.tracking_id
    return jsonify({
        "id": 1337, "email": "victim+sample@wibuku.app", "username": "victim_sample",
        "display_name": "Victim Sample",
        "bio": "Sample profile served from the wibuku honeypot.",
        "tracking_id": tid, "created_at": "2021-03-15T08:22:11Z",
        "verified": True, "follower_count": 142, "following_count": 87,
        "session_token": fake_session_token(tid),
    }), 200


@app.route("/api/admin", methods=["GET", "POST"])
def admin_endpoint():
    log_hit(
        ip=get_client_ip(), ua=request.headers.get("User-Agent", ""),
        method=request.method, path=request.path,
        query=request.query_string.decode("utf-8", errors="replace"),
        referer=request.headers.get("Referer", ""),
        content_type=request.headers.get("Content-Type", ""),
        headers=request.headers,
        body=(request.get_data(cache=True, as_text=True) if request.method == "POST" else ""),
        is_alert=1, alert_reason="admin_endpoint_access",
        tracking_id=g.tracking_id,
    )
    return jsonify({
        "ok": False, "error": "Forbidden",
        "message": "Admin access required. Provide valid X-Admin-Token header.",
        "admin_token_hint": "X-Admin-Token: <contact ops>",
        "tracking_id": g.tracking_id,
    }), 403


@app.route("/admin/login.html", methods=["GET"])
def admin_login_html():
    html = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>wp-login &middot; wibuku CMS</title>
<style>body{font-family:-apple-system,sans-serif;background:#f0f0f1;margin:0;padding:64px 0}
.login form{margin-left:auto;margin-right:auto;width:320px;background:#fff;
padding:24px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1)}
.login h1{font-weight:400;text-align:center;color:#23282d;margin:0 0 16px}
.login label{display:block;margin-bottom:8px;color:#23282d}
.login input[type=text],.login input[type=password]{width:100%;padding:8px;
border:1px solid #ddd;border-radius:4px;box-sizing:border-box;margin-bottom:16px}
.login .submit{text-align:right}
.login button{background:#0085ba;border:none;color:#fff;padding:8px 16px;
border-radius:4px;cursor:pointer;font-weight:600}
</style></head><body class="login">
<form method="POST" action="/admin/login.html" id="loginform">
<h1><a href="/">wibuku CMS</a></h1>
<label for="user_login">Username or Email</label>
<input type="text" name="log" id="user_login" required>
<label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" required>
<div class="submit"><button type="submit">Log In</button></div>
</form></body></html>"""
    log_hit(
        ip=get_client_ip(), ua=request.headers.get("User-Agent", ""),
        method="GET", path=request.path, query="",
        referer=request.headers.get("Referer", ""),
        content_type=request.headers.get("Content-Type", ""),
        headers=request.headers, body="",
        is_alert=1, alert_reason="admin_login_html_view",
        tracking_id=g.tracking_id,
    )
    return Response(html, status=200, content_type="text/html; charset=utf-8")


@app.route("/admin/login.html", methods=["POST"])
def admin_login_post():
    log_hit(
        ip=get_client_ip(), ua=request.headers.get("User-Agent", ""),
        method="POST", path=request.path, query="",
        referer=request.headers.get("Referer", ""),
        content_type=request.headers.get("Content-Type", ""),
        headers=request.headers, body=str(dict(request.form))[:4096],
        is_alert=1, alert_reason="wp_admin_login_attempt",
        tracking_id=g.tracking_id,
    )
    return Response("ERROR: Invalid username or password.",
                    status=200, content_type="text/html; charset=utf-8")


@app.route("/wp-admin", methods=["GET"])
def wp_admin_index():
    return Response("<html><body>wp-admin requires auth. <a href='/admin/login.html'>Login</a></body></html>",
                    status=302, content_type="text/html; charset=utf-8",
                    headers={"Location": "/admin/login.html"})


@app.route("/.env", methods=["GET"])
def env_dotfile():
    body = ("APP_NAME=wibuku\nAPP_ENV=production\n"
            "APP_KEY=base64:" + base64.b64encode(secrets.token_bytes(32)).decode() + "\n"
            "APP_DEBUG=false\nDB_HOST=db-internal.wibuku.internal\n"
            "DB_DATABASE=wibuku_prod\nREDIS_HOST=redis.wibuku.internal\n"
            "AWS_ACCESS_KEY_ID=AKIAFAKEHONEYPOTKEY\n"
            "AWS_SECRET_ACCESS_KEY=" + secrets.token_urlsafe(40) + "\n"
            "STRIPE_SECRET_KEY=sk_live_fake_honeypot\n")
    log_hit(
        ip=get_client_ip(), ua=request.headers.get("User-Agent", ""),
        method="GET", path=request.path, query="",
        referer=request.headers.get("Referer", ""),
        content_type="text/plain", headers=request.headers, body="",
        is_alert=1, alert_reason="dotenv_recon",
        tracking_id=g.tracking_id,
    )
    return Response(body, status=200, content_type="text/plain; charset=utf-8")


@app.route("/config.json", methods=["GET"])
def config_json():
    cfg = {
        "app": "wibuku", "version": "2.14.7",
        "api_url": "https://api.wibuku.app",
        "feature_flags": {"new_feed": True, "labs": False},
        "tracking_id_prefix": g.tracking_id[:6],
        "session": fake_session_token(g.tracking_id),
    }
    log_hit(
        ip=get_client_ip(), ua=request.headers.get("User-Agent", ""),
        method="GET", path=request.path, query="",
        referer=request.headers.get("Referer", ""),
        content_type=request.headers.get("Content-Type", ""),
        headers=request.headers, body="",
        is_alert=1, alert_reason="config_recon",
        tracking_id=g.tracking_id,
    )
    return jsonify(cfg), 200


@app.route("/api/debug/console", methods=["GET"])
def debug_console():
    """Canary tracking endpoint - any visit is logged as alert."""
    token = request.args.get("_t", "")
    event = request.args.get("event", "console_visit")
    log_hit(
        ip=get_client_ip(), ua=request.headers.get("User-Agent", ""),
        method="GET", path=request.path, query=request.query_string.decode("utf-8", errors="replace"),
        referer=request.headers.get("Referer", ""),
        content_type=request.headers.get("Content-Type", ""),
        headers=request.headers, body="",
        is_alert=1, alert_reason=f"canary_hit: token={token} event={event}",
        tracking_id=g.tracking_id,
    )
    return Response("ok", status=200, content_type="text/plain")


# ---------------------------------------------------------------------------
# Dashboard (basic auth)
# ---------------------------------------------------------------------------

def check_dash_auth():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
            u, _, p = decoded.partition(":")
            if secrets.compare_digest(u, DASH_USER) and secrets.compare_digest(p, DASH_PASS):
                return True
        except Exception:
            pass
    return False


DASHBOARD_HTML = """<!DOCTYPE html><html><head><title>wibuku honeypot</title>
<style>body{font-family:-apple-system,sans-serif;background:#0f1419;color:#e7e9ea;margin:0;padding:24px}
.wrap{max-width:1200px;margin:0 auto}h1{color:#1d9bf0;margin:0 0 8px}
.sub{color:#71767b;margin-bottom:24px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.card{background:#16202c;padding:16px;border-radius:12px}
.card .num{font-size:32px;font-weight:800;color:#1d9bf0}
.card .label{color:#71767b;font-size:13px}
section{background:#16202c;padding:16px;border-radius:12px;margin-bottom:16px}
h2{font-size:16px;margin:0 0 12px;color:#1d9bf0}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #2f3336}
th{color:#71767b;font-weight:600}
tr.alert{background:rgba(231,76,60,.12)}
.export{margin-left:8px;color:#1d9bf0;text-decoration:none;font-size:13px}
</style></head><body><div class="wrap">
<h1>wibuku honeypot &mdash; dashboard</h1>
<div class="sub">Local defensive trap. All hits since startup logged to hits.db.</div>
<div class="cards">
<div class="card"><div class="num">__TOTAL__</div><div class="label">total hits</div></div>
<div class="card"><div class="num">__ALERTS__</div><div class="label">alerts</div></div>
<div class="card"><div class="num">__UNIQUE_IPS__</div><div class="label">unique IPs</div></div>
<div class="card"><div class="num">__COUNTRIES_N__</div><div class="label">countries</div></div>
</div>
<section><h2>Recent hits</h2>
<table><thead><tr><th>id</th><th>ts</th><th>ip</th><th>cc</th><th>method</th><th>path</th><th>ua</th><th>reason</th></tr></thead>
<tbody>__ROWS__</tbody></table>
<a class="export" href="/dashboard/export">&#x2B07; Export markdown report</a>
</section>
<section><h2>Top paths</h2><table><thead><tr><th>path</th><th>count</th></tr></thead><tbody>__PATHS__</tbody></table></section>
<section><h2>Methods</h2><table><thead><tr><th>method</th><th>count</th></tr></thead><tbody>__METHODS__</tbody></table></section>
<section><h2>Countries</h2><table><thead><tr><th>cc</th><th>count</th></tr></thead><tbody>__COUNTRIES_R__</tbody></table></section>
<section><h2>Top user agents</h2><table><thead><tr><th>ua</th><th>count</th></tr></thead><tbody>__UAS__</tbody></table></section>
</div></body></html>"""


@app.route("/dashboard")
@app.route("/dashboard/")
def dashboard():
    if not check_dash_auth():
        return Response("Auth required", status=401,
                        headers={"WWW-Authenticate": 'Basic realm="honeypot", charset="UTF-8"'})
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    total = cur.execute("SELECT COUNT(*) c FROM hits").fetchone()["c"]
    alerts = cur.execute("SELECT COUNT(*) c FROM hits WHERE is_alert=1").fetchone()["c"]
    unique_ips = cur.execute("SELECT COUNT(DISTINCT ip) c FROM hits").fetchone()["c"]
    countries = cur.execute("SELECT country, COUNT(*) c FROM hits GROUP BY country ORDER BY c DESC LIMIT 20").fetchall()
    paths = cur.execute("SELECT path, COUNT(*) c FROM hits GROUP BY path ORDER BY c DESC LIMIT 30").fetchall()
    methods = cur.execute("SELECT method, COUNT(*) c FROM hits GROUP BY method").fetchall()
    recent = cur.execute("SELECT id, ts, ip, country, method, path, ua, is_alert, alert_reason FROM hits ORDER BY id DESC LIMIT 100").fetchall()
    top_uas = cur.execute("SELECT ua, COUNT(*) c FROM hits GROUP BY ua ORDER BY c DESC LIMIT 20").fetchall()
    conn.close()

    rows_html = "\n".join(
        f"<tr class='{'alert' if r['is_alert'] else ''}'>"
        f"<td>{r['id']}</td><td>{r['ts']}</td><td>{r['ip']}</td>"
        f"<td>{r['country']}</td><td>{r['method']}</td>"
        f"<td>{r['path']}</td><td>{(r['ua'] or '')[:60]}</td>"
        f"<td>{r['alert_reason'] or ''}</td></tr>" for r in recent)
    country_rows = "\n".join(f"<tr><td>{c['country']}</td><td>{c['c']}</td></tr>" for c in countries)
    path_rows = "\n".join(f"<tr><td>{c['path']}</td><td>{c['c']}</td></tr>" for c in paths)
    method_rows = "\n".join(f"<tr><td>{c['method']}</td><td>{c['c']}</td></tr>" for c in methods)
    ua_rows = "\n".join(f"<tr><td>{(c['ua'] or '-')[:80]}</td><td>{c['c']}</td></tr>" for c in top_uas)
    html = DASHBOARD_HTML
    countries_count = len(countries)
    html = (html
            .replace("__TOTAL__", str(total))
            .replace("__ALERTS__", str(alerts))
            .replace("__UNIQUE_IPS__", str(unique_ips))
            .replace("__COUNTRIES_N__", str(countries_count))
            .replace("__ROWS__", rows_html)
            .replace("__PATHS__", path_rows)
            .replace("__METHODS__", method_rows)
            .replace("__COUNTRIES_R__", country_rows)
            .replace("__UAS__", ua_rows))
    return Response(html, status=200, content_type="text/html; charset=utf-8")


@app.route("/dashboard/export")
def dashboard_export():
    if not check_dash_auth():
        return Response("Auth required", status=401,
                        headers={"WWW-Authenticate": 'Basic realm="honeypot", charset="UTF-8"'})
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT id, ts, ip, country, method, path, query, ua, is_alert, alert_reason, tracking_id "
        "FROM hits ORDER BY id DESC"
    ).fetchall()
    conn.close()
    lines = ["# wibuku honeypot — markdown report", ""]
    lines.append(f"_Generated: {now_iso()} — {len(rows)} hits_")
    lines.append("")
    lines.append("| id | ts | ip | cc | method | path | query | ua | alert | reason |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        ua = (r["ua"] or "-").replace("|", "\\|")[:60]
        path = (r["path"] or "-").replace("|", "\\|")
        q = (r["query"] or "").replace("|", "\\|")[:40]
        reason = (r["alert_reason"] or "").replace("|", "\\|")
        lines.append(
            f"| {r['id']} | {r['ts']} | {r['ip']} | {r['country']} | "
            f"{r['method']} | {path} | {q} | {ua} | "
            f"{'YES' if r['is_alert'] else ''} | {reason} |"
        )
    return Response("\n".join(lines), status=200,
                    content_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=hits.md"})


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print(f"[honeypot] DB: {DB_PATH}", file=sys.stderr)
    print(f"[honeypot] GeoIP2: {'enabled' if _geoip_reader else 'disabled'}", file=sys.stderr)
    print(f"[honeypot] Listening on http://{BIND_HOST}:{BIND_PORT}", file=sys.stderr)
    print(f"[honeypot] Dashboard: http://{BIND_HOST}:{BIND_PORT}/dashboard "
          f"(basic auth: {DASH_USER} / {DASH_PASS})", file=sys.stderr)
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False, use_reloader=False)