#!/usr/bin/env python3
"""Caddy Manager — a tiny GUI to CRUD reverse-proxy routes in a Caddyfile.

Source of truth is /data/routes.json. On every change it re-renders the
Caddyfile, applies it live via Caddy's admin API (POST /load, which validates
first), and persists to disk. Zero third-party dependencies.
"""
import hashlib
import hmac
import http.client
import http.cookies
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ADMIN = os.environ.get("CADDY_ADMIN", "http://caddy:2019")
CADDYFILE = os.environ.get("CADDYFILE_PATH", "/caddy/Caddyfile")
ROUTES = os.environ.get("ROUTES_PATH", "/data/routes.json")
PORT = int(os.environ.get("LISTEN_PORT", "8080"))
AUTH_PATH = os.environ.get("AUTH_PATH", "/data/auth.json")
# Optional env override: if both are set, these credentials are used and the
# onboarding flow is skipped entirely (handy for automated / headless deploys).
ENV_USER = os.environ.get("UI_USER", "")
ENV_PASS = os.environ.get("UI_PASS", "")
HERE = os.path.dirname(os.path.abspath(__file__))

LOCK = threading.Lock()

# ---- sessions: stateless HMAC-signed cookie (secret is per-process) ----
SESSION_TTL = 7 * 24 * 3600
_SECRET = secrets.token_bytes(32)


def make_token():
    exp = str(int(time.time()) + SESSION_TTL)
    sig = hmac.new(_SECRET, exp.encode(), "sha256").hexdigest()
    return exp + "." + sig


def valid_token(tok):
    try:
        exp, sig = tok.split(".", 1)
    except ValueError:
        return False
    good = hmac.new(_SECRET, exp.encode(), "sha256").hexdigest()
    return hmac.compare_digest(sig, good) and int(exp) > time.time()


# ---- login rate limiting (per client IP) ----
RL_MAX = 5            # this many failed attempts...
RL_WINDOW = 900       # ...within this window (s) -> locked out for the remainder
_RL = {}
_RL_LOCK = threading.Lock()


def rl_locked_for(ip):
    """Seconds remaining on a lockout, or 0 if not locked."""
    with _RL_LOCK:
        rec = _RL.get(ip)
        if not rec:
            return 0
        count, first = rec
        if time.time() - first > RL_WINDOW:
            _RL.pop(ip, None)
            return 0
        if count >= RL_MAX:
            return max(1, int(RL_WINDOW - (time.time() - first)))
        return 0


def rl_fail(ip):
    with _RL_LOCK:
        rec = _RL.get(ip)
        now = time.time()
        if not rec or now - rec[1] > RL_WINDOW:
            _RL[ip] = [1, now]
        else:
            rec[0] += 1


def rl_reset(ip):
    with _RL_LOCK:
        _RL.pop(ip, None)


# ---- account: single admin credential, hashed in AUTH_PATH ----
PBKDF2_ITERS = 200_000


def load_auth():
    try:
        with open(AUTH_PATH) as f:
            return json.load(f)
    except Exception:
        return None


def env_managed():
    return bool(ENV_USER and ENV_PASS)


def is_configured():
    if env_managed():
        return True
    a = load_auth()
    return bool(a and a.get("username") and a.get("hash"))


def _hash(password, salt, iters):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), iters).hex()


def write_auth(rec):
    tmp = AUTH_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f)
    os.replace(tmp, AUTH_PATH)
    try:
        os.chmod(AUTH_PATH, 0o600)   # the file is only a salted hash, but keep it tight
    except OSError:
        pass


def save_auth(username, password):
    salt = secrets.token_hex(16)
    write_auth({"username": username, "salt": salt, "iters": PBKDF2_ITERS,
                "hash": _hash(password, salt, PBKDF2_ITERS)})


def check_password(password):
    a = load_auth()
    if not a:
        return False
    calc = _hash(password, a["salt"], a.get("iters", PBKDF2_ITERS))
    return hmac.compare_digest(calc, a.get("hash", ""))


def verify_login(username, password):
    if env_managed():
        return hmac.compare_digest(username, ENV_USER) and hmac.compare_digest(password, ENV_PASS)
    a = load_auth()
    if not a:
        return False
    return hmac.compare_digest(username, a.get("username", "")) and check_password(password)


LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
UPSTREAM_RE = re.compile(r"^(?:https?://)?[A-Za-z0-9.\-]+(?::\d{1,5})?$")


DEFAULT_DATA = {
    "config": {
        "base_domain": os.environ.get("BASE_DOMAIN", "example.com"),
        "global_lines": ["email you@example.com", "admin :2019"],
    },
    "routes": [],
}


def load_data():
    with open(ROUTES) as f:
        return json.load(f)


def save_data(data):
    tmp = ROUTES + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, ROUTES)


def _indent(text, n):
    pad = " " * n
    out = []
    for line in str(text or "").splitlines():
        s = line.strip()
        if s:
            out.append(pad + s)
    return out


def render(data):
    cfg = data.get("config", {})
    base = cfg.get("base_domain", "example.com")
    global_lines = cfg.get("global_lines", [])
    L = ["# Managed by Caddy Manager. Edits to this file may be overwritten.", "{"]
    for gl in global_lines:
        L.append("    " + str(gl).strip())
    L += ["}", "", "*.%s {" % base]
    for r in data.get("routes", []):
        if not r.get("enabled", True):
            continue
        rid = r["id"]
        label = r.get("label") or rid
        L.append("    # --- %s ---" % label)
        for nl in str(r.get("notes", "")).splitlines():
            if nl.strip():
                L.append("    # note: " + nl.strip())
        L.append("    @%s host %s.%s" % (rid, r["subdomain"], base))
        L.append("    handle @%s {" % rid)
        L += _indent(r.get("before_proxy", ""), 8)
        headers = _indent(r.get("proxy_headers", ""), 12)
        if headers:
            L.append("        reverse_proxy %s {" % r["upstream"])
            L += headers
            L.append("        }")
        else:
            L.append("        reverse_proxy %s" % r["upstream"])
        L += ["    }", ""]
    L += ["    handle {", '        respond "Not found" 404', "    }", "}"]
    return "\n".join(L) + "\n"


def caddy_load(text):
    """Push Caddyfile to the admin API.

    Returns (ok, live, message):
      ok=False  -> Caddy rejected the config (validation error); do not persist.
      ok=True, live=True  -> applied to the running server.
      ok=True, live=False -> admin unreachable; safe to persist to disk anyway.
    """
    req = urllib.request.Request(
        ADMIN + "/load", data=text.encode(),
        headers={"Content-Type": "text/caddyfile"}, method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        return True, True, "Applied to running Caddy."
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace").strip()
        try:
            body = json.loads(body).get("error", body)
        except Exception:
            pass
        return False, False, body or ("HTTP %s from admin API" % e.code)
    except (urllib.error.URLError, OSError) as e:
        return True, False, "Caddy admin unreachable (%s). Saved to disk; " \
                            "it will apply on the next Caddy reload/restart." % e


def write_caddyfile(text):
    # In-place write preserves the inode so Caddy's bind-mounted Caddyfile
    # reflects the change and stays consistent across restarts.
    with open(CADDYFILE, "w") as f:
        f.write(text)


def apply(data):
    text = render(data)
    ok, live, msg = caddy_load(text)
    if not ok:
        raise ValueError(msg)
    write_caddyfile(text)
    save_data(data)
    return live, msg


def validate_route(r, existing_ids, current_id=None):
    sub = (r.get("subdomain") or "").strip().lower()
    if not LABEL_RE.match(sub):
        raise ValueError("Subdomain must be letters, digits and hyphens (e.g. 'grafana').")
    rid = (r.get("id") or sub).strip().lower()
    if not LABEL_RE.match(rid):
        raise ValueError("Invalid id.")
    if rid in existing_ids and rid != current_id:
        raise ValueError("A route named '%s' already exists." % rid)
    up = (r.get("upstream") or "").strip()
    if not UPSTREAM_RE.match(up):
        raise ValueError("Upstream must look like host:port (e.g. 192.168.1.50:3000).")
    return {
        "id": rid,
        "label": (r.get("label") or sub).strip(),
        "subdomain": sub,
        "upstream": up,
        "notes": (r.get("notes") or "").strip(),
        "before_proxy": (r.get("before_proxy") or "").strip(),
        "proxy_headers": (r.get("proxy_headers") or "").strip(),
        "enabled": bool(r.get("enabled", True)),
    }


def probe_route(r, base):
    """What a real HTTP request to the upstream returns (mimics what Caddy sends).

    Returns {reachable, status, note}: an HTTP status means the backend answered
    (even a 502/404 tells you far more than a bare 'down'); status None with
    reachable True means the port is open but didn't speak HTTP.
    """
    up = r.get("upstream", "")
    scheme = "https" if up.startswith("https") else "http"
    hostport = up.split("://")[-1]
    host, _, port = hostport.partition(":")
    port = int(port) if port else (443 if scheme == "https" else 80)
    fqdn = "%s.%s" % (r.get("subdomain", ""), base)
    hdrs = {"Host": fqdn, "User-Agent": "CaddyManager-healthcheck"}
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=3,
                                               context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=3)
        try:
            conn.request("GET", "/", headers=hdrs)
            return {"reachable": True, "status": conn.getresponse().status, "note": ""}
        finally:
            conn.close()
    except Exception:
        pass
    try:
        socket.create_connection((host, port), timeout=2).close()
        return {"reachable": True, "status": None, "note": "port open (no HTTP response)"}
    except Exception:
        return {"reachable": False, "status": None, "note": "connection refused / unreachable"}


class Handler(BaseHTTPRequestHandler):
    server_version = "CaddyManager"

    def log_message(self, *a):
        pass

    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For", "")
        return xff.split(",")[0].strip() if xff else self.client_address[0]

    # ---- auth (cookie session) ----
    def _session_ok(self):
        c = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return "session" in c and valid_token(c["session"].value)

    def _redirect(self, to):
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _set_session(self):
        b = json.dumps({"ok": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "session=%s; HttpOnly; Secure; SameSite=Strict; "
                         "Path=/; Max-Age=%d" % (make_token(), SESSION_TTL))
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _guard(self, is_page):
        if not is_configured():
            if is_page:
                self._redirect("/setup")
            else:
                self._json(403, {"error": "setup required"})
            return False
        if self._session_ok():
            return True
        if is_page:
            self._redirect("/login")
        else:
            self._json(401, {"error": "unauthorized"})
        return False

    def _setup(self):
        if is_configured():
            return self._json(409, {"error": "Already configured."})
        body = self._safe_body()
        u = (body.get("username") or "").strip()
        p = body.get("password") or ""
        c = body.get("confirm") or ""
        if len(u) < 3:
            return self._json(400, {"error": "Username must be at least 3 characters."})
        if len(p) < 8:
            return self._json(400, {"error": "Password must be at least 8 characters."})
        if p != c:
            return self._json(400, {"error": "Passwords do not match."})
        save_auth(u, p)
        self._set_session()

    def _login(self):
        ip = self._client_ip()
        wait = rl_locked_for(ip)
        if wait > 0:
            b = json.dumps({"error": "Too many failed attempts. Try again in %d seconds." % wait}).encode()
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", str(wait))
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        body = self._safe_body()
        u = (body.get("username") or "").strip()
        p = body.get("password") or ""
        if verify_login(u, p):
            rl_reset(ip)
            self._set_session()
        else:
            rl_fail(ip)
            self._json(401, {"error": "Invalid username or password."})

    def _logout(self):
        self.send_response(200)
        self.send_header("Set-Cookie", "session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _account_get(self):
        a = load_auth() or {}
        self._json(200, {"username": ENV_USER if env_managed() else a.get("username", ""),
                         "env_managed": env_managed()})

    def _account_update(self):
        if env_managed():
            return self._json(400, {"error": "Credentials are set via the UI_USER/UI_PASS "
                                             "environment variables and can't be changed here."})
        body = self._safe_body()
        if not check_password(body.get("current_password") or ""):
            return self._json(403, {"error": "Current password is incorrect."})
        a = load_auth() or {}
        new_user = (body.get("username") or a.get("username") or "").strip()
        new_pass = body.get("password") or ""
        confirm = body.get("confirm") or ""
        if len(new_user) < 3:
            return self._json(400, {"error": "Username must be at least 3 characters."})
        if new_pass:
            if len(new_pass) < 8:
                return self._json(400, {"error": "New password must be at least 8 characters."})
            if new_pass != confirm:
                return self._json(400, {"error": "New passwords do not match."})
            save_auth(new_user, new_pass)
        else:
            a["username"] = new_user
            write_auth(a)
        self._json(200, {"ok": True, "username": new_user})

    def _config_update(self):
        body = self._safe_body()
        base = (body.get("base_domain") or "").strip().lower()
        if not DOMAIN_RE.match(base) or "." not in base:
            return self._json(400, {"error": "Base domain looks invalid (e.g. 'home.example.com')."})
        gl = body.get("global_lines")
        if isinstance(gl, str):
            gl = gl.splitlines()
        gl = [str(x).strip() for x in (gl or []) if str(x).strip()]
        with LOCK:
            data = load_data()
            data.setdefault("config", {})
            data["config"]["base_domain"] = base
            data["config"]["global_lines"] = gl
            live, msg = apply(data)
        self._json(200, {"ok": True, "live": live, "message": msg, "config": data["config"]})

    # ---- helpers ----
    def _json(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _send(self, code, s, ctype):
        b = s.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _read_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _safe_body(self):
        try:
            return self._read_body()
        except Exception:
            return {}

    # ---- routing ----
    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/healthz":
            return self._send(200, "ok", "text/plain; charset=utf-8")
        if p == "/setup":
            if is_configured():
                return self._redirect("/login")
            with open(os.path.join(HERE, "setup.html")) as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if p == "/login":
            if not is_configured():
                return self._redirect("/setup")
            if self._session_ok():
                return self._redirect("/")
            with open(os.path.join(HERE, "login.html")) as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if p in ("/", "/index.html"):
            if not self._guard(True):
                return
            with open(os.path.join(HERE, "index.html")) as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if not self._guard(False):
            return
        if p == "/api/routes":
            return self._json(200, load_data())
        if p == "/api/config":
            return self._json(200, load_data().get("config", {}))
        if p == "/api/account":
            return self._account_get()
        if p == "/api/caddyfile":
            return self._send(200, render(load_data()), "text/plain; charset=utf-8")
        if p == "/api/health":
            return self._json(200, self._health())
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        if p == "/setup":
            return self._setup()
        if p == "/login":
            return self._login()
        if p == "/logout":
            return self._logout()
        if not self._guard(False):
            return
        try:
            if p == "/api/routes":
                body = self._read_body()
                with LOCK:
                    data = load_data()
                    nr = validate_route(body, {x["id"] for x in data["routes"]})
                    data["routes"].append(nr)
                    live, msg = apply(data)
                return self._json(200, {"ok": True, "live": live, "message": msg, "route": nr})
            if p == "/api/account":
                return self._account_update()
            if p == "/api/apply":
                with LOCK:
                    live, msg = apply(load_data())
                return self._json(200, {"ok": True, "live": live, "message": msg})
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:
            return self._json(500, {"error": str(e)})
        return self._json(404, {"error": "not found"})

    def do_PUT(self):
        if not self._guard(False):
            return
        p = self.path.split("?")[0]
        try:
            if p == "/api/config":
                return self._config_update()
            m = re.match(r"^/api/routes/([^/?]+)", self.path)
            if not m:
                return self._json(404, {"error": "not found"})
            rid = m.group(1)
            body = self._read_body()
            with LOCK:
                data = load_data()
                idx = next((i for i, x in enumerate(data["routes"]) if x["id"] == rid), None)
                if idx is None:
                    return self._json(404, {"error": "no such route"})
                nr = validate_route(body, {x["id"] for x in data["routes"]}, current_id=rid)
                data["routes"][idx] = nr
                live, msg = apply(data)
            return self._json(200, {"ok": True, "live": live, "message": msg, "route": nr})
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    def do_DELETE(self):
        if not self._guard(False):
            return
        m = re.match(r"^/api/routes/([^/?]+)", self.path)
        if not m:
            return self._json(404, {"error": "not found"})
        rid = m.group(1)
        try:
            with LOCK:
                data = load_data()
                before = len(data["routes"])
                data["routes"] = [x for x in data["routes"] if x["id"] != rid]
                if len(data["routes"]) == before:
                    return self._json(404, {"error": "no such route"})
                live, msg = apply(data)
            return self._json(200, {"ok": True, "live": live, "message": msg})
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    def _health(self):
        data = load_data()
        base = data.get("config", {}).get("base_domain", "example.com")
        out = {"admin": False, "admin_url": ADMIN, "routes": {}}
        try:
            urllib.request.urlopen(ADMIN + "/config/", timeout=3)
            out["admin"] = True
        except Exception:
            pass
        routes = data.get("routes", [])
        if routes:
            with ThreadPoolExecutor(max_workers=8) as ex:
                for rid, res in ex.map(lambda r: (r["id"], probe_route(r, base)), routes):
                    out["routes"][rid] = res
        return out


def startup():
    try:
        if not os.path.exists(ROUTES):
            save_data(DEFAULT_DATA)   # bootstrap a fresh install
        data = load_data()
        text = render(data)
        write_caddyfile(text)     # keep on-disk Caddyfile canonical
        caddy_load(text)          # best effort; admin may not be up yet
        print("startup: rendered %d routes" % len(data.get("routes", [])), flush=True)
    except Exception as e:
        print("startup warning:", e, flush=True)


if __name__ == "__main__":
    startup()
    print("Caddy Manager listening on :%d" % PORT, flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
