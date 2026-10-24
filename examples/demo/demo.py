"""Browser demo for the IAM engine (Python stdlib only).

Plays two roles on http://localhost:3000:
  * a SaaS web app that signs users in with OIDC (authorization code + PKCE)
  * that app's custom login UI, driving the engine's headless session API

On start it seeds demo data (vendor org, project, roles, app, customer orgs,
users). Run:  python examples/demo/demo.py   [--reset]
"""

import base64
import hashlib
import html
import http.cookies
import json
import os
import pathlib
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ISSUER = os.environ.get("IAM_ISSUER", "http://localhost:8080")
PORT = 3000
BASE = f"http://localhost:{PORT}"
ROOT = pathlib.Path(__file__).resolve().parents[2]
STATE_FILE = pathlib.Path(__file__).resolve().parent / ".demo-state.json"
PASSWORD = "Demo-pass-123"
DEMO_SLUGS = ("demo-vendor", "demo-acme", "demo-globex")


# --- HTTP helpers ----------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def call(method, url, body=None, headers=None, form=None):
    data, headers = None, dict(headers or {})
    if body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url if url.startswith("http") else ISSUER + url,
                                 data=data, method=method, headers=headers)
    try:
        resp = _opener.open(req)
    except urllib.error.HTTPError as e:
        resp = e
    raw = resp.read()
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = raw.decode(errors="replace")
    return resp.status, payload


def admin_key():
    if os.environ.get("IAM_BOOTSTRAP_ADMIN_KEY"):
        return os.environ["IAM_BOOTSTRAP_ADMIN_KEY"]
    for line in (ROOT / ".env").read_text().splitlines():
        if line.startswith("IAM_BOOTSTRAP_ADMIN_KEY="):
            return line.split("=", 1)[1].strip()
    sys.exit("IAM_BOOTSTRAP_ADMIN_KEY not found in env or .env")


KEY = admin_key()


def api(method, path, body=None):
    status, payload = call(method, "/v1" + path, body, {"Authorization": "Bearer " + KEY})
    if status >= 300:
        raise RuntimeError(f"{method} {path} -> {status} {payload}")
    return payload


# --- seed data -------------------------------------------------------------------------------

def seed():
    """Create demo tenants. Recreates everything if no saved state exists."""
    old = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    if old.get("login_key") and "--reset" not in sys.argv:
        return old
    # Only delete what this demo created: the ids it saved, or (for state files
    # from older versions) exactly its own three slugs. Nothing else is touched.
    for key_id in [old.get("login_key_id")] if old.get("login_key_id") else []:
        call("DELETE", f"/v1/api-keys/{key_id}", headers={"Authorization": "Bearer " + KEY})
    ids = old.get("org_ids") or [o["id"] for o in api("GET", "/orgs?limit=1000") if o["slug"] in DEMO_SLUGS and old]
    for org_id in ids:
        call("DELETE", f"/v1/orgs/{org_id}", headers={"Authorization": "Bearer " + KEY})
    for org in api("GET", "/orgs?limit=1000"):
        if org["slug"] in DEMO_SLUGS:
            sys.exit(f"Org '{org['slug']}' exists but was not created by this demo; refusing to touch it.")

    vendor = api("POST", "/orgs", {"name": "Demo Vendor (you)", "slug": "demo-vendor"})
    project = api("POST", f"/orgs/{vendor['id']}/projects", {"name": "Demo SaaS"})
    for key in ("admin", "member", "billing"):
        api("POST", f"/projects/{project['id']}/roles", {"key": key, "display_name": key.title()})
    app = api("POST", f"/projects/{project['id']}/apps", {
        "name": "Demo SaaS web", "app_type": "web", "dev_mode": True,
        "redirect_uris": [BASE + "/callback"], "post_logout_redirect_uris": [BASE + "/"],
        "login_url": BASE + "/login",
    })

    acme = api("POST", "/orgs", {"name": "Acme Inc", "slug": "demo-acme"})
    api("POST", f"/projects/{project['id']}/grants", {"org_id": acme["id"], "role_keys": ["admin", "member"]})
    globex = api("POST", "/orgs", {"name": "Globex (no access)", "slug": "demo-globex"})

    def user(org, name, roles):
        u = api("POST", f"/orgs/{org['id']}/users", {
            "username": name, "email": f"{name}@{org['slug']}.test", "email_verified": True,
            "given_name": name.title(), "family_name": "Demo", "password": PASSWORD})
        if roles:
            api("POST", f"/users/{u['id']}/grants", {"project_id": project["id"], "role_keys": roles})

    user(acme, "alice", ["admin"])
    user(acme, "bob", ["member"])
    user(globex, "carol", [])
    user(vendor, "owner", ["admin", "billing"])

    # The login UI gets its own restricted key: session API only, no management.
    login = api("POST", "/api-keys", {"name": "demo login ui", "scope": "login", "expires_in_days": 30})
    state = {"client_id": app["client_id"], "client_secret": app["client_secret"],
             "project_id": project["id"], "login_key": login["key"], "login_key_id": login["id"],
             "org_ids": [vendor["id"], acme["id"], globex["id"]]}
    STATE_FILE.write_text(json.dumps(state))
    return state


# --- app -------------------------------------------------------------------------------------------

STATE = None


def q(v):
    """Escape a value for use as one URL path segment."""
    return urllib.parse.quote(v, safe="")
SESSIONS = {}  # browser cookie -> dict


def jwt_claims(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def client_auth():
    pair = f"{urllib.parse.quote(STATE['client_id'])}:{urllib.parse.quote(STATE['client_secret'])}"
    return {"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()}


STYLE = """
body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;padding:0 16px;color:#222}
h1{font-size:22px} .card{border:1px solid #ddd;border-radius:8px;padding:16px;margin:16px 0}
input{display:block;width:100%;padding:8px;margin:4px 0 12px;box-sizing:border-box}
button,.btn{background:#2d5bd7;color:#fff;border:0;border-radius:6px;padding:9px 14px;
 text-decoration:none;display:inline-block;cursor:pointer;margin-right:6px}
.btn.grey{background:#666} .err{background:#fde8e8;color:#9b1c1c;padding:10px;border-radius:6px}
.ok{background:#e6f6ea;color:#155724;padding:10px;border-radius:6px}
pre{background:#f5f5f5;padding:12px;border-radius:6px;overflow:auto;font-size:13px}
table{border-collapse:collapse} td{padding:4px 12px 4px 0}
"""


def page(title, body):
    return f"<!doctype html><html><head><meta charset=utf-8><title>{title}</title>" \
           f"<style>{STYLE}</style></head><body>{body}</body></html>"


def pretty(obj):
    return "<pre>" + html.escape(json.dumps(obj, indent=2)) + "</pre>"


ACCOUNTS = """
<div class=card><b>Demo accounts</b> (password <code>Demo-pass-123</code>)
<table>
<tr><td><code>demo-acme</code> / <code>alice</code></td><td>customer admin</td></tr>
<tr><td><code>demo-acme</code> / <code>bob</code></td><td>customer member</td></tr>
<tr><td><code>demo-globex</code> / <code>carol</code></td><td>org has no grant: login refused</td></tr>
<tr><td><code>demo-vendor</code> / <code>owner</code></td><td>your own staff</td></tr>
</table></div>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    # session cookie
    def sess(self):
        cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        sid = cookie["demo_sid"].value if "demo_sid" in cookie else None
        if sid not in SESSIONS:
            sid = secrets.token_urlsafe(16)
            SESSIONS[sid] = {}
            self._new_sid = sid
        return SESSIONS[sid]

    def send(self, status, body="", location=None):
        self.send_response(status)
        if getattr(self, "_new_sid", None):
            self.send_header("Set-Cookie", f"demo_sid={self._new_sid}; HttpOnly; Path=/; SameSite=Lax")
        if location:
            self.send_header("Location", location)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def form(self):
        n = int(self.headers.get("Content-Length", 0))
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        routes = {"/": self.home, "/signin": self.signin, "/login": self.login_page,
                  "/callback": self.callback, "/refresh": self.refresh, "/logout": self.logout,
                  "/admin": self.admin_area}
        handler = routes.get(url.path)
        if handler is None:
            return self.send(404, page("404", "<h1>Not found</h1>"))
        handler(q)

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path == "/login":
            return self.login_submit(self.form())
        self.send(404, "")

    # --- the SaaS app ---------------------------------------------------------------------

    def home(self, q):
        s = self.sess()
        msg = f"<p class=err>{html.escape(q['error'])}</p>" if q.get("error") else ""
        if not s.get("tokens"):
            return self.send(200, page("Demo SaaS", f"""
<h1>Demo SaaS</h1>{msg}
<p>A pretend B2B2C app. Sign-in goes through your IAM engine at <code>{ISSUER}</code>.</p>
<a class=btn href="/signin">Sign in</a>{ACCOUNTS}"""))
        t = s["tokens"]
        at, idt = jwt_claims(t["access_token"]), jwt_claims(t["id_token"])
        _, userinfo = call("GET", "/userinfo", headers={"Authorization": "Bearer " + t["access_token"]})
        roles = at.get("roles", [])
        self.send(200, page("Demo SaaS", f"""
<h1>Hello {html.escape(idt.get('given_name') or idt.get('preferred_username', ''))}</h1>{msg}
<p class=ok>Signed in to org <b>{html.escape(at.get('org_slug', ''))}</b> with roles <b>{html.escape(', '.join(roles) or 'none')}</b></p>
<a class=btn href="/admin">Admin area</a><a class="btn grey" href="/refresh">Refresh tokens</a>
<a class="btn grey" href="/logout">Sign out</a>
<div class=card><b>Access token claims</b> (what your backend uses to authorize){pretty(at)}</div>
<div class=card><b>ID token claims</b>{pretty(idt)}</div>
<div class=card><b>/userinfo</b>{pretty(userinfo)}</div>"""))

    def signin(self, q):
        s = self.sess()
        s["state"], s["verifier"] = secrets.token_urlsafe(16), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(s["verifier"].encode()).digest()).rstrip(b"=").decode()
        params = urllib.parse.urlencode({
            "client_id": STATE["client_id"], "redirect_uri": BASE + "/callback", "response_type": "code",
            "scope": "openid profile email offline_access", "state": s["state"], "nonce": secrets.token_urlsafe(8),
            "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "consent",
        })
        self.send(302, location=f"{ISSUER}/authorize?{params}")

    def callback(self, q):
        s = self.sess()
        if q.get("error"):
            return self.send(302, location="/?error=" + urllib.parse.quote(q.get("error_description", q["error"])))
        if not q.get("state") or q["state"] != s.pop("state", None):
            return self.send(400, page("Error", "<p class=err>state mismatch</p>"))
        status, tokens = call("POST", "/oauth/token", headers=client_auth(), form={
            "grant_type": "authorization_code", "code": q.get("code", ""),
            "redirect_uri": BASE + "/callback", "code_verifier": s.pop("verifier", "")})
        if status != 200:
            return self.send(302, location="/?error=" + urllib.parse.quote(f"token exchange failed: {tokens}"))
        s["tokens"] = tokens
        self.send(302, location="/")

    def refresh(self, q):
        s = self.sess()
        t = s.get("tokens")
        if not t:
            return self.send(302, location="/")
        status, tokens = call("POST", "/oauth/token", headers=client_auth(), form={
            "grant_type": "refresh_token", "refresh_token": t["refresh_token"]})
        if status != 200:
            s.pop("tokens", None)
            return self.send(302, location="/?error=" + urllib.parse.quote(f"refresh failed: {tokens}"))
        s["tokens"] = tokens
        self.send(302, location="/?error=" + urllib.parse.quote("(not an error) tokens refreshed and rotated"))

    def admin_area(self, q):
        """A protected route: the backend checks the token with introspection."""
        t = self.sess().get("tokens")
        if not t:
            return self.send(302, location="/")
        _, intro = call("POST", "/oauth/introspect", headers=client_auth(), form={"token": t["access_token"]})
        allowed = intro.get("active") and "admin" in intro.get("roles", [])
        verdict = "<p class=ok>Access granted: token is active and has role <b>admin</b>.</p>" if allowed \
            else "<p class=err>403 Forbidden: you need role <b>admin</b> (or the token was revoked).</p>"
        self.send(200 if allowed else 403, page("Admin area", f"""
<h1>Admin area</h1>{verdict}
<div class=card><b>Introspection response</b>{pretty(intro)}</div><a class=btn href="/">Back</a>"""))

    def logout(self, q):
        s = self.sess()
        t = s.pop("tokens", None)
        if t and t.get("refresh_token"):
            call("POST", "/revoke", headers=client_auth(),
                 form={"token": t["refresh_token"], "token_type_hint": "refresh_token"})
        self.send(302, location="/")

    # --- the login UI (uses the session API) ------------------------------------------------

    def login_page(self, q, error="", values=None, totp=False):
        v = values or {}
        ar = q.get("authRequest") or v.get("authRequest", "")
        status, info = call("GET", f"/v1/auth-requests/{urllib.parse.quote(ar, safe='')}", headers=self.login_headers())
        if status != 200:
            return self.send(400, page("Login", "<p class=err>Unknown or expired login request.</p>"
                                                "<a class=btn href='/signin'>Start again</a>"))
        err = f"<p class=err>{html.escape(error)}</p>" if error else ""
        hidden = "".join(f"<input type=hidden name={k} value='{html.escape(v.get(k, ''))}'>"
                         for k in ("session_id", "session_token") if totp)
        fields = f"""<label>TOTP code<input name=code autofocus autocomplete=one-time-code></label>""" if totp else f"""
<label>Organization<input name=org value="{html.escape(v.get('org', 'demo-acme'))}"></label>
<label>Username or email<input name=login_name value="{html.escape(v.get('login_name', ''))}" autofocus></label>
<label>Password<input name=password type=password></label>"""
        self.send(200, page("Sign in", f"""
<h1>Sign in to {html.escape(info['app_name'])}</h1>
<p>This page is <i>your</i> login UI. It calls the engine's session API from the server side.</p>{err}
<form method=post action=/login><input type=hidden name=authRequest value="{html.escape(ar)}">
<input type=hidden name=csrf value="{self.csrf_token()}">{hidden}{fields}
<button>Continue</button></form>{'' if totp else ACCOUNTS}"""))

    def login_headers(self):
        # Restricted login key, plus the browser's IP for per-user rate limits and audit.
        return {"Authorization": "Bearer " + STATE["login_key"], "X-End-User-IP": self.client_address[0]}

    def csrf_token(self):
        s = self.sess()
        s.setdefault("csrf", secrets.token_urlsafe(24))
        return s["csrf"]

    def login_submit(self, f):
        if not secrets.compare_digest(f.get("csrf", ""), self.sess().get("csrf", "-")):
            return self.send(403, page("Forbidden", "<p class=err>Invalid form token. Reload the page.</p>"))
        auth = self.login_headers()
        ar = f.get("authRequest", "")
        if f.get("code"):  # second factor step
            status, st = call("POST", f"/v1/sessions/{q(f['session_id'])}/totp",
                              {"session_token": f["session_token"], "code": f["code"]}, auth)
            if status != 200:
                return self.login_page({}, st.get("error", "invalid code"), f, totp=True)
            sid, token = f["session_id"], f["session_token"]
        else:
            status, sess = call("POST", "/v1/sessions", {"org": f.get("org", ""), "login_name": f.get("login_name", "")}, auth)
            if status != 201:
                return self.login_page({}, sess.get("error", "login failed"), f)
            sid, token = sess["session_id"], sess["session_token"]
            status, st = call("POST", f"/v1/sessions/{q(sid)}/password",
                              {"session_token": token, "password": f.get("password", "")}, auth)
            if status != 200:
                return self.login_page({}, st.get("error", "login failed"), f)
            if st["mfa_required"] and not st["authenticated"]:
                return self.login_page({}, "", {**f, "session_id": sid, "session_token": token}, totp=True)
        status, fin = call("POST", f"/v1/auth-requests/{q(ar)}/finalize", {"session_id": sid, "session_token": token}, auth)
        if status != 200:
            return self.login_page({}, fin.get("error", "login failed"), f)
        self.send(302, location=fin["callback_url"])


def main():
    global STATE
    host = urllib.parse.urlparse(ISSUER).hostname
    if host not in ("localhost", "127.0.0.1", "::1") and "--not-localhost" not in sys.argv:
        sys.exit(f"Refusing to run against {ISSUER}: this demo creates users with a public password "
                 "and deletes its own orgs on --reset. Use it only on a local engine.")
    status, _ = call("GET", "/healthz")
    if status != 200:
        sys.exit(f"IAM engine not reachable at {ISSUER}. Start it with: docker compose up -d")
    STATE = seed()
    print(f"Demo running at {BASE}  (engine: {ISSUER})")
    print(f"Accounts: demo-acme/alice, demo-acme/bob, demo-globex/carol, demo-vendor/owner  password: {PASSWORD}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
