"""End-to-end smoke test of the IAM engine (stdlib only).

Runs the full B2B2C flow against a running engine:
vendor org -> project/roles/app -> customer org + project grant -> customer
user + user grant -> OIDC authorization code flow through the session API ->
token, userinfo, introspection, refresh rotation, replay rejection,
cross-org isolation and grant revocation.

Usage: python scripts/smoke_test.py [issuer] (reads IAM_BOOTSTRAP_ADMIN_KEY from env or .env)
"""

import base64
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ISSUER = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
REDIRECT_URI = "http://localhost:9999/callback"
LOGIN_URL = "http://localhost:3000/login"


def admin_key():
    if os.environ.get("IAM_BOOTSTRAP_ADMIN_KEY"):
        return os.environ["IAM_BOOTSTRAP_ADMIN_KEY"]
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    for line in env.read_text().splitlines():
        if line.startswith("IAM_BOOTSTRAP_ADMIN_KEY="):
            return line.split("=", 1)[1].strip()
    sys.exit("IAM_BOOTSTRAP_ADMIN_KEY not set")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(NoRedirect)


def http(method, path, body=None, headers=None, form=None):
    url = path if path.startswith("http") else ISSUER + path
    data = None
    headers = dict(headers or {})
    if path.startswith(("/v1/sessions", "/v1/auth-requests", "/v1/password-resets", "/v1/federated-logins")):
        # Like a real login UI backend: forward the end user's IP. Each call
        # pretends to be a different browser so the per-IP limit is not hit.
        headers.setdefault("X-End-User-IP", f"198.51.100.{secrets.randbelow(254) + 1}")
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        resp = opener.open(req)
    except urllib.error.HTTPError as e:
        resp = e
    raw = resp.read()
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = raw.decode(errors="replace")
    return resp.status, payload, resp.headers


def api(key, method, path, body=None, expect=(200, 201, 204), headers=None):
    h = {"Authorization": "Bearer " + key}
    h.update(headers or {})
    status, payload, _ = http(method, "/v1" + path, body, h)
    if status not in expect:
        sys.exit(f"FAIL {method} {path}: {status} {payload}")
    return payload


def check(cond, label):
    print(("PASS " if cond else "FAIL ") + label)
    if not cond:
        sys.exit(1)


def jwt_claims(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def login(key, org, login_name, password, client_id, extra=None):
    """Drive authorize -> session API -> callback; return the auth code."""
    state = secrets.token_urlsafe(8)
    q = urllib.parse.urlencode({
        "client_id": client_id, "redirect_uri": REDIRECT_URI, "response_type": "code",
        "scope": "openid profile email offline_access", "state": state, "nonce": "n-1",
        "prompt": "consent", **(extra or {}),
    })
    status, _, headers = http("GET", "/authorize?" + q)
    loc = headers.get("Location", "")
    if status != 302 or not loc.startswith(LOGIN_URL):
        sys.exit(f"FAIL authorize did not redirect to login UI: {status} {loc}")
    auth_request = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["authRequest"][0]

    sess = api(key, "POST", "/sessions", {"org": org, "login_name": login_name})
    api(key, "POST", f"/sessions/{sess['session_id']}/password",
        {"session_token": sess["session_token"], "password": password})
    status, fin, _ = http("POST", f"/v1/auth-requests/{auth_request}/finalize",
                          {"session_id": sess["session_id"], "session_token": sess["session_token"]},
                          {"Authorization": "Bearer " + key})
    if status != 200:
        return None, status
    status, _, headers = http("GET", fin["callback_url"])
    loc = headers.get("Location", "")
    params = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    if status != 302 or params.get("state") != [state]:
        sys.exit(f"FAIL callback did not redirect with code: {status} {loc}")
    return params["code"][0], 200


def totp_code(secret_b32, at=None):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    counter = struct.pack(">Q", int(at if at is not None else time.time()) // 30)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    off = digest[-1] & 15
    return "%06d" % ((struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % 1000000)


def password_step(key, org, login_name, password):
    sess = api(key, "POST", "/sessions", {"org": org, "login_name": login_name})
    status, body, _ = http("POST", f"/v1/sessions/{sess['session_id']}/password",
                           {"session_token": sess["session_token"], "password": password},
                           {"Authorization": "Bearer " + key})
    return sess, status, body


def token(basic, **form):
    return http("POST", "/oauth/token", headers={"Authorization": basic}, form=form)[:2]


def main():
    key = admin_key()
    suffix = secrets.token_hex(3)

    # Vendor (SaaS owner) org with a project, roles and an app.
    vendor = api(key, "POST", "/orgs", {"name": "Vendor", "slug": f"vendor-{suffix}"})
    project = api(key, "POST", f"/orgs/{vendor['id']}/projects", {"name": "My SaaS"})
    for role in ("admin", "member", "billing"):
        api(key, "POST", f"/projects/{project['id']}/roles", {"key": role, "display_name": role})
    app = api(key, "POST", f"/projects/{project['id']}/apps", {
        "name": "web", "app_type": "web", "redirect_uris": [REDIRECT_URI],
        "login_url": LOGIN_URL, "dev_mode": True,
    })
    basic = "Basic " + base64.b64encode(
        f"{urllib.parse.quote(app['client_id'])}:{urllib.parse.quote(app['client_secret'])}".encode()).decode()

    # A restricted key for the login UI backend: session API only.
    login_key = api(key, "POST", "/api-keys", {"name": "login ui", "scope": "login", "expires_in_days": 1})["key"]
    status, _, _ = http("GET", "/v1/orgs", headers={"Authorization": "Bearer " + login_key})
    check(status == 403, "login-scoped key cannot use the management API")

    # Customer org, onboarded with a project grant limited to admin + member.
    acme = api(key, "POST", "/orgs", {"name": "Acme", "slug": f"acme-{suffix}"})
    api(key, "POST", f"/projects/{project['id']}/grants", {"org_id": acme["id"], "role_keys": ["admin", "member"]})

    # Delegated admin: Acme's own key manages Acme's users.
    acme_key = api(key, "POST", f"/orgs/{acme['id']}/api-keys", {"name": "acme admin"})["key"]
    status, body, _ = http("POST", f"/v1/orgs/{acme['id']}/users",
                           {"username": "weak", "email": "weak@acme.test", "password": "weak-weak-weak"},
                           {"Authorization": "Bearer " + acme_key})
    check(status == 400, "password containing the username is rejected")
    status, _, _ = http("POST", f"/v1/orgs/{acme['id']}/users",
                        {"username": "x", "email": "x@acme.test", "email_verified": True},
                        {"Authorization": "Bearer " + acme_key})
    check(status == 400, "org key cannot mark an email verified directly")
    alice = api(acme_key, "POST", f"/orgs/{acme['id']}/users", {
        "username": "alice", "email": "alice@acme.test",
        "given_name": "Alice", "family_name": "Doe", "password": "correct-horse-1",
    })
    status, _, _ = http("POST", f"/v1/orgs/{acme['id']}/users",
                        {"username": "alice@acme.test", "email": "mallory@acme.test", "password": "correct-horse-7"},
                        {"Authorization": "Bearer " + acme_key})
    check(status == 400, "username cannot impersonate another user's email")
    status, _, _ = http("POST", f"/v1/orgs/{acme['id']}/users",
                        {"username": "alice2", "email": "ALICE@acme.test", "password": "correct-horse-7"},
                        {"Authorization": "Bearer " + acme_key})
    check(status == 409, "email is unique per org (case-insensitive)")
    status, _, _ = http("POST", f"/v1/projects/{project['id']}/grants", {"org_id": acme["id"], "role_keys": []},
                        {"Authorization": "Bearer " + acme_key})
    check(status == 403, "org key cannot grant projects to other orgs")
    api(acme_key, "POST", f"/users/{alice['id']}/grants", {"project_id": project["id"], "role_keys": ["admin"]})
    status, _, _ = http("POST", f"/v1/users/{alice['id']}/grants",
                        {"project_id": project["id"], "role_keys": ["billing"]},
                        {"Authorization": "Bearer " + acme_key})
    check(status == 400, "org cannot assign a role it was not granted (billing)")
    status, _, _ = http("GET", f"/v1/orgs/{vendor['id']}/users", headers={"Authorization": "Bearer " + acme_key})
    check(status == 403, "org key cannot read another org's users")

    # No user enumeration: unknown and real users look the same.
    ghost, s1, b1 = password_step(login_key, acme["slug"], "nobody-here", "whatever-123")
    real, s2, b2 = password_step(login_key, acme["slug"], "alice", "wrong-password")
    check(set(ghost) == set(real) and (s1, b1) == (s2, b2) == (401, {"error": "invalid credentials"}),
          "unknown user indistinguishable from wrong password")

    # Login through the headless session API.
    code, _ = login(login_key, acme["slug"], "alice", "correct-horse-1", app["client_id"])
    status, tokens = token(basic, grant_type="authorization_code", code=code, redirect_uri=REDIRECT_URI)
    check(status == 200 and "access_token" in tokens, "authorization code exchanged for tokens")
    check("refresh_token" in tokens, "refresh token issued for offline_access")
    status, _ = token(basic, grant_type="authorization_code", code=code, redirect_uri=REDIRECT_URI)
    check(status == 400, "authorization code cannot be reused")

    # Concurrent exchanges of one code: exactly one may win.
    import concurrent.futures
    code2, _ = login(login_key, acme["slug"], "alice@acme.test", "correct-horse-1", app["client_id"])
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda _: token(basic, grant_type="authorization_code", code=code2,
                                                redirect_uri=REDIRECT_URI)[0], range(8)))
    check(results.count(200) == 1, f"concurrent code exchange: one success, got {results}")

    at = jwt_claims(tokens["access_token"])
    check(at["org_id"] == acme["id"] and at["roles"] == ["admin"], f"JWT access token tenant claims {at['roles']}")
    check(at["exp"] - at["iat"] <= 300, "access token lifetime <= 5 minutes")
    idt = jwt_claims(tokens["id_token"])
    check(idt["sub"] == alice["id"] and idt["nonce"] == "n-1" and idt["roles"] == ["admin"], "ID token subject, nonce, roles")

    status, info, _ = http("GET", "/userinfo", headers={"Authorization": "Bearer " + tokens["access_token"]})
    check(status == 200 and info["email"] == "alice@acme.test" and info["org_slug"] == acme["slug"], "userinfo")
    status, intro, _ = http("POST", "/oauth/introspect", headers={"Authorization": basic}, form={"token": tokens["access_token"]})
    check(status == 200 and intro.get("active") is True and intro.get("roles") == ["admin"], "introspection active")

    # Refresh rotation and reuse detection.
    status, refreshed = token(basic, grant_type="refresh_token", refresh_token=tokens["refresh_token"])
    check(status == 200 and refreshed["refresh_token"] != tokens["refresh_token"], "refresh token rotated")
    status, _ = token(basic, grant_type="refresh_token", refresh_token=tokens["refresh_token"])
    check(status == 400, "used refresh token rejected (replay)")
    status, _ = token(basic, grant_type="refresh_token", refresh_token=refreshed["refresh_token"])
    check(status == 400, "replay revoked the whole token family, including the newest token")
    status, intro, _ = http("POST", "/oauth/introspect", headers={"Authorization": basic}, form={"token": refreshed["access_token"]})
    check(intro.get("active") is False, "access token of revoked family is inactive")

    # Revocation of a refresh token actually works.
    code, _ = login(login_key, acme["slug"], "alice", "correct-horse-1", app["client_id"])
    _, tokens = token(basic, grant_type="authorization_code", code=code, redirect_uri=REDIRECT_URI)
    status, _, _ = http("POST", "/revoke", headers={"Authorization": basic},
                        form={"token": tokens["refresh_token"], "token_type_hint": "refresh_token"})
    check(status == 200, "revocation endpoint accepts refresh token")
    status, _ = token(basic, grant_type="refresh_token", refresh_token=tokens["refresh_token"])
    check(status == 400, "revoked refresh token can no longer be used")
    status, intro, _ = http("POST", "/oauth/introspect", headers={"Authorization": basic}, form={"token": tokens["access_token"]})
    check(intro.get("active") is False, "revoking the refresh token also kills its access token")

    # A password change ends existing sessions.
    code, _ = login(login_key, acme["slug"], "alice", "correct-horse-1", app["client_id"])
    _, tokens = token(basic, grant_type="authorization_code", code=code, redirect_uri=REDIRECT_URI)
    api(acme_key, "PUT", f"/users/{alice['id']}/password", {"password": "correct-horse-1"})
    status, _ = token(basic, grant_type="refresh_token", refresh_token=tokens["refresh_token"])
    check(status == 400, "password change revokes existing refresh tokens")

    # Reducing a user's roles ends their current tokens.
    code, _ = login(login_key, acme["slug"], "alice", "correct-horse-1", app["client_id"])
    _, tokens = token(basic, grant_type="authorization_code", code=code, redirect_uri=REDIRECT_URI)
    ug = api(acme_key, "GET", f"/users/{alice['id']}/grants")[0]
    api(acme_key, "PATCH", f"/user-grants/{ug['id']}", {"role_keys": ["member"]})
    status, _ = token(basic, grant_type="refresh_token", refresh_token=tokens["refresh_token"])
    check(status == 400, "role reduction revokes existing tokens")
    api(acme_key, "PATCH", f"/user-grants/{ug['id']}", {"role_keys": ["admin"]})

    # Granted orgs only see the roles they were granted.
    keys_seen = sorted(r["key"] for r in api(acme_key, "GET", f"/projects/{project['id']}/roles"))
    check(keys_seen == ["admin", "member"], f"granted org sees only granted roles: {keys_seen}")

    # Usernames are case-insensitive and ASCII only.
    status, _, _ = http("POST", f"/v1/orgs/{acme['id']}/users", {"username": "ALICE", "email": "a2@acme.test"},
                        {"Authorization": "Bearer " + acme_key})
    check(status == 409, "usernames are unique case-insensitively")
    status, _, _ = http("POST", f"/v1/orgs/{acme['id']}/users", {"username": "аlice", "email": "a3@acme.test"},
                        {"Authorization": "Bearer " + acme_key})
    check(status == 400, "non-ASCII (look-alike) usernames rejected")
    _, status, _ = password_step(login_key, acme["slug"], "ALICE", "correct-horse-1")
    check(status == 200, "login name matches the username case-insensitively")

    # Pagination.
    check(len(api(key, "GET", "/orgs?limit=1")) == 1, "list endpoints are paginated")

    # Org-scoped login keys only see auth requests of apps their org can use.
    q = urllib.parse.urlencode({"client_id": app["client_id"], "redirect_uri": REDIRECT_URI, "response_type": "code",
                                "scope": "openid", "state": "s", "nonce": "n"})
    loc = http("GET", "/authorize?" + q)[2].get("Location", "")
    ar = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["authRequest"][0]
    other0 = api(key, "POST", "/orgs", {"name": "Outsider", "slug": f"outsider-{suffix}"})
    outsider_key = api(key, "POST", f"/orgs/{other0['id']}/api-keys", {"name": "o", "scope": "login"})["key"]
    status, _, _ = http("GET", f"/v1/auth-requests/{ar}", headers={"Authorization": "Bearer " + outsider_key})
    check(status == 404, "org key of an ungranted org cannot read the auth request")
    status, _, _ = http("POST", "/v1/sessions", {"org": f"no-such-org-{suffix}", "login_name": "x"},
                        {"Authorization": "Bearer " + outsider_key})
    status2, _, _ = http("POST", "/v1/sessions", {"org": acme["slug"], "login_name": "x"},
                         {"Authorization": "Bearer " + outsider_key})
    check(status == status2 == 403, "org key cannot tell missing orgs from foreign orgs")

    # Public clients must use PKCE with S256.
    spa = api(key, "POST", f"/projects/{project['id']}/apps", {
        "name": "spa", "app_type": "spa", "redirect_uris": [REDIRECT_URI], "login_url": LOGIN_URL, "dev_mode": True})
    q = urllib.parse.urlencode({"client_id": spa["client_id"], "redirect_uri": REDIRECT_URI, "response_type": "code",
                                "scope": "openid", "state": "s"})
    status, _, hdrs = http("GET", "/authorize?" + q)
    check("error=invalid_request" in hdrs.get("Location", "") or status == 400, "public client without PKCE is refused")

    # A wrong PKCE verifier must not burn the code for the real client.
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    code, _ = login(login_key, acme["slug"], "alice", "correct-horse-1", spa["client_id"],
                    {"code_challenge": challenge, "code_challenge_method": "S256"})
    pub = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI, "client_id": spa["client_id"]}
    status, _, _ = http("POST", "/oauth/token", form={**pub, "code_verifier": "x" * 50})
    check(status == 400, "exchange with wrong PKCE verifier fails")
    status, _, _ = http("POST", "/oauth/token", form={**pub, "code_verifier": verifier})
    check(status == 200, "the real client can still exchange the code afterwards")

    # Redirect URLs: script schemes are refused even in dev mode.
    status, _, _ = http("POST", f"/v1/projects/{project['id']}/apps", {
        "name": "evil", "app_type": "web", "redirect_uris": ["javascript:alert(1)"], "login_url": LOGIN_URL},
        {"Authorization": "Bearer " + key})
    check(status == 400, "javascript: redirect URI rejected")

    # X-End-User-IP is ignored outside the login API, so audit IPs cannot be forged.
    forged = api(key, "POST", f"/orgs/{acme['id']}/users",
                 {"username": "ivan", "email": "ivan@acme.test"}, headers={"X-End-User-IP": "203.0.113.99"})
    events = api(key, "GET", f"/orgs/{acme['id']}/audit?limit=50")
    created = [e for e in events if e["action"] == "user.created" and e["target"] == "user:" + forged["id"]]
    check(created and created[0]["ip"] != "203.0.113.99", "management audit IP comes from the connection, not the header")

    # Parallel password guesses cannot exceed the lockout threshold.
    import concurrent.futures as cf
    gina = api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "gina", "email": "gina@acme.test", "password": "correct-horse-8"})
    with cf.ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda _: password_step(login_key, acme["slug"], "gina", "wrong-password"), range(8)))
    fails = [e for e in api(key, "GET", f"/orgs/{acme['id']}/audit?limit=200")
             if e["action"] == "login.failed" and e["target"] == "user:" + gina["id"]]
    check(len(fails) <= 5, f"8 parallel guesses: only {len(fails)} evaluated (max 5)")
    _, status, _ = password_step(login_key, acme["slug"], "gina", "correct-horse-8")
    check(status == 401, "account locked after parallel guesses")

    # Temporary lockout instead of a permanent lock.
    dave = api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "dave", "email": "dave@acme.test", "password": "correct-horse-4"})
    for _ in range(5):
        password_step(login_key, acme["slug"], "dave", "wrong-password")
    _, status, _ = password_step(login_key, acme["slug"], "dave", "wrong-password")
    check(status == 401, "wrong password during lockout still looks like a wrong password")
    _, status, _ = password_step(login_key, acme["slug"], "dave", "correct-horse-4")
    check(status == 401, f"correct password during lockout is not confirmed (got {status})")
    check(api(key, "GET", f"/users/{dave['id']}")["locked"] is False, "lockout is temporary, not a manual lock")
    api(key, "POST", f"/users/{dave['id']}/unlock")
    _, status, _ = password_step(login_key, acme["slug"], "dave", "correct-horse-4")
    check(status == 200, "admin unlock clears the lockout")

    # Manual lock: existing tokens become inactive immediately.
    code, _ = login(login_key, acme["slug"], "alice", "correct-horse-1", app["client_id"])
    _, tokens = token(basic, grant_type="authorization_code", code=code, redirect_uri=REDIRECT_URI)
    api(acme_key, "POST", f"/users/{alice['id']}/lock")
    status, intro, _ = http("POST", "/oauth/introspect", headers={"Authorization": basic}, form={"token": tokens["access_token"]})
    check(intro.get("active") is False, "locked user's access token is inactive at introspection")
    status, _ = token(basic, grant_type="refresh_token", refresh_token=tokens["refresh_token"])
    check(status == 400, "locked user cannot refresh")
    api(acme_key, "POST", f"/users/{alice['id']}/unlock")

    # Email verification codes.
    api(acme_key, "PATCH", f"/users/{alice['id']}", {"email": "alice.new@acme.test"})
    check(api(acme_key, "GET", f"/users/{alice['id']}")["email_verified"] is False, "changing email clears verification")
    status, _, _ = http("POST", f"/v1/users/{alice['id']}/email/verification", headers={"Authorization": "Bearer " + acme_key})
    check(status == 403, "org key cannot run email verification (it would see the code)")
    ver = api(key, "POST", f"/users/{alice['id']}/email/verification")
    wrong = "000000" if ver["code"] != "000000" else "111111"
    status, _, _ = http("POST", f"/v1/users/{alice['id']}/email/verify", {"code": wrong}, {"Authorization": "Bearer " + key})
    check(status == 401, "wrong email code rejected")
    api(key, "POST", f"/users/{alice['id']}/email/verify", {"code": ver["code"]})
    check(api(acme_key, "GET", f"/users/{alice['id']}")["email_verified"] is True, "email verified with code")

    # TOTP: password alone is not enough, and a code cannot be replayed.
    erin = api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "erin", "email": "erin@acme.test", "password": "correct-horse-5"})
    en = api(acme_key, "POST", f"/users/{erin['id']}/totp")
    api(acme_key, "POST", f"/users/{erin['id']}/totp/verify", {"code": totp_code(en["secret"])})
    sess, _, st = password_step(login_key, acme["slug"], "erin", "correct-horse-5")
    check(st["mfa_required"] and not st["authenticated"], "password alone not enough with TOTP")
    status, _, _ = http("POST", f"/v1/sessions/{sess['session_id']}/totp",
                        {"session_token": sess["session_token"], "code": totp_code(en["secret"])},
                        {"Authorization": "Bearer " + login_key})
    check(status == 401, "TOTP code already used for enrollment is rejected (replay)")
    print("     waiting for the next TOTP window...")
    time.sleep(30 - time.time() % 30 + 1)
    st = api(login_key, "POST", f"/sessions/{sess['session_id']}/totp",
             {"session_token": sess["session_token"], "code": totp_code(en["secret"])})
    check(st["authenticated"], "fresh TOTP code authenticates")
    st = api(login_key, "POST", f"/sessions/{sess['session_id']}/password",
             {"session_token": sess["session_token"], "password": "correct-horse-5"})
    check(st["totp_checked"] is False and st["authenticated"] is False,
          "re-entering the password requires a fresh TOTP code")

    # TOTP failures are not reset by re-entering the correct password.
    frank = api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "frank", "email": "frank@acme.test", "password": "correct-horse-6"})
    fen = api(key, "POST", f"/users/{frank['id']}/totp")
    api(key, "POST", f"/users/{frank['id']}/totp/verify", {"code": totp_code(fen["secret"])})
    def wrong_totp(sess):
        return http("POST", f"/v1/sessions/{sess['session_id']}/totp",
                    {"session_token": sess["session_token"], "code": "000000"},
                    {"Authorization": "Bearer " + login_key})[0]
    sess, _, _ = password_step(login_key, acme["slug"], "frank", "correct-horse-6")
    for _ in range(4):
        wrong_totp(sess)
    sess, _, _ = password_step(login_key, acme["slug"], "frank", "correct-horse-6")
    wrong_totp(sess)
    _, status, _ = password_step(login_key, acme["slug"], "frank", "correct-horse-6")
    check(status == 401, "TOTP guessing locks the account despite password re-entry")
    api(key, "POST", f"/users/{frank['id']}/unlock")

    # An org without a grant cannot sign in to the app.
    other = api(key, "POST", "/orgs", {"name": "Other", "slug": f"other-{suffix}"})
    api(key, "POST", f"/orgs/{other['id']}/users", {"username": "bob", "email": "bob@other.test", "password": "correct-horse-2"})
    _, status = login(login_key, other["slug"], "bob", "correct-horse-2", app["client_id"])
    check(status == 403, "user of an ungranted org is refused")

    # Revoking the project grant cuts Acme off, including refresh.
    code, _ = login(login_key, acme["slug"], "alice", "correct-horse-1", app["client_id"])
    _, tokens = token(basic, grant_type="authorization_code", code=code, redirect_uri=REDIRECT_URI)
    grants = api(key, "GET", f"/projects/{project['id']}/grants")
    api(acme_key, "DELETE", f"/project-grants/{grants[0]['id']}")  # the granted org leaves
    status, _ = token(basic, grant_type="refresh_token", refresh_token=tokens["refresh_token"])
    check(status == 400, "granted org can leave a project; refresh refused afterwards")

    # Audit trail.
    actions = {e["action"] for e in api(acme_key, "GET", f"/orgs/{acme['id']}/audit?limit=500")}
    needed = {"login.succeeded", "login.failed", "user.locked_out", "user.locked", "user.email_verified", "project_grant.deleted"}
    check(needed <= actions, "audit trail records logins, lockouts and admin actions")
    status, _, _ = http("GET", "/v1/audit", headers={"Authorization": "Bearer " + acme_key})
    check(status == 403, "org key cannot read the instance-wide audit log")

    # Per-IP rate limit on the login API.
    statuses = [http("POST", "/v1/sessions", {"org": acme["slug"], "login_name": "x"},
                     {"Authorization": "Bearer " + login_key, "X-End-User-IP": "203.0.113.7"})[0]
                for _ in range(40)]
    check(429 in statuses and statuses[0] == 201, "login API rate-limited per end-user IP")

    # Existence oracle: an unrelated org cannot tell a foreign project from a missing one.
    stranger = api(key, "POST", "/orgs", {"name": "Stranger", "slug": f"stranger-{suffix}"})
    stranger_key = api(key, "POST", f"/orgs/{stranger['id']}/api-keys", {"name": "s"})["key"]
    status, _, _ = http("GET", f"/v1/projects/{project['id']}", headers={"Authorization": "Bearer " + stranger_key})
    status2, _, _ = http("DELETE", f"/v1/apps/{app['id']}", headers={"Authorization": "Bearer " + stranger_key})
    check(status == status2 == 404, "foreign projects and apps look missing (404)")

    # Org keys expire, and keys they mint die with them.
    parent = api(key, "POST", f"/orgs/{stranger['id']}/api-keys", {"name": "parent"})
    child = api(parent["key"], "POST", f"/orgs/{stranger['id']}/api-keys", {"name": "child"})
    check(child["expires_at"] is not None, "org-created keys get an expiry by default")
    status, _, _ = http("POST", f"/v1/orgs/{stranger['id']}/api-keys", {"name": "forever", "expires_in_days": 3650},
                        {"Authorization": "Bearer " + parent["key"]})
    check(status == 400, "org keys cannot mint keys longer than 365 days")
    api(key, "DELETE", f"/orgs/{stranger['id']}/api-keys/{parent['id']}")
    status, _, _ = http("GET", f"/v1/orgs/{stranger['id']}", headers={"Authorization": "Bearer " + child["key"]})
    check(status == 401, "deleting a key also revokes the keys it created")

    # Quotas.
    statuses = [http("POST", f"/v1/orgs/{stranger['id']}/api-keys", {"name": f"k{i}"},
                     {"Authorization": "Bearer " + key})[0] for i in range(52)]
    check(409 in statuses and statuses.count(201) <= 50, "per-org API key quota enforced (50)")

    # Email code cooldown.
    api(key, "POST", f"/users/{alice['id']}/email/verification")
    status, _, _ = http("POST", f"/v1/users/{alice['id']}/email/verification", headers={"Authorization": "Bearer " + key})
    check(status == 429, "new email code within a minute is refused")

    status, init_js, _ = http("GET", "/docs/init.js")
    check(status == 404 or "persistAuthorization: false" in init_js, "Swagger UI does not persist API keys")

    status, jwks, _ = http("GET", "/keys")
    check(status == 200 and len(jwks["keys"]) >= 1, "JWKS published")
    # Invalid API keys are throttled per address (last: it blocks this IP briefly).
    statuses = [http("GET", "/v1/orgs", headers={"Authorization": "Bearer iam_wrong"})[0] for _ in range(35)]
    check(statuses[0] == 401 and 429 in statuses, "invalid API key attempts are rate-limited")
    status, _, _ = http("GET", "/v1/orgs?limit=1", headers={"Authorization": "Bearer " + key})
    check(status == 200, "a valid key from the same address is never blocked")
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
