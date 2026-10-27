"""End-to-end tests for password reset, machine users, per-org SSO and passkeys.

Run against a running dev engine (IAM_DEV_MODE=true, IAM_WEBAUTHN_ORIGINS
including http://localhost:3000):  python scripts/features_test.py

SSO is tested with the engine as its own external identity provider: one org's
OIDC app plays the customer's IdP. Passkeys use a software authenticator
(ES256) built on the `cryptography` package.
"""

import base64
import concurrent.futures
import hashlib
import json
import os
import secrets
import struct
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import smoke_test as t  # noqa: E402  (shared HTTP helpers)

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

ORIGIN = "http://localhost:3000"
RP_ID = "localhost"
check, api, http = t.check, t.api, t.http


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# --- minimal CBOR encoder (enough for WebAuthn attestation objects) ----------------

def cbor(v):
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        if n < 256:
            return bytes([major << 5 | 24, n])
        if n < 65536:
            return bytes([major << 5 | 25]) + struct.pack(">H", n)
        return bytes([major << 5 | 26]) + struct.pack(">I", n)
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        e = v.encode()
        return head(3, len(e)) + e
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(type(v))


class Authenticator:
    """A software passkey: one ES256 credential with a signature counter."""

    def __init__(self, synced=False):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = secrets.token_bytes(32)
        self.counter = 0
        self.user_handle = b""
        # Backup eligible + backed up flags, as set by synced passkeys.
        self.backup_flags = 0x18 if synced else 0

    def register(self, options, origin=ORIGIN):
        pk = options["publicKey"]
        self.user_handle = unb64u(pk["user"]["id"])
        client_data = json.dumps({"type": "webauthn.create", "challenge": pk["challenge"],
                                  "origin": origin, "crossOrigin": False}).encode()
        nums = self.key.public_key().public_numbers()
        cose = cbor({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        auth_data = (hashlib.sha256(pk["rp"]["id"].encode()).digest() + bytes([0x45 | self.backup_flags]) + struct.pack(">I", 0)
                     + bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + cose)
        att = cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client_data), "attestationObject": b64u(att)},
                "clientExtensionResults": {}}

    def assert_(self, options, origin=ORIGIN, counter=None):
        pk = options["publicKey"]
        self.counter = self.counter + 1 if counter is None else counter
        client_data = json.dumps({"type": "webauthn.get", "challenge": pk["challenge"],
                                  "origin": origin, "crossOrigin": False}).encode()
        auth_data = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x05 | self.backup_flags]) + struct.pack(">I", self.counter)
        sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64u(self.cred_id), "rawId": b64u(self.cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(client_data), "authenticatorData": b64u(auth_data),
                             "signature": b64u(sig), "userHandle": b64u(self.user_handle)},
                "clientExtensionResults": {}}


def basic(client_id, client_secret):
    pair = f"{urllib.parse.quote(client_id)}:{urllib.parse.quote(client_secret)}"
    return "Basic " + base64.b64encode(pair.encode()).decode()


def start_authorize(client_id):
    q = urllib.parse.urlencode({"client_id": client_id, "redirect_uri": t.REDIRECT_URI, "response_type": "code",
                                "scope": "openid profile email", "state": "st", "nonce": "nn"})
    loc = http("GET", "/authorize?" + q)[2].get("Location", "")
    return urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["authRequest"][0]


def finalize_and_exchange(key, auth_request, sess, app_basic):
    """Finalize an auth request with an authenticated session; return token claims."""
    fin = api(key, "POST", f"/auth-requests/{auth_request}/finalize",
              {"session_id": sess["session_id"], "session_token": sess["session_token"]})
    loc = http("GET", fin["callback_url"])[2].get("Location", "")
    code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]
    status, tokens, _ = http("POST", "/oauth/token", headers={"Authorization": app_basic},
                             form={"grant_type": "authorization_code", "code": code, "redirect_uri": t.REDIRECT_URI})
    check(status == 200, "tokens issued for the authenticated session")
    _, info, _ = http("GET", "/userinfo", headers={"Authorization": "Bearer " + tokens["access_token"]})
    claims = {**t.jwt_claims(tokens["id_token"]), "email": info.get("email")}
    return claims, t.jwt_claims(tokens["access_token"])


def main():
    key = t.admin_key()
    sfx = secrets.token_hex(3)
    login_key = api(key, "POST", "/api-keys", {"name": "features login", "scope": "login", "expires_in_days": 1})["key"]

    # Vendor product + a customer org granted access.
    vendor = api(key, "POST", "/orgs", {"name": "Vendor", "slug": f"fvendor-{sfx}"})
    project = api(key, "POST", f"/orgs/{vendor['id']}/projects", {"name": "SaaS"})
    for role in ("admin", "reader"):
        api(key, "POST", f"/projects/{project['id']}/roles", {"key": role})
    app = api(key, "POST", f"/projects/{project['id']}/apps", {
        "name": "web", "app_type": "web", "redirect_uris": [t.REDIRECT_URI], "login_url": t.LOGIN_URL, "dev_mode": True})
    app_basic = basic(app["client_id"], app["client_secret"])
    acme = api(key, "POST", "/orgs", {"name": "Acme", "slug": f"facme-{sfx}"})
    api(key, "POST", f"/projects/{project['id']}/grants", {"org_id": acme["id"], "role_keys": ["admin", "reader"]})

    # --- project-grant modification authorization (internal audit N20/F2) --------------------
    # Boundaries that hold regardless of the pending owner-decision on who may
    # adjust an existing grant's role set: the granted org cannot modify the grant
    # it received, an unrelated org cannot touch it, and the role set stays
    # confined to the owning project's defined roles.
    grant = api(key, "GET", f"/projects/{project['id']}/grants")[0]
    acme_key = api(key, "POST", f"/orgs/{acme['id']}/api-keys", {"name": "acme admin"})["key"]
    other = api(key, "POST", "/orgs", {"name": "Other", "slug": f"fother-{sfx}"})
    other_key = api(key, "POST", f"/orgs/{other['id']}/api-keys", {"name": "other admin"})["key"]
    status, _, _ = http("PATCH", f"/v1/project-grants/{grant['id']}", {"role_keys": ["admin", "reader"]},
                        {"Authorization": "Bearer " + acme_key})
    check(status in (403, 404), f"granted org cannot modify its own project grant ({status})")
    status, _, _ = http("PATCH", f"/v1/project-grants/{grant['id']}", {"role_keys": ["admin"]},
                        {"Authorization": "Bearer " + other_key})
    check(status == 404, f"unrelated org cannot modify a project grant ({status})")
    status, _, _ = http("DELETE", f"/v1/project-grants/{grant['id']}", None,
                        {"Authorization": "Bearer " + other_key})
    check(status == 404, f"unrelated org cannot delete a project grant ({status})")
    status, _, _ = http("PATCH", f"/v1/project-grants/{grant['id']}", {"role_keys": ["nonexistent"]},
                        {"Authorization": "Bearer " + key})
    check(status == 400, f"a project grant cannot list a role the project has not defined ({status})")

    # --- password reset ---------------------------------------------------------------------
    api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "rita", "email": "rita@acme.test", "password": "correct-horse-0"})
    reset = api(login_key, "POST", "/password-resets", {"org": acme["slug"], "login_name": "rita"}, expect=(202,))
    check(bool(reset.get("token")) and reset["email"] == "rita@acme.test", "password reset token issued")
    check(api(login_key, "POST", "/password-resets", {"org": acme["slug"], "login_name": "ghost"}, expect=(202,)) == {},
          "unknown user gets the same 202 with no token")
    status, _, _ = http("POST", "/v1/password-resets/confirm", {"token": reset["token"], "password": "short"},
                        {"Authorization": "Bearer " + login_key})
    check(status == 400, "weak new password rejected (token not used up)")
    api(login_key, "POST", "/password-resets/confirm", {"token": reset["token"], "password": "brand-new-pass-1"})
    status, _, _ = http("POST", "/v1/password-resets/confirm", {"token": reset["token"], "password": "brand-new-pass-2"},
                        {"Authorization": "Bearer " + login_key})
    check(status == 401, "reset token works only once")
    _, status, _ = t.password_step(login_key, acme["slug"], "rita", "brand-new-pass-1")
    check(status == 200, "new password works")
    _, status, _ = t.password_step(login_key, acme["slug"], "rita", "correct-horse-0")
    check(status == 401, "old password no longer works")

    def reset_token(login_name):
        return api(login_key, "POST", "/password-resets", {"org": acme["slug"], "login_name": login_name}, expect=(202,))

    def confirm_status(token, password):
        return http("POST", "/v1/password-resets/confirm", {"token": token, "password": password},
                    {"Authorization": "Bearer " + login_key})[0]

    # Audit L1/L2: a request inside the cooldown looks like an unknown user, and
    # does not cancel the token already emailed.
    api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "rob", "email": "rob@acme.test", "password": "correct-horse-7"})
    first = reset_token("rob")
    check(reset_token("rob") == {}, "reset within the cooldown answers like an unknown user (L1)")
    check(confirm_status(first["token"], "fresh-pass-1234") == 204, "earlier reset token still valid (L2)")
    # Audit M12 (reproductions R4, R4b): credential changes and locks end reset tokens.
    lee = api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "lee", "email": "lee@acme.test", "password": "correct-horse-8"})
    tok = reset_token("lee")["token"]
    api(key, "POST", f"/users/{lee['id']}/lock")
    check(confirm_status(tok, "changed-while-locked-1") == 401, "reset refused for a manually locked user (R4)")
    api(key, "POST", f"/users/{lee['id']}/unlock")
    check(confirm_status(tok, "changed-after-lock-1") == 401, "lock invalidated the reset token for good")
    _, status, _ = t.password_step(login_key, acme["slug"], "lee", "correct-horse-8")
    check(status == 200, "locked user's password was not changed")
    max_ = api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "max", "email": "max@acme.test", "password": "correct-horse-9"})
    tok = reset_token("max")["token"]
    api(key, "PUT", f"/users/{max_['id']}/password", {"password": "admin-set-pass-1"})
    check(confirm_status(tok, "old-token-pass-1") == 401, "admin password change invalidates reset tokens (R4b)")
    eve = api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "eve", "email": "eve@acme.test", "password": "correct-horse-6"})
    tok = reset_token("eve")["token"]
    api(key, "PATCH", f"/users/{eve['id']}", {"email": "eve-new@acme.test"})
    check(confirm_status(tok, "after-email-change-1") == 401, "email change invalidates reset tokens")
    # Audit L3: a password reset does not lift a lockout caused by TOTP guessing.
    tia = api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "tia", "email": "tia@acme.test", "password": "correct-horse-4"})
    en = api(key, "POST", f"/users/{tia['id']}/totp")
    api(key, "POST", f"/users/{tia['id']}/totp/verify", {"code": t.totp_code(en["secret"])})
    tok = reset_token("tia")["token"]
    sess, _, _ = t.password_step(login_key, acme["slug"], "tia", "correct-horse-4")
    for _ in range(5):
        http("POST", f"/v1/sessions/{sess['session_id']}/totp", {"session_token": sess["session_token"], "code": "000000"},
             {"Authorization": "Bearer " + login_key})
    check(confirm_status(tok, "after-totp-lockout-1") == 204, "reset still sets a new password during a lockout")
    _, status, _ = t.password_step(login_key, acme["slug"], "tia", "after-totp-lockout-1")
    check(status == 401, "reset does not lift the TOTP lockout (L3)")
    api(key, "POST", f"/users/{tia['id']}/unlock")
    _, status, _ = t.password_step(login_key, acme["slug"], "tia", "after-totp-lockout-1")
    check(status == 200, "after an admin unlock the new password works")

    # --- machine users ------------------------------------------------------------------------
    bot = api(key, "POST", f"/orgs/{acme['id']}/machine-users", {"name": "billing-sync"})
    bot_grant = api(key, "POST", f"/users/{bot['id']}/grants", {"project_id": project["id"], "role_keys": ["reader"]})
    bot_basic = basic(bot["client_id"], bot["client_secret"])
    check(http("POST", "/v1/password-resets", {"org": acme["slug"], "login_name": "billing-sync"},
               {"Authorization": "Bearer " + login_key})[1] == {}, "machine users get no reset token")
    status, tok, _ = http("POST", "/oauth/token", headers={"Authorization": bot_basic},
                          form={"grant_type": "client_credentials", "scope": "urn:iam:project:" + project["id"]})
    check(status == 200, "machine user gets a token with client_credentials")
    check(tok.get("scope") == "urn:iam:project:" + project["id"], f"only the validated scope is granted ({tok.get('scope')})")
    # Audit M1 (reproduction F3): unsupported or extra scopes are refused, not passed through.
    for bad in (f"urn:iam:project:{project['id']} admin:all openid email",
                f"urn:iam:project:{project['id']} urn:iam:project:{project['id']}",
                "urn:iam:project:not-a-uuid", "openid", "offline_access"):
        status, err, _ = http("POST", "/oauth/token", headers={"Authorization": bot_basic},
                              form={"grant_type": "client_credentials", "scope": bad})
        check(status == 400 and err.get("error") == "invalid_scope", f"scope {bad!r} refused with invalid_scope (F3)")
    claims = t.jwt_claims(tok["access_token"])
    check(claims["sub"] == bot["id"] and claims["org_id"] == acme["id"] and claims["roles"] == ["reader"],
          f"machine token carries org and project roles {claims.get('roles')}")
    status, intro, _ = http("POST", "/oauth/introspect", headers={"Authorization": app_basic}, form={"token": tok["access_token"]})
    check(intro.get("active") is True, "project app can introspect the machine token")
    # Audit L5 (reproduction F8): removing the grant ends the project-scoped token.
    api(key, "DELETE", f"/user-grants/{bot_grant['id']}")
    _, intro, _ = http("POST", "/oauth/introspect", headers={"Authorization": app_basic}, form={"token": tok["access_token"]})
    check(intro.get("active") is False, "machine token inactive after its grant is removed (F8)")
    bot_grant = api(key, "POST", f"/users/{bot['id']}/grants", {"project_id": project["id"], "role_keys": ["reader"]})
    status, tok, _ = http("POST", "/oauth/token", headers={"Authorization": bot_basic},
                          form={"grant_type": "client_credentials", "scope": "urn:iam:project:" + project["id"]})
    # Audit L6: a machine user can revoke its own token.
    status, _, _ = http("POST", "/revoke", headers={"Authorization": bot_basic}, form={"token": tok["access_token"]})
    _, intro, _ = http("POST", "/oauth/introspect", headers={"Authorization": app_basic}, form={"token": tok["access_token"]})
    check(status == 200 and intro.get("active") is False, f"machine user revokes its own token (L6, status {status})")
    status, _, _ = http("POST", "/revoke", headers={"Authorization": basic(bot["client_id"], "wrong")}, form={"token": "x"})
    check(status == 401, "revocation with a wrong machine secret is refused")
    status, live, _ = http("POST", "/oauth/token", headers={"Authorization": bot_basic},
                           form={"grant_type": "client_credentials", "scope": "urn:iam:project:" + project["id"]})
    _, intro, _ = http("POST", "/oauth/introspect", headers={"Authorization": bot_basic}, form={"token": live["access_token"]})
    check(intro.get("active") is False and "sub" not in intro, "machine credentials cannot introspect tokens")
    other_project = api(key, "POST", f"/orgs/{vendor['id']}/projects", {"name": "Other"})
    status, _, _ = http("POST", "/oauth/token", headers={"Authorization": bot_basic},
                        form={"grant_type": "client_credentials", "scope": "urn:iam:project:" + other_project["id"]})
    check(status == 400, "machine user cannot get a token for a project its org has no access to")
    status, _, _ = http("POST", "/oauth/token", headers={"Authorization": basic(bot["client_id"], "wrong")},
                        form={"grant_type": "client_credentials"})
    check(status == 401, "wrong client secret rejected")
    status, _, _ = http("PUT", f"/v1/users/{bot['id']}/password", {"password": "some-password-1"}, {"Authorization": "Bearer " + key})
    check(status == 400, "machine users cannot get a password")
    rotated = api(key, "POST", f"/users/{bot['id']}/client-secret")
    status, _, _ = http("POST", "/oauth/token", headers={"Authorization": bot_basic}, form={"grant_type": "client_credentials"})
    check(status == 401, "old secret stops working after rotation")
    status, _, _ = http("POST", "/oauth/token", headers={"Authorization": basic(bot["client_id"], rotated["client_secret"])},
                        form={"grant_type": "client_credentials"})
    check(status == 200, "new secret works")

    # --- per-org SSO: the engine federates to an "external" IdP (itself) ----------------------------
    corp = api(key, "POST", "/orgs", {"name": "Corp IdP", "slug": f"fcorp-{sfx}"})
    corp_project = api(key, "POST", f"/orgs/{corp['id']}/projects", {"name": "Corp SSO"})
    callback = t.ISSUER + "/idp/callback"
    corp_app = api(key, "POST", f"/projects/{corp_project['id']}/apps", {
        "name": "acme sso", "app_type": "web", "redirect_uris": [callback], "login_url": t.LOGIN_URL, "dev_mode": True})
    api(key, "POST", f"/orgs/{corp['id']}/users", {"username": "carl", "email": "carl@corp.test", "email_verified": True,
                                                   "given_name": "Carl", "password": "corp-pass-123"})
    idp_conf = {"name": "Corp", "issuer": t.ISSUER, "client_id": corp_app["client_id"], "client_secret": corp_app["client_secret"]}
    # Audit M11: just-in-time provisioning is off unless asked for.
    plain_idp = api(key, "POST", f"/orgs/{acme['id']}/idps", idp_conf)
    check(plain_idp["auto_create_users"] is False and plain_idp["trust_email"] is False and plain_idp["trust_mfa"] is False,
          "IdP defaults: no JIT users, email and MFA not trusted")
    idp = api(key, "POST", f"/orgs/{acme['id']}/idps", {**idp_conf, "auto_create_users": True})
    check(idp["callback_url"] == callback, "IdP config returns the callback URL to register")
    # Audit M2: tenant admins cannot mark their own IdP as trusted.
    acme_admin = api(key, "POST", f"/orgs/{acme['id']}/api-keys", {"name": "acme admin"})["key"]
    status, _, _ = http("POST", f"/v1/orgs/{acme['id']}/idps", {**idp_conf, "trust_email": True},
                        {"Authorization": "Bearer " + acme_admin})
    check(status == 400, "org admin cannot create an IdP with trust_email")
    status, _, _ = http("POST", f"/v1/orgs/{acme['id']}/idps", {**idp_conf, "link_by_email": True},
                        {"Authorization": "Bearer " + key})
    check(status == 400, "link_by_email requires trust_email")
    status, _, _ = http("PUT", f"/v1/orgs/{acme['id']}/idps/{idp['id']}/trust", {"trust_email": True, "trust_mfa": True},
                        {"Authorization": "Bearer " + acme_admin})
    check(status == 403, "org admin cannot change the IdP trust policy")
    for domains in (["*.corp.test"], ["corp"], ["co rp.test"]):
        status, _, _ = http("POST", f"/v1/orgs/{acme['id']}/idps", {**idp_conf, "allowed_email_domains": domains},
                            {"Authorization": "Bearer " + key})
        check(status == 400, f"invalid email domain allowlist {domains} refused")

    # --- provider presets: Google, Microsoft personal, Entra -----------------------------------
    # Creation stores config only (no network), so these are deterministic and need no live IdP.
    creds = {"client_id": "preset-client", "client_secret": "preset-secret-value"}
    google = api(key, "POST", f"/orgs/{acme['id']}/idps", {"name": "Google", "provider_type": "google", **creds})
    check(google["issuer"] == "https://accounts.google.com" and google["provider_type"] == "google",
          "google preset pins the Google issuer")
    check("client_secret" not in json.dumps(google), "provider config read never includes the client secret")
    msa = api(key, "POST", f"/orgs/{acme['id']}/idps", {"name": "MS personal", "provider_type": "microsoft", **creds})
    check(msa["issuer"] == "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0",
          "microsoft preset pins the personal-account (consumers) issuer")
    tenant = "11112222-3333-4444-5555-666677778888"
    entra = api(key, "POST", f"/orgs/{acme['id']}/idps",
                {"name": "Entra", "provider_type": "entra", "tenant": tenant, **creds})
    check(entra["issuer"] == f"https://login.microsoftonline.com/{tenant}/v2.0" and entra["tenant"] == tenant,
          "entra preset pins the configured tenant issuer")
    upper = api(key, "POST", f"/orgs/{acme['id']}/idps",
                {"name": "Entra upper", "provider_type": "entra", "tenant": tenant.upper(), **creds})
    check(upper["tenant"] == tenant and upper["issuer"] == f"https://login.microsoftonline.com/{tenant}/v2.0",
          "entra tenant is stored lowercased to match the pinned issuer")
    # Misconfigurations are refused.
    for label, payload in [
        ("unknown provider_type", {"name": "x", "provider_type": "azure", **creds}),
        ("entra without tenant", {"name": "x", "provider_type": "entra", **creds}),
        ("entra tenant not a GUID", {"name": "x", "provider_type": "entra", "tenant": "contoso.com", **creds}),
        ("google with tenant", {"name": "x", "provider_type": "google", "tenant": tenant, **creds}),
        ("preset with explicit issuer", {"name": "x", "provider_type": "google", "issuer": "https://evil.example", **creds}),
        ("preset without client secret", {"name": "x", "provider_type": "google", "client_id": "c"}),
    ]:
        status, _, _ = http("POST", f"/v1/orgs/{acme['id']}/idps", payload, {"Authorization": "Bearer " + key})
        check(status == 400, f"rejected: {label}")
    # An org admin still cannot grant trust on a preset provider.
    status, _, _ = http("POST", f"/v1/orgs/{acme['id']}/idps",
                        {"name": "x", "provider_type": "google", "trust_email": True, **creds},
                        {"Authorization": "Bearer " + acme_admin})
    check(status == 400, "org admin cannot set trust_email on a preset provider")

    def browser_binding():
        return secrets.token_urlsafe(32)  # what the login UI keeps in an HttpOnly cookie

    def sso_callback(idp_id, binding):
        """Runs the browser round trip; returns the login UI return URL query."""
        start = api(login_key, "POST", "/federated-logins",
                    {"org": acme["slug"], "idp_id": idp_id, "return_url": "http://localhost:3000/sso-return",
                     "browser_binding": binding})
        # Browser: engine-as-IdP authorize -> corp login UI (session API) -> corp callback -> engine /idp/callback.
        loc = http("GET", start["auth_url"])[2]["Location"]
        corp_ar = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["authRequest"][0]
        cs = api(login_key, "POST", "/sessions", {"org": corp["slug"], "login_name": "carl"})
        api(login_key, "POST", f"/sessions/{cs['session_id']}/password", {"session_token": cs["session_token"], "password": "corp-pass-123"})
        fin = api(login_key, "POST", f"/auth-requests/{corp_ar}/finalize", {"session_id": cs["session_id"], "session_token": cs["session_token"]})
        idp_cb = http("GET", fin["callback_url"])[2]["Location"]
        check(idp_cb.startswith(callback), "IdP redirects back to the engine callback")
        status, _, hdrs = http("GET", idp_cb)
        back = hdrs.get("Location", "")
        check(status == 302 and back.startswith("http://localhost:3000/sso-return"), "engine returns to the login UI")
        return urllib.parse.parse_qs(urllib.parse.urlparse(back).query), idp_cb

    def redeem(q, binding):
        return http("POST", f"/v1/federated-logins/{q['intent'][0]}/redeem", {"code": q["code"][0], "browser_binding": binding},
                    {"Authorization": "Bearer " + login_key})

    def sso_login(idp_id):
        binding = browser_binding()
        q, idp_cb = sso_callback(idp_id, binding)
        check("code" in q, f"engine verifies the IdP login ({q.get('error')})")
        replay_status, _, _ = http("GET", idp_cb)
        status, sess, _ = redeem(q, binding)
        check(status == 201, "redeem from the initiating browser works")
        return sess, replay_status, q, binding

    q, _ = sso_callback(plain_idp["id"], browser_binding())
    check(q.get("error") == ["no_account"], "IdP without auto_create_users does not provision users (M11)")

    # Audit M3: the intent is bound to the browser that started it.
    status, _, _ = http("POST", "/v1/federated-logins", {"org": acme["slug"], "idp_id": idp["id"],
                                                         "return_url": "http://localhost:3000/sso-return"},
                        {"Authorization": "Bearer " + login_key})
    check(status == 400, "federated login without a browser binding is refused")
    binding = browser_binding()
    q, _ = sso_callback(idp["id"], binding)
    status, _, _ = redeem(q, browser_binding())
    check(status == 401, "redeem from another browser (cross-browser callback replay) is refused")
    status, _, _ = redeem(q, binding)
    check(status == 401, f"a refused redeem burns the intent ({status})")

    sess, replay_status, q, binding = sso_login(idp["id"])
    check(replay_status == 400, "IdP callback cannot be replayed")
    check(sess["authenticated"] and sess["amr"] == ["fed"], "redeemed SSO session is authenticated (amr fed)")
    status, _, _ = redeem(q, binding)
    check(status == 401, "SSO redeem code works only once")
    idt, _ = finalize_and_exchange(login_key, start_authorize(app["client_id"]), sess, app_basic)
    check(idt["email"] == "carl@corp.test" and idt["org_id"] == acme["id"], "SSO user created just-in-time in the customer org")
    first_sub = idt["sub"]
    jit = api(key, "GET", f"/users/{first_sub}")
    check(jit["email_verified"] is False, "IdP email_verified is not trusted without trust_email (M2, reproduction F1)")
    sess2, _, _, _ = sso_login(idp["id"])
    idt2, _ = finalize_and_exchange(login_key, start_authorize(app["client_id"]), sess2, app_basic)
    check(idt2["sub"] == first_sub, "second SSO login links to the same user")

    # Audit D1: users with TOTP must still enter it after SSO, unless the IdP is trusted for MFA.
    en = api(key, "POST", f"/users/{first_sub}/totp")
    api(key, "POST", f"/users/{first_sub}/totp/verify", {"code": t.totp_code(en["secret"])})
    sess3, _, _, _ = sso_login(idp["id"])
    check(not sess3["authenticated"] and sess3["mfa_required"], "SSO alone is not enough for a TOTP user (D1)")
    print("     waiting for the next TOTP window...")
    time.sleep(30 - time.time() % 30 + 1)
    st = api(login_key, "POST", f"/sessions/{sess3['session_id']}/totp",
             {"session_token": sess3["session_token"], "code": t.totp_code(en["secret"])})
    check(st["authenticated"] and st["amr"] == ["fed", "otp", "mfa"], f"SSO plus TOTP authenticates ({st.get('amr')})")
    trusted = api(key, "PUT", f"/orgs/{acme['id']}/idps/{idp['id']}/trust", {"trust_email": True, "trust_mfa": True})
    check(trusted["trust_mfa"] is True, "instance admin sets the IdP trust policy")
    sess4, _, _, _ = sso_login(idp["id"])
    check(sess4["authenticated"] and sess4["amr"] == ["fed", "mfa"], "trusted IdP satisfies MFA (amr fed mfa)")

    # --- passkeys -------------------------------------------------------------------------------
    pia = api(key, "POST", f"/orgs/{acme['id']}/users", {"username": "pia", "email": "pia@acme.test", "given_name": "Pia"})
    api(key, "POST", f"/users/{pia['id']}/grants", {"project_id": project["id"], "role_keys": ["admin"]})
    authr = Authenticator()
    options = api(key, "POST", f"/users/{pia['id']}/passkeys/registration")
    check(options["publicKey"]["rp"]["id"] == RP_ID, "registration options bound to the RP ID")
    passkey = api(key, "POST", f"/users/{pia['id']}/passkeys/registration/finish",
                  {"name": "laptop", "credential": authr.register(options)})
    check(passkey["id"] == b64u(authr.cred_id), "passkey registered")
    check(len(api(key, "GET", f"/users/{pia['id']}/passkeys")) == 1, "passkey listed")

    sess = api(login_key, "POST", "/sessions", {"org": acme["slug"], "login_name": "pia"})
    opts = api(login_key, "POST", f"/sessions/{sess['session_id']}/passkey/begin", {"session_token": sess["session_token"]})
    check(opts["publicKey"].get("userVerification") == "required", "login requires user verification")
    st = api(login_key, "POST", f"/sessions/{sess['session_id']}/passkey/finish",
             {"session_token": sess["session_token"], "credential": authr.assert_(opts)})
    check(st["authenticated"] and "hwk" in st["amr"], "passwordless passkey login authenticates (amr hwk)")
    idt, at = finalize_and_exchange(login_key, start_authorize(app["client_id"]), sess, app_basic)
    check(idt["sub"] == pia["id"] and "hwk" in idt.get("amr", []) and at["roles"] == ["admin"], "passkey login yields tokens")

    def passkey_attempt(assertion_fn):
        s = api(login_key, "POST", "/sessions", {"org": acme["slug"], "login_name": "pia"})
        o = api(login_key, "POST", f"/sessions/{s['session_id']}/passkey/begin", {"session_token": s["session_token"]})
        return http("POST", f"/v1/sessions/{s['session_id']}/passkey/finish",
                    {"session_token": s["session_token"], "credential": assertion_fn(o)},
                    {"Authorization": "Bearer " + login_key})[0], s, o

    status, _, _ = passkey_attempt(lambda o: authr.assert_(o, origin="https://evil.example"))
    check(status == 401, "assertion from a foreign origin is rejected")
    status, s, o = passkey_attempt(lambda o: authr.assert_(o))
    check(status == 200, "a fresh assertion works")
    status, _, _ = http("POST", f"/v1/sessions/{s['session_id']}/passkey/finish",
                        {"session_token": s["session_token"], "credential": authr.assert_(o)},
                        {"Authorization": "Bearer " + login_key})
    check(status == 401, "a challenge can be answered only once")
    status, _, _ = passkey_attempt(lambda o: authr.assert_(o, counter=1))
    check(status == 401, "a repeated signature counter (cloned key) is rejected")
    ghost = api(login_key, "POST", "/sessions", {"org": acme["slug"], "login_name": "nobody-at-all"})
    status, _, _ = http("POST", f"/v1/sessions/{ghost['session_id']}/passkey/begin", {"session_token": ghost["session_token"]},
                        {"Authorization": "Bearer " + login_key})
    check(status == 200, "passkey begin for an unknown user looks the same (no enumeration)")
    other = Authenticator()
    other.user_handle = pia["id"].encode()
    status, _, _ = passkey_attempt(lambda o: other.assert_(o))
    check(status == 401, "an unregistered key cannot sign in")

    # Audit M5 (reproduction R1): no credential IDs are disclosed, and the
    # options for a user with passkeys, without passkeys and an unknown login
    # name have the same shape.
    def begin_options(login_name):
        s = api(login_key, "POST", "/sessions", {"org": acme["slug"], "login_name": login_name})
        return api(login_key, "POST", f"/sessions/{s['session_id']}/passkey/begin", {"session_token": s["session_token"]})["publicKey"]

    def shape(pk):
        return {k: v for k, v in pk.items() if k != "challenge"}

    known, without, unknown = begin_options("pia"), begin_options("rita"), begin_options("nobody-" + sfx)
    check(not known.get("allowCredentials"), "passkey begin lists no credential IDs (R1)")
    check(shape(known) == shape(without) == shape(unknown), "passkey options identical for known, keyless and unknown users")

    # Audit L9: two logins racing with the same counter value: only one wins.
    s1 = api(login_key, "POST", "/sessions", {"org": acme["slug"], "login_name": "pia"})
    s2 = api(login_key, "POST", "/sessions", {"org": acme["slug"], "login_name": "pia"})
    o1 = api(login_key, "POST", f"/sessions/{s1['session_id']}/passkey/begin", {"session_token": s1["session_token"]})
    o2 = api(login_key, "POST", f"/sessions/{s2['session_id']}/passkey/begin", {"session_token": s2["session_token"]})
    n = 1000  # above every counter used so far (an earlier check rewound authr.counter)
    bodies = [(s1, authr.assert_(o1, counter=n)), (s2, authr.assert_(o2, counter=n))]
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        statuses = list(pool.map(lambda sa: http("POST", f"/v1/sessions/{sa[0]['session_id']}/passkey/finish",
                                                    {"session_token": sa[0]["session_token"], "credential": sa[1]},
                                                    {"Authorization": "Bearer " + login_key})[0], bodies))
    check(sorted(statuses) == [200, 401], f"concurrent logins cannot reuse a signature counter (L9, {statuses})")

    # Audit L8: a synced (backup-eligible) passkey is reported as swk, not hwk.
    synced = Authenticator(synced=True)
    options = api(key, "POST", f"/users/{pia['id']}/passkeys/registration")
    api(key, "POST", f"/users/{pia['id']}/passkeys/registration/finish", {"name": "phone", "credential": synced.register(options)})
    s = api(login_key, "POST", "/sessions", {"org": acme["slug"], "login_name": "pia"})
    o = api(login_key, "POST", f"/sessions/{s['session_id']}/passkey/begin", {"session_token": s["session_token"]})
    st = api(login_key, "POST", f"/sessions/{s['session_id']}/passkey/finish",
             {"session_token": s["session_token"], "credential": synced.assert_(o)})
    check(st["authenticated"] and st["amr"] == ["swk", "user", "mfa"], f"synced passkey reported as swk ({st.get('amr')})")

    # Regression (cross-factor lockout): a temporary password lockout must NOT
    # block a phishing-resistant passkey the attacker cannot guess. Before the
    # fix the passkey/federated/finalize paths used IsLocked() (which includes
    # the temporary lockout), so password guessing denied all factors.
    # A fresh user, so the per-account attempt limiter (keyed on org:login_name,
    # capacity 10) is not already consumed by the earlier passkey operations.
    xname = f"xfactor-{sfx}"
    xuser = api(key, "POST", f"/orgs/{acme['id']}/users",
                {"username": xname, "email": f"{xname}@acme.test", "password": "correct-horse-xfactor-1"})
    xauth = Authenticator()
    xopts = api(key, "POST", f"/users/{xuser['id']}/passkeys/registration")
    api(key, "POST", f"/users/{xuser['id']}/passkeys/registration/finish",
        {"name": "xfactor key", "credential": xauth.register(xopts)})
    for _ in range(5):  # a fresh session per guess, like the smoke lockout test
        t.password_step(login_key, acme["slug"], xname, "definitely-wrong")
    _, pstatus, _ = t.password_step(login_key, acme["slug"], xname, "correct-horse-xfactor-1")
    check(pstatus == 401, "the password factor is locked after repeated failures")
    xs = api(login_key, "POST", "/sessions", {"org": acme["slug"], "login_name": xname})
    xo = api(login_key, "POST", f"/sessions/{xs['session_id']}/passkey/begin", {"session_token": xs["session_token"]})
    xst = api(login_key, "POST", f"/sessions/{xs['session_id']}/passkey/finish",
              {"session_token": xs["session_token"], "credential": xauth.assert_(xo)})
    check(xst.get("authenticated") is True,
          "a passkey login still succeeds during a temporary password lockout (cross-factor DoS fix)")

    # Regression (API-key expiry cap): a key may not mint a successor that
    # outlives it, or a leaked but still-valid key could renew itself forever.
    shortkey = api(key, "POST", f"/orgs/{acme['id']}/api-keys", {"name": "short-parent", "scope": "admin", "expires_in_days": 1})
    child = api(shortkey["key"], "POST", f"/orgs/{acme['id']}/api-keys", {"name": "child", "scope": "admin", "expires_in_days": 365})
    check(bool(child.get("expires_at")) and child["expires_at"] <= shortkey["expires_at"],
          "a child key cannot be minted to outlive its parent (expiry cap)")

    print("ALL FEATURE CHECKS PASSED")


if __name__ == "__main__":
    main()
