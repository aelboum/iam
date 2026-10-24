"""End-to-end tests for password reset, machine users, per-org SSO and passkeys.

Run against a running dev engine (IAM_DEV_MODE=true, IAM_WEBAUTHN_ORIGINS
including http://localhost:3000):  python scripts/features_test.py

SSO is tested with the engine as its own external identity provider: one org's
OIDC app plays the customer's IdP. Passkeys use a software authenticator
(ES256) built on the `cryptography` package.
"""

import base64
import hashlib
import json
import os
import secrets
import struct
import sys
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

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = secrets.token_bytes(32)
        self.counter = 0
        self.user_handle = b""

    def register(self, options, origin=ORIGIN):
        pk = options["publicKey"]
        self.user_handle = unb64u(pk["user"]["id"])
        client_data = json.dumps({"type": "webauthn.create", "challenge": pk["challenge"],
                                  "origin": origin, "crossOrigin": False}).encode()
        nums = self.key.public_key().public_numbers()
        cose = cbor({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        auth_data = (hashlib.sha256(pk["rp"]["id"].encode()).digest() + bytes([0x45]) + struct.pack(">I", 0)
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
        auth_data = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x05]) + struct.pack(">I", self.counter)
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

    # --- machine users ------------------------------------------------------------------------
    bot = api(key, "POST", f"/orgs/{acme['id']}/machine-users", {"name": "billing-sync"})
    api(key, "POST", f"/users/{bot['id']}/grants", {"project_id": project["id"], "role_keys": ["reader"]})
    bot_basic = basic(bot["client_id"], bot["client_secret"])
    status, tok, _ = http("POST", "/oauth/token", headers={"Authorization": bot_basic},
                          form={"grant_type": "client_credentials", "scope": "urn:iam:project:" + project["id"]})
    check(status == 200, "machine user gets a token with client_credentials")
    claims = t.jwt_claims(tok["access_token"])
    check(claims["sub"] == bot["id"] and claims["org_id"] == acme["id"] and claims["roles"] == ["reader"],
          f"machine token carries org and project roles {claims.get('roles')}")
    status, intro, _ = http("POST", "/oauth/introspect", headers={"Authorization": app_basic}, form={"token": tok["access_token"]})
    check(intro.get("active") is True, "project app can introspect the machine token")
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
    idp = api(key, "POST", f"/orgs/{acme['id']}/idps", {
        "name": "Corp", "issuer": t.ISSUER, "client_id": corp_app["client_id"], "client_secret": corp_app["client_secret"]})
    check(idp["callback_url"] == callback, "IdP config returns the callback URL to register")

    def sso_login():
        start = api(login_key, "POST", "/federated-logins",
                    {"org": acme["slug"], "idp_id": idp["id"], "return_url": "http://localhost:3000/sso-return"})
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
        q = urllib.parse.parse_qs(urllib.parse.urlparse(back).query)
        check(status == 302 and back.startswith("http://localhost:3000/sso-return") and "code" in q,
              f"engine verifies the IdP login and returns to the login UI ({q.get('error')})")
        replay_status, _, _ = http("GET", idp_cb)
        sess = api(login_key, "POST", f"/federated-logins/{q['intent'][0]}/redeem", {"code": q["code"][0]})
        return sess, replay_status, q

    sess, replay_status, q = sso_login()
    check(replay_status == 400, "IdP callback cannot be replayed")
    check(sess["authenticated"] and sess["amr"] == ["fed"], "redeemed SSO session is authenticated (amr fed)")
    status, _, _ = http("POST", f"/v1/federated-logins/{q['intent'][0]}/redeem", {"code": q["code"][0]},
                        {"Authorization": "Bearer " + login_key})
    check(status == 401, "SSO redeem code works only once")
    idt, _ = finalize_and_exchange(login_key, start_authorize(app["client_id"]), sess, app_basic)
    check(idt["email"] == "carl@corp.test" and idt["org_id"] == acme["id"], "SSO user created just-in-time in the customer org")
    first_sub = idt["sub"]
    sess2, _, _ = sso_login()
    idt2, _ = finalize_and_exchange(login_key, start_authorize(app["client_id"]), sess2, app_basic)
    check(idt2["sub"] == first_sub, "second SSO login links to the same user")

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

    print("ALL FEATURE CHECKS PASSED")


if __name__ == "__main__":
    main()
