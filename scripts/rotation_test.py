"""End-to-end test for master key rotation (audit M6, M8, M9).

Run against the dev engine in three steps, restarting it in between:

  python scripts/rotation_test.py prepare  STATE.json   # old key
  # restart with IAM_MASTER_KEY=<new>, IAM_MASTER_KEY_PREVIOUS=<old>
  python scripts/rotation_test.py during   STATE.json
  # iamd rotate-keys; iamd rotate-keys --check; restart without the previous key
  python scripts/rotation_test.py after    STATE.json

`prepare` creates values sealed with the old key: an unexchanged
authorization code, a refresh token, an email verification code, a TOTP
secret and an IdP client secret. `during` checks they all still work after the
restart with the new key (M6). `after` checks the re-encrypted data works
without the old key.
"""

import json
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.argv, (phase, state_path) = sys.argv[:1], sys.argv[1:3]
import smoke_test as t  # noqa: E402
import features_test as f  # noqa: E402

check, api, http = t.check, t.api, t.http


def login_with_totp(s, key):
    sess, status, _ = t.password_step(key, s["org"], "rosa", "rotate-pass-123")
    check(status == 200, "password login works")
    time.sleep(30 - time.time() % 30 + 1)  # a fresh TOTP window, so the code is not a replay
    st = api(key, "POST", f"/sessions/{sess['session_id']}/totp",
             {"session_token": sess["session_token"], "code": t.totp_code(s["totp_secret"])})
    check(st["authenticated"], "TOTP (encrypted secret) verifies")


def federated_start(s, key):
    status, start, _ = http("POST", "/v1/federated-logins",
                            {"org": s["org"], "idp_id": s["idp_id"], "return_url": "http://localhost:3000/sso-return",
                             "browser_binding": secrets.token_urlsafe(32)}, {"Authorization": "Bearer " + key})
    check(status == 201 and start["auth_url"], "IdP client secret (encrypted) can be decrypted")


def refresh(s):
    status, tokens = t.token(s["basic"], grant_type="refresh_token", refresh_token=s["refresh_token"])
    check(status == 200, "refresh token issued before the rotation still works")
    s["refresh_token"] = tokens["refresh_token"]


def main():
    key = t.admin_key()
    if phase == "prepare":
        sfx = secrets.token_hex(3)
        login_key = api(key, "POST", "/api-keys", {"name": "rotation login", "scope": "login", "expires_in_days": 1})["key"]
        org = api(key, "POST", "/orgs", {"name": "Rotation", "slug": f"rot-{sfx}"})
        project = api(key, "POST", f"/orgs/{org['id']}/projects", {"name": "P"})
        app = api(key, "POST", f"/projects/{project['id']}/apps", {
            "name": "web", "app_type": "web", "redirect_uris": [t.REDIRECT_URI], "login_url": t.LOGIN_URL, "dev_mode": True})
        basic = f.basic(app["client_id"], app["client_secret"])
        user = api(key, "POST", f"/orgs/{org['id']}/users", {"username": "rosa", "email": "rosa@rot.test", "password": "rotate-pass-123"})
        code, _ = t.login(login_key, org["slug"], "rosa", "rotate-pass-123", app["client_id"])
        _, tokens = t.token(basic, grant_type="authorization_code", code=code, redirect_uri=t.REDIRECT_URI)
        pending_code, _ = t.login(login_key, org["slug"], "rosa", "rotate-pass-123", app["client_id"])
        en = api(key, "POST", f"/users/{user['id']}/totp")
        api(key, "POST", f"/users/{user['id']}/totp/verify", {"code": t.totp_code(en["secret"])})
        ver = api(key, "POST", f"/users/{user['id']}/email/verification")
        idp = api(key, "POST", f"/orgs/{org['id']}/idps", {
            "name": "Ext", "issuer": t.ISSUER, "client_id": app["client_id"], "client_secret": app["client_secret"]})
        state = {"org": org["slug"], "user_id": user["id"], "login_key": login_key, "basic": basic,
                 "pending_code": pending_code, "refresh_token": tokens["refresh_token"],
                 "email_code": ver["code"], "totp_secret": en["secret"], "idp_id": idp["id"]}
        json.dump(state, open(state_path, "w"))
        print("PREPARED (old key)")
        return

    s = json.load(open(state_path))
    login_key = s["login_key"]
    if phase == "during":
        status, tokens = t.token(s["basic"], grant_type="authorization_code", code=s["pending_code"], redirect_uri=t.REDIRECT_URI)
        check(status == 200, f"authorization code issued before the restart is accepted (M6, {status})")
        api(key, "POST", f"/users/{s['user_id']}/email/verify", {"code": s["email_code"]})
        check(api(key, "GET", f"/users/{s['user_id']}")["email_verified"], "email code issued before the restart verifies (M6)")
        refresh(s)
        federated_start(s, login_key)
        login_with_totp(s, login_key)
    elif phase == "after":
        refresh(s)
        federated_start(s, login_key)
        login_with_totp(s, login_key)
    json.dump(s, open(state_path, "w"))
    print(f"ROTATION CHECKS PASSED ({phase})")


if __name__ == "__main__":
    main()
