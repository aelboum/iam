# Production deployment

`docker-compose.prod.yml` runs the engine behind [Caddy](https://caddyserver.com),
which obtains and renews the TLS certificate automatically.

```
internet ──443──> caddy (TLS, HSTS) ──> iam:8080 ──> postgres:5432
                                        (no public port) (no public port)
```

## Steps

1. **DNS:** point `auth.example.com` (your domain) at the server. Open ports 80 and 443.
2. **Secrets:** `cp .env.prod.example .env.prod` and fill in every value.
   - Generate them with `openssl rand`, as the file explains.
   - Store `IAM_MASTER_KEY` in a password manager or secrets manager. **If it is lost,
     signing keys and TOTP secrets cannot be recovered.**
   - Prefer injecting the values from a secrets manager rather than keeping `.env.prod`
     on disk. The file is gitignored either way.
3. **Start:** `docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build`
4. **Verify:**
   - `curl https://auth.example.com/healthz` prints `ok`.
   - `/.well-known/openid-configuration` shows `"issuer":"https://auth.example.com"`.
   - `/docs` returns 404.
5. **Rotate the bootstrap key:**
   - Create your own instance key: `POST /v1/api-keys` `{"name":"ops","expires_in_days":90}`.
   - Delete the bootstrap key: `DELETE /v1/api-keys/{id}`, then remove
     `IAM_BOOTSTRAP_ADMIN_KEY` from `.env.prod`. It is never recreated.
   - Create a `login`-scoped key for your login UI backend.
6. **Backups:** back up the `pgdata` volume (for example a nightly `pg_dump`) and keep
   the master key separately from the backups.

7. **Rotate the master key** (for example yearly, or right away if it may have leaked).
   Back up the database and keep a copy of the old key until step 5 is done.
   1. Set a new `IAM_MASTER_KEY`, move the old value to `IAM_MASTER_KEY_PREVIOUS`, and
      restart every instance. Nothing stops working: the engine encrypts with the new key
      and still decrypts with the old one: stored secrets, authorization codes, opaque
      access tokens and email verification codes issued before the restart all keep working.
   2. Run `docker compose -f docker-compose.prod.yml --env-file .env.prod run --rm iam rotate-keys`.
      It re-encrypts every stored secret (signing keys, TOTP secrets, IdP client secrets,
      pending SSO logins) with the new key and prints how many it changed. It works in
      batches of 500 rows without long transactions or table locks, so it can run while
      the engine serves traffic. Each row is updated only if it is unchanged since it was
      read, so it is safe to interrupt and re-run; a second run prints 0.
   3. Run `... run --rm iam rotate-keys --check`. It decrypts every stored secret with the
      new key alone and exits with an error, listing the rows, if any still needs the
      old key. Only continue when it succeeds. It is strictly read-only: it writes
      nothing and changes no row.
   4. Wait until values sealed under the old key by the engine itself have expired: at
      least 30 minutes, or `IAM_ACCESS_TOKEN_TTL` if that is longer. These are
      authorization codes (5 minutes), opaque access tokens (`IAM_ACCESS_TOKEN_TTL`) and
      email codes (15 minutes). Run `rotate-keys --check` again.
   5. Remove `IAM_MASTER_KEY_PREVIOUS` and restart. Sessions, refresh tokens, JWT access
      tokens, password reset tokens and API keys are not encrypted with the master key
      and are unaffected. `rotate-keys` logs a fingerprint of the current key (never the
      key), so you can confirm which key a run used.

   If logins, SSO or token signing fail after step 5, put the old key back into
   `IAM_MASTER_KEY_PREVIOUS` and restart: nothing has been lost, because the old key can
   still decrypt anything `rotate-keys` did not reach. Then repeat steps 2 and 3.

## What the production stack enforces

| Setting | Value | Why |
|---|---|---|
| `IAM_DEV_MODE` | `false` | https issuer only; no `dev_mode` apps; no plain-http redirect URIs |
| `IAM_ENABLE_DOCS` | `false` | Swagger UI off. Caddy also blocks `/docs` |
| `IAM_TRUST_PROXY` / `IAM_TRUSTED_PROXY_HOPS` | `true` / `1` | Real client IPs for rate limits and audit; spoofed `X-Forwarded-For` ignored |
| Engine and Postgres ports | not published | Only Caddy is reachable from outside |
| Containers | read-only, `cap_drop: ALL`, `no-new-privileges` | Limits damage if a process is compromised |
| HSTS | 2 years | Browsers refuse plain http |

All of this was verified with a local run of the stack: TLS, HSTS, the http→https
redirect, `/docs` blocked, a spoofed `X-Forwarded-For` ignored, and `dev_mode` and http
redirect URIs refused.

## Scaling notes

- The production stack counts rate limits in Postgres (`IAM_SHARED_RATE_LIMITS=true`), so
  they hold across all engine instances.
- Signing keys are coordinated through Postgres, so several instances can share one database.

## Upgrading past the audit-remediation release

This release changes some defaults and one API contract. Review before upgrading
an existing deployment. Details are in the README and [openapi.yaml](../internal/docs/openapi.yaml).

- **Migration 0006 drops pending password resets.** It recreates the
  `password_resets` table, so reset tokens outstanding at migration time (at
  most 30 minutes old) stop working. Any affected user can request a new reset
  link; no action is required from operators.
- **Existing identity providers become untrusted for email.** Every existing
  IdP is set to `trust_email=false` and `trust_mfa=false`. Email-based account
  linking (`link_by_email`) stops until an **instance admin** turns trust back
  on with `PUT /v1/orgs/{orgID}/idps/{idpID}/trust`, and SSO users provisioned
  meanwhile are stored with an unverified email. This is deliberate: an IdP is
  configured by the tenant, so an **organization admin cannot grant its own IdP
  trusted-email status** — only an instance admin can. Re-enable trust only for
  IdPs you control or vet.
- **SSO now requires a browser binding.** `POST /v1/federated-logins` and
  `POST /v1/federated-logins/{intentID}/redeem` both require a `browser_binding`
  field. Existing login UIs must be updated: before redirecting to the IdP, set
  an `HttpOnly`, `Secure`, `SameSite=Lax` cookie on the login UI's own origin
  holding at least 32 random bytes (base64url), send that value as
  `browser_binding` on start, and on return send the value from the returning
  browser's cookie on redeem. A redeem without the matching binding fails and
  burns the login attempt. This binds a login to the browser that began it and
  prevents login-CSRF; do not log or share the value.
- **Invalid WebAuthn configuration now stops startup.** Each
  `IAM_WEBAUTHN_ORIGINS` entry must be a bare origin (`scheme://host[:port]`,
  no path or trailing slash), use `https` outside dev mode, and have a host
  equal to `IAM_WEBAUTHN_RP_ID` or a subdomain of it. Validate the two settings
  against your login UI's real origin in staging before deploying; a bad value
  fails fast at boot rather than breaking passkeys silently.

## Before real customer data

Commission an external penetration test. [PENTEST.md](PENTEST.md) is a scope
brief you can hand to the tester.
