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

7. **Rotate the master key** (for example yearly, or right away if it may have leaked):
   1. Set a new `IAM_MASTER_KEY`, move the old value to `IAM_MASTER_KEY_PREVIOUS`, and restart.
   2. Run `docker compose -f docker-compose.prod.yml --env-file .env.prod run --rm iam rotate-keys`.
      It re-encrypts every stored secret (signing keys, TOTP secrets, IdP client secrets)
      and prints how many it changed. A second run prints 0.
   3. Remove `IAM_MASTER_KEY_PREVIOUS` and restart. Short-lived opaque tokens and pending
      email codes from before the rotation stop working; nothing else changes.

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

## Before real customer data

Commission an external penetration test. [PENTEST.md](PENTEST.md) is a scope
brief you can hand to the tester.
