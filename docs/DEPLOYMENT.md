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

### Expected one-time disruption from migration 0006

Migration `0006_audit_remediation.sql` makes two changes that intentionally
invalidate short-lived, in-flight security state. These are deliberate
security-remediation consequences, **not** signs that the upgrade failed:

1. It **drops and recreates the `password_resets` table**, so every
   password-reset token outstanding at upgrade time stops working. Tokens live
   at most 30 minutes, so the affected window is small.
2. It adds the required browser-binding column to federation intents
   (`ALTER TABLE idp_intents ADD COLUMN binding_hash text NOT NULL DEFAULT ''`).
   Intents started before the upgrade carry an empty binding and **can no longer
   be redeemed**, because redemption requires a non-empty binding that matches
   the returning browser's cookie.

After the upgrade, therefore:

- Users who had requested a password reset must **request a new reset link**.
- Users in the middle of an SSO / federated login must **start the login again**.
- Existing user **passwords and already-completed sessions are not invalidated**
  by these two changes. Migration 0006 adds columns to `sessions`
  (`idp_trust_mfa`, `passkey_synced`) with safe defaults and does not touch
  stored password hashes; source inspection of the migration confirms this.

Plan the upgrade in a brief **maintenance window** and tell operators to expect
this short-lived disruption to password-reset and federated-login flows.
Draining in-flight requests before the upgrade reduces how many users are
affected, but it does **not** remove the need for this warning: a reset token or
login intent created just before the cutover is still invalidated.

### Recovering from a failed migration

The engine applies migrations automatically at startup: `Migrate` in
[internal/db/db.go](../internal/db/db.go) runs every file under
`internal/db/migrations/*.sql` not yet recorded in the `schema_migrations`
table, in lexical order, **each inside its own transaction that also records the
version**. There is **no automatic down-migration mechanism** in this
repository; migrations only move forward.

If a migration fails during an upgrade:

1. **Stop or isolate the application instances** if your deployment's
   consistency requires it, so no instance keeps retrying blindly against a
   half-upgraded target.
2. **Preserve the exact error and migration logs.** The engine returns
   `apply <file>: <error>`; capture it rather than restarting in a loop.
3. **Determine what actually committed.** Inspect the tracking table —
   `SELECT version FROM schema_migrations ORDER BY version;` — and the relevant
   schema. Because each migration commits atomically with its own
   `schema_migrations` row, a version is present only if that migration fully
   applied.
4. **A failed migration rolls back its own changes** (its transaction aborts),
   while every earlier, already-committed migration stays applied. The database
   is left at the last fully-applied version, not in a half-applied state within
   a single migration.
5. **If the cause is correctable** (for example a transient resource limit), fix
   the underlying issue, confirm the current `schema_migrations` state, and
   **rerun the normal mechanism** — restart the engine, which re-applies only
   the still-pending migrations.
6. **If recovery requires a backup**, restore to an **isolated target first** and
   validate schema and data there before directing any application traffic to
   it. Backup tooling, restore commands, storage locations, and retention are
   environment-specific and must come from your deployment runbook — this
   repository defines none.
7. **Treat restoration as a coordinated database-recovery operation.** Do not
   restore an older snapshot over a live or newer database without an approved
   recovery decision; doing so can discard legitimate writes made after the
   snapshot.
8. **Before reopening traffic**, verify the final version in `schema_migrations`,
   application health, a real login flow, and that audit events are being
   written.

Distinguish three different actions:

- **Repair and rerun** a failed, rolled-back migration — fix the cause and
  restart the engine so it re-applies the pending migration. This is the
  preferred path for a correctable failure.
- **Restore from backup** after an unrecoverable problem — a full, coordinated
  database recovery (see above), not a routine step.
- **Roll back the application binary** — reverting to the previous engine image
  does **not** roll back schema changes already committed by 0006 or 0007, and
  an older binary may not understand the newer schema. Decide binary and schema
  recovery together.

## Rehearsing migrations and recovery

[`scripts/migration_rehearsal.sh`](../scripts/migration_rehearsal.sh) exercises
the recovery-relevant properties of this section against disposable, isolated
Postgres containers, so you can confirm them before and after any schema change:

- **Fresh install** — a brand-new database receives every migration, in order,
  and the engine becomes reachable afterwards.
- **Backup and restore** — a `pg_dump` of a populated database restores onto a
  *separate* target (the "isolated target first" rule above) with identical
  `schema_migrations` state and the data intact, and a second engine run against
  the restored target applies zero further migrations.
- **Upgrade path** — a database left at the pre-0007 state is upgraded by the
  engine, which applies exactly 0007, and a generic OIDC provider that pre-dates
  0007 survives as `provider_type='oidc'` with an empty tenant.

It needs only Docker and an engine image (`iam-iam:latest` by default; override
with `IAM_REHEARSAL_IMAGE`). It uses ephemeral keys, makes no off-host network
calls, touches nothing already running, and removes everything it creates on
exit. Exit status is `0` only if every assertion passed. The script is a
*rehearsal of the mechanism*; the backup tooling, storage, and restore commands
for a real environment remain the runbook items described above.

## Before real customer data

Commission an external penetration test. [PENTEST.md](PENTEST.md) is a scope
brief you can hand to the tester.
