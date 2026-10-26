# HTTPS staging rehearsal (WS9)

This is the plan for the staging rehearsal that production authorization depends
on. It is **not** evidence of a pass; it defines exactly what to provision and
run so the rehearsal produces retained evidence when an isolated staging host
and the provider credentials exist. Nothing here authorizes production traffic.

Staging exists to re-establish, under real HTTPS and the production
configuration posture, what the local non-production tests established on
`http://localhost` with `IAM_DEV_MODE=true`. The engine refuses an `http` or
private issuer unless dev mode is on (`internal/config/config.go`), so the
localhost round trips could not themselves prove the HTTPS path — that is the
gap this rehearsal closes.

## Prerequisites

All must be **non-production** and disposable:

1. An isolated host or cluster reachable at a dedicated DNS name over TLS
   (for example `iam.staging.example`), with a valid certificate terminated by
   a proxy in front of the engine. No production data, keys, or traffic.
2. A dedicated Postgres 17 instance for staging only.
3. Freshly generated `IAM_MASTER_KEY` (32-byte base64) and
   `IAM_BOOTSTRAP_ADMIN_KEY` (≥32 chars) created for staging and stored in the
   staging secret store — never reused from any other environment.
4. The live-provider registrations, each pointed at the staging callback
   `https://<staging-host>/idp/callback`:
   - **Google** — the WS5 OAuth client, or a staging-specific one, with the
     staging redirect URI added.
   - **Microsoft personal (WS6)** — *out of the initial production scope*
     (see ROADMAP.md WS6); not part of this staging rehearsal unless a future
     release adds MSA to scope.
   - **Microsoft Entra (WS7)** — a test directory, app registration, directory
     GUID, a test user, and one out-of-directory identity for the mandatory
     cross-tenant rejection gate.

## Configuration posture (production-like, not dev)

Set on the staging engine, and confirm each at boot:

- `IAM_ISSUER=https://<staging-host>` — the callback is `{issuer}/idp/callback`.
- `IAM_DEV_MODE` **unset / false** — this is the whole point of staging; the
  engine must accept only an `https` issuer.
- `IAM_WEBAUTHN_RP_ID` and `IAM_WEBAUTHN_ORIGINS` set to the staging login UI's
  real domain and origin; invalid values fail fast at boot.
- TLS 1.2+ at the proxy; set `IAM_TRUST_PROXY=true` and
  `IAM_TRUSTED_PROXY_HOPS` to the exact number of trusted hops if the proxy
  sets the client IP.
- Secrets injected from the staging secret store as environment variables,
  never committed or baked into images.

## Rehearsal steps (produce evidence for each)

1. **Migration and recovery.** Run
   [`scripts/migration_rehearsal.sh`](../scripts/migration_rehearsal.sh) against
   the staging engine image (fresh install, backup/restore to an isolated
   target, pre-0007 upgrade path). Retain its `ALL_PASS` log.
2. **Startup posture.** Confirm the engine refuses to start with an `http`
   issuer (dev mode off), and starts cleanly with the `https` issuer. Confirm
   `schema_migrations` lists every migration and the health check passes.
3. **Live Google round trip over HTTPS.** Repeat the WS5 flow against the
   staging issuer: mint the authorization URL and verify host
   `accounts.google.com`, the byte-exact
   `redirect_uri=https://<staging-host>/idp/callback`, `state`, `nonce`, PKCE
   `code_challenge`+`S256`, and `scope=openid profile email`; complete a human
   browser login; verify the redeemed session is `authenticated`, `amr=["fed"]`,
   `idp_checked`, and the identity is keyed on `(idp_id, subject)`. Re-run the
   live negatives (forged state, burned intent, wrong binding).
4. **Live Entra round trip over HTTPS (WS7).** Same shape against the test
   directory, plus the **mandatory cross-tenant rejection gate**: a login
   attempt with an identity outside the configured directory must be rejected
   (issuer mismatch; strict equality).
5. **Microsoft personal (WS6).** Out of initial scope (ROADMAP.md WS6) — not run
   for the initial release. If a future release adds MSA, run it here: same shape
   as Google, issuer pinned to the consumers tenant.
6. **Backup/restore of the staging database** using the environment's real
   backup tooling (not just the rehearsal script), restored to an isolated
   target and validated before any reuse.

## Rollback and recovery criteria (rehearse before relying on them)

Decide and prove these in staging, not during a production incident:

- **Abort criteria.** Stop the rollout and investigate if: the engine fails to
  start (migration error, invalid config, or WebAuthn-origin rejection), the
  health check does not pass, `schema_migrations` is missing any migration, a
  real login flow fails, or audit events stop being written.
- **Binary rollback does not roll back schema.** Reverting to a previous engine
  image does **not** undo schema changes already committed by 0006 or 0007, and
  an older binary may not understand the newer schema. Decide binary and schema
  recovery together (DEPLOYMENT.md § *Recovering from a failed migration*).
- **Restore to an isolated target first.** If recovery needs a backup, restore
  onto a separate database and validate schema and data there before directing
  traffic to it; never restore an older snapshot over a live or newer database
  without an approved recovery decision.
- **Rehearse the restore** with the environment's real backup tooling (step 6),
  and record the measured restore time so an incident has a known bound.

## Ephemeral VM runbook (the committed staging bundle)

The reviewable bundle is `docker-compose.staging.yml` (project name
`iam-staging`), the reused `deploy/Caddyfile`, and `.env.staging.example`. It
brings up Caddy (auto-TLS) + the engine (dev mode off) + a dedicated, unpublished
Postgres 17. Everything below runs on the disposable host; nothing is provisioned
from this repository.

### Remaining manual steps (operator, on the VM)

1. **Create a small disposable VM** (1 vCPU / 1 GB is enough), with inbound
   80/443 open and SSH restricted to your IP. Install Docker Engine + compose.
2. **DNS / hostname.** Point a hostname at the VM's public IP (an `A`/`AAAA`
   record), or use a provider hostname. This value is `IAM_DOMAIN`.
3. **Clone the repo** on the VM and `cp .env.staging.example .env.staging`.
4. **Inject staging-only secrets** into `.env.staging` (or the host secret
   store): `IAM_MASTER_KEY=$(openssl rand -base64 32)`,
   `POSTGRES_PASSWORD=$(openssl rand -hex 32)`,
   `IAM_BOOTSTRAP_ADMIN_KEY=$(openssl rand -hex 32)`, and set `IAM_DOMAIN`,
   `IAM_WEBAUTHN_RP_ID`, `IAM_WEBAUTHN_ORIGINS`. Never reuse a production value;
   never commit the filled file.
5. **Add the HTTPS redirect URI** `https://<IAM_DOMAIN>/idp/callback` to the
   **Google** OAuth client and the **Entra** app registration (Web platform),
   alongside the existing local one. (Operator action in each provider console —
   not done from here.)
6. **Start:** `docker compose -f docker-compose.staging.yml --env-file .env.staging up -d --build`.

### Startup and health checks (capture output as evidence)

```
# Compose file is valid and fully resolved (no secrets echoed beyond your .env):
docker compose -f docker-compose.staging.yml --env-file .env.staging config -q

# Engine reports healthy (the container healthcheck probes /healthz):
docker compose -f docker-compose.staging.yml ps

# Dev mode is really off: an http issuer must be refused. This MUST fail to boot:
docker run --rm -e IAM_DEV_MODE=false -e IAM_ISSUER=http://x -e IAM_MASTER_KEY=x iam-staging-iam \
  || echo "OK: engine refuses an http issuer when dev mode is off"

# Health and migrations over real HTTPS:
curl -fsS https://<IAM_DOMAIN>/healthz && echo "  healthz OK"
docker compose -f docker-compose.staging.yml exec -T postgres \
  psql -U iam -d iam -c "select version from schema_migrations order by version;"
```

Then run the live round trips and suites against the staging issuer (see
`.env.staging.example` harness section and steps 3–5 above):
`python scripts/smoke_test.py https://<IAM_DOMAIN>` and the Google/Entra
federation harness pointed at the same issuer.

### Backup, restore, and recovery-time measurement

Database access is private to the compose network; reach it through the
container. Restore onto an **isolated** target and validate before trusting it.

```
# Timed backup:
time docker compose -f docker-compose.staging.yml exec -T postgres \
  pg_dump -U iam -Fc iam > iam-staging-$(date +%Y%m%d%H%M%S).dump

# Restore onto a SEPARATE scratch database and validate there (never over the live DB):
docker compose -f docker-compose.staging.yml exec -T postgres \
  psql -U iam -d postgres -c "create database restore_check;"
time docker compose -f docker-compose.staging.yml exec -T postgres \
  pg_restore -U iam -d restore_check --no-owner < iam-staging-<stamp>.dump
docker compose -f docker-compose.staging.yml exec -T postgres \
  psql -U iam -d restore_check -c "select count(*) from schema_migrations;"
```

Record the two `time` figures; their sum is the measured recovery bound for an
incident. For the migration + upgrade rehearsal (fresh install, backup/restore,
pre-0007 upgrade) reuse the existing script rather than re-deriving it:
`scripts/migration_rehearsal.sh` — retain its `ALL_PASS` log.

### Teardown (what exactly gets removed)

```
# Removes ONLY the iam-staging project's containers, the default network, and the
# named volumes (pgdata, caddy_data, caddy_config) — nothing else on the host:
docker compose -f docker-compose.staging.yml --env-file .env.staging down -v
```

Then **destroy the VM** (and release its static IP / DNS record if created).
The bundle touches no resource outside the `iam-staging` project; it never
references the developer stack (`iam-iam`, `iam-postgres`) or any production
target.

### Cost control

Use the smallest instance that boots the stack; stop or destroy it whenever the
rehearsal is not actively running (TLS certs and data live in the named volumes,
but for a disposable run prefer tear-down + rebuild). Let's Encrypt and the
provider hostname are free; the only running cost is VM compute, which is
sub-dollar for a few hours. Delete the VM as soon as evidence is captured.

## Go / no-go

Staging is complete for pre-production only when steps 1–4 pass with retained
evidence and the Entra cross-tenant rejection is proven live. WS6 may remain
deferred with that fact recorded. Production stays **NO-GO** until the overall
completion criteria in [ROADMAP.md](ROADMAP.md) are met; a staging pass is
pre-production evidence, never production authorization.
