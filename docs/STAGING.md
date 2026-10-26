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

**Rollback triggers (stop the rollout and execute recovery).** Any of: a migration
fails or aborts mid-apply; the engine is unhealthy after an upgrade (health check
fails, or it will not start); a database integrity check fails; identity/federation
flows are unavailable (login or redeem broken for a supported provider); key or
session incompatibility appears after a key or schema change; a backup or restore
fails its validation; or recovery is trending past the agreed time bound.

**Decision ownership and preconditions.** The release manager decides a rollback,
with the platform/DBA owner for any database action. Preconditions: a validated,
recent backup retained off-host, and a known-good previous engine image. Recovery
action: restore the validated backup to an isolated target, validate schema and data
there, then cut over — and pair the binary and schema recovery decision, because an
older binary may not understand newer schema.

**Per-migration strategy (forward-only).** Migrations 0001–0007 are forward-only and
each is transactional (atomic per file). There are no down-migrations and none should
be invented: reversing committed schema (e.g. 0006/0007) can lose data. The rollback
path is therefore restore-from-backup plus a compatible engine image, not a schema
down-migration.

**Rehearsed (2026-10-26, disposable).** On throwaway containers: a seeded database
(7 migrations, 3 orgs) was backed up, then degraded (`DROP TABLE orgs CASCADE` on the
disposable source only — never the active staging DB), then recovered by restoring the
backup onto a fresh isolated target: 7 migrations and all 3 orgs restored, a fresh engine
became reachable and applied zero further migrations, and the pre/post integrity check
matched (`pre_orgs == post_orgs`). Evidence is recorded in
[EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md) § 4.

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

Confirm the **running** engine advertises the expected issuer. This is a
separate check from the `IAM_DEV_MODE=false` refusal test above and does **not**
replace it — the issuer value alone does not prove dev mode is off. It fails on
any mismatch or HTTP error (export `IAM_DOMAIN` first):

```
python3 - "$IAM_DOMAIN" <<'PY'
import json, sys, urllib.request
host = sys.argv[1]
want = "https://%s" % host
url = want + "/.well-known/openid-configuration"
try:
    with urllib.request.urlopen(url, timeout=5) as r:
        if r.status != 200:
            sys.exit("FAIL: discovery returned HTTP %s" % r.status)
        issuer = json.load(r).get("issuer")
except Exception as e:
    sys.exit("FAIL: discovery request failed: %s" % e)
if issuer != want:
    sys.exit("FAIL: advertised issuer %r != expected %r" % (issuer, want))
print("OK: issuer == %s" % issuer)
PY
```

Then run the live round trips and suites against the staging issuer (see
`.env.staging.example` harness section and steps 3–5 above):
`python scripts/smoke_test.py https://<IAM_DOMAIN>` and the Google/Entra
federation harness pointed at the same issuer.

### Backup, restore, and recovery-time measurement

Database access is private to the compose network; reach it through the
container. Write every dump **outside the cloned repository** — dumps contain
data and at-rest-encrypted secrets and must never be committed (`*.dump` is
git-ignored as a backstop). Use a directory such as `~/iam-backups` on the VM.

```
mkdir -p ~/iam-backups
STAMP=$(date +%Y%m%d%H%M%S); DUMP=~/iam-backups/iam-staging-$STAMP.dump

# Timed backup — this is the RETAINED artifact:
time docker compose -f docker-compose.staging.yml exec -T postgres \
  pg_dump -U iam -Fc iam > "$DUMP"

# The file existing is NOT proof of validity; only check it is present and a
# plausible non-zero size here (the restore test below is what proves it):
test -s "$DUMP" && echo "backup present: $(wc -c < "$DUMP") bytes" \
  || echo "FAIL: backup missing or empty"
```

Validate by restoring into a SEPARATE, TEMPORARY database — never over the live
one. `restore_check` is a throwaway restore-test artifact, not a backup to keep:

```
docker compose -f docker-compose.staging.yml exec -T postgres \
  psql -U iam -d postgres -c "create database restore_check;"
time docker compose -f docker-compose.staging.yml exec -T postgres \
  pg_restore -U iam -d restore_check --no-owner < "$DUMP"
docker compose -f docker-compose.staging.yml exec -T postgres \
  psql -U iam -d restore_check -c "select count(*) from schema_migrations;"
# Drop the throwaway once the restore is validated:
docker compose -f docker-compose.staging.yml exec -T postgres \
  psql -U iam -d postgres -c "drop database restore_check;"
```

Record the two `time` figures; their sum is the measured recovery bound for an
incident. Retain only the validated `$DUMP`; the `restore_check` database is
temporary.

**Preserve the backup off the VM before any teardown.** Copy the retained dump
to storage outside the VM and confirm it is readable at the destination before
destroying the VM or its volumes:

```
# From your workstation (not the VM):
scp <vm-user>@<vm-host>:~/iam-backups/iam-staging-<stamp>.dump ./secure-store/
test -s ./secure-store/iam-staging-<stamp>.dump \
  && echo "offsite copy present: $(wc -c < ./secure-store/iam-staging-<stamp>.dump) bytes" \
  || echo "FAIL: offsite copy missing or empty"
```

Treat the dump as sensitive (data + sealed secrets): store it encrypted and
never print its contents. For the migration + upgrade rehearsal (fresh install,
backup/restore, pre-0007 upgrade) reuse the existing script rather than
re-deriving it: `scripts/migration_rehearsal.sh` — retain its `ALL_PASS` log.

### Administrative access (staging decision)

The engine exposes a single `/v1` API surface: the login API (called by operator
backends) and the management API share that prefix and are separated by **key
scope** — `requireAdminScope` — not by URL path
(`internal/api/api.go:55-156`), and admin routes interleave with login routes. A
network-level edge allowlist therefore cannot single out admin calls without
either blocking ordinary login traffic (allowlisting all of `/v1`) or relying on
a fragile, drift-prone list of admin paths, so **no IP allowlist is added** here:
either option risks locking us out or giving false security. Management access is
enforced by admin-scoped bearer keys plus management rate limiting
(`limitManagement` / the `mgmt-key` limiter), and `/docs` is refused at the edge
and disabled in the engine. If network-level restriction is required for staging,
treat it as a deliberate architecture decision — for example run admin calls from
the VM itself over SSH/localhost, or front the management plane with a separate
restricted entrypoint bound to a known static operator IP — rather than guessing
an allowlist.

### Teardown (what exactly gets removed)

Make sure the backup has been preserved off the VM first (previous section);
`down -v` deletes the `pgdata` volume, so an un-exported dump is lost.

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

## Option B — dedicated Cloudflare Tunnel (alternative to host-port Caddy)

Use this variant to host staging next to an existing deployment that already
fronts traffic with its own tunnel, without opening host ports 80/443. It is a
separate override; the base bundle (Option A, Caddy on 80/443) is unchanged and
still usable on its own.

### Where TLS terminates and how a request reaches IAM

```
visitor ──HTTPS──▶ Cloudflare edge (TLS terminates here) ──tunnel──▶
  cloudflared (in the iam-staging network, OUTBOUND 443 only) ──http──▶ iam:8080
```

The engine is never bound to a host port; Postgres stays private. `cloudflared`
opens only outbound connections, so no inbound firewall change and no host
80/443 are needed (this is why it coexists with an existing tunnel-fronted app).

Start it with both files (Caddy and host ports are not started):

```
docker compose -f docker-compose.staging.yml -f docker-compose.staging.tunnel.yml \
  --env-file .env.staging up -d --build
```

### Keep the public URL consistent

Set `IAM_DOMAIN` in `.env.staging` to the **Cloudflare public hostname** (e.g.
`iam-staging.example.com`). Everything derives from it and must match exactly:
`IAM_ISSUER=https://<IAM_DOMAIN>`, the OIDC discovery `issuer`, the redirect URI
`https://<IAM_DOMAIN>/idp/callback`, and `IAM_WEBAUTHN_ORIGINS=https://<IAM_DOMAIN>`.
Dev mode stays off; the engine accepts the https issuer string even though TLS is
terminated upstream at Cloudflare.

### Trusted-proxy handling (review)

The engine derives the client IP as the entry `IAM_TRUSTED_PROXY_HOPS` from the
**right** of `X-Forwarded-For`; entries to the left (client-supplied) are ignored
and `X-Real-IP` is never trusted (`cmd/iamd/main.go:194-214`). With cloudflared as
the single proxy in front, the expected value is `IAM_TRUSTED_PROXY_HOPS=1` (as
set in the base compose). Because the engine is reachable **only** through the
tunnel (never a public port), a client cannot inject `X-Forwarded-For` directly.

- **No code change is required.** The only tunable is the hop count.
- **Verify the hop count empirically** after bring-up: make a request from a
  known client IP and confirm it is attributed to that IP (e.g. in a rate-limit
  or audit observation). If the observed address is a Cloudflare address instead
  of the real client, set `IAM_TRUSTED_PROXY_HOPS=2` and recheck.
- **Confirm `X-Forwarded-Proto: https` reaches the engine** (Cloudflare sets it
  by default). The engine treats a request as secure when `r.TLS != nil` **or**
  `X-Forwarded-Proto == "https"` (`cmd/iamd/main.go:345`); this header is what
  makes that true behind the tunnel.

### Manual Cloudflare configuration (operator)

1. Create a **new, dedicated** tunnel in the Cloudflare Zero Trust dashboard
   (do **not** reuse the existing `vps-ai-pbx` tunnel). Copy its **token**.
2. Add a **public hostname** on that tunnel, e.g. `iam-staging.example.com`,
   routed to service **`http://iam:8080`** (cloudflared resolves `iam` on the
   staging network). Cloudflare manages the hostname's DNS automatically — no
   manual DNS record, no firewall/port change.
3. Supply the token at deploy time only:
   `export CLOUDFLARE_TUNNEL_TOKEN=…` (or a gitignored secret file passed with a
   second `--env-file`). Never commit or print it; never reuse another tunnel's
   token. **Do not run a bare `docker compose … config`** while the token is set
   — it prints the resolved token in its output; validate with `config -q`
   (quiet) or with the token unset. cloudflared itself does not log the token.

### Provider redirect URIs

Add `https://<IAM_DOMAIN>/idp/callback` (the Cloudflare hostname) as a redirect
URI on the **Google** OAuth client and the **Entra** app registration (Web
platform), alongside the existing ones.

### Health checks (tunnel mode)

Run the issuer/dev-mode checks from the base runbook, plus — over the public
Cloudflare URL rather than a host port:

```
curl -fsS https://<IAM_DOMAIN>/healthz && echo "  healthz OK (via tunnel)"
# live issuer check (same python snippet as above) against https://<IAM_DOMAIN>
docker compose -f docker-compose.staging.yml -f docker-compose.staging.tunnel.yml ps
```

### Rollback and teardown (tunnel scope only)

- **Rollback:** `docker compose -f docker-compose.staging.yml -f docker-compose.staging.tunnel.yml stop cloudflared`
  stops ingress immediately; disable or delete the public hostname in the
  Cloudflare dashboard to stop serving.
- **Teardown:** preserve the backup off the VM first. Then **verify exactly what
  will be removed belongs to `iam-staging`** before deleting anything — if any
  line below shows a `vps-ai-pbx`, `zitadel-stack`, or otherwise unexpected
  object, **stop and investigate** rather than proceeding:

  ```
  # Containers, volumes, and networks scoped to this project only:
  docker compose -f docker-compose.staging.yml -f docker-compose.staging.tunnel.yml ps -a
  docker volume ls  --filter label=com.docker.compose.project=iam-staging
  docker network ls --filter label=com.docker.compose.project=iam-staging
  ```

  Only once every listed object is `iam-staging`:

  ```
  docker compose -f docker-compose.staging.yml -f docker-compose.staging.tunnel.yml --env-file .env.staging down -v
  ```

  This removes only the `iam-staging` containers (incl. this cloudflared), its
  network, and its volumes. Then **delete the new tunnel** in the Cloudflare
  dashboard. The existing `vps-ai-pbx` tunnel and both existing stacks are never
  touched.

## Quick Tunnel (temporary HTTPS, no domain / no token / no DNS)

For a short ad-hoc HTTPS test with no owned domain, no Cloudflare account token,
and no DNS setup, use the **Quick Tunnel** variant
(`docker-compose.staging.quicktunnel.yml`). Cloudflare assigns a **random
`https://<random>.trycloudflare.com` hostname that changes on every (re)start**.

> **Temporary, non-production only.** This hostname is ephemeral and
> unauthenticated at the edge. Use it only for a single short test with
> **synthetic test data** — never real user data or production secrets. A new
> hostname (any tunnel restart) invalidates the `IAM_ISSUER` and every OAuth
> redirect URI you registered, so logins will fail until you re-register. Do not
> use for anything that must persist or for production.
>
> **Public-exposure warning.** A Quick Tunnel publishes the engine on a public
> HTTPS URL that anyone with the link can reach. Keep the session short, keep
> `IAM_BOOTSTRAP_ADMIN_KEY` strong and staging-only, tear it down promptly, and
> never point it at anything but a disposable staging stack.

Pick **exactly one** tunnel variant — use this file **or**
`docker-compose.staging.tunnel.yml`, never both at once (both define
`cloudflared` and profile Caddy out).

### Phase A — start only the tunnel, learn the hostname

```
# Starts ONLY cloudflared (no token needed). The engine is not up yet; that is
# fine — the tunnel URL comes up independently and requests 502 until phase B.
docker compose -f docker-compose.staging.yml -f docker-compose.staging.quicktunnel.yml \
  --env-file .env.staging up -d cloudflared

# Read the generated hostname from the container log (no secrets are printed):
docker compose -f docker-compose.staging.yml -f docker-compose.staging.quicktunnel.yml \
  logs cloudflared | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1
```

### Phase B — set IAM_DOMAIN to that hostname, then start IAM + Postgres

Set these in `.env.staging` to the **exact** hostname from Phase A (host only,
no scheme, for the two WebAuthn values):

```
IAM_DOMAIN=<random>.trycloudflare.com
IAM_WEBAUTHN_RP_ID=<random>.trycloudflare.com
IAM_WEBAUTHN_ORIGINS=https://<random>.trycloudflare.com
```

```
docker compose -f docker-compose.staging.yml -f docker-compose.staging.quicktunnel.yml \
  --env-file .env.staging up -d iam postgres
```

`IAM_ISSUER` is then `https://<random>.trycloudflare.com` (base compose line 47),
the OIDC discovery `issuer`, the federation callback `{issuer}/idp/callback`
(`internal/authn/federation.go:44`), and the WebAuthn origin all resolve to that
same hostname. Verify consistency with the live-issuer check from the base
runbook against `https://<IAM_DOMAIN>` — it must report exactly
`"issuer":"https://<random>.trycloudflare.com"`.

### Provider redirect URIs (manual, after Phase A)

Once the hostname is known, add
`https://<random>.trycloudflare.com/idp/callback` as a redirect URI on the
**Google** OAuth client and the **Entra** app registration (Web platform). If the
tunnel restarts and the hostname changes, these must be **re-registered** or the
federated logins fail.

### Pre-teardown verification and teardown (iam-staging only)

Preserve any backup off the VM first. Then confirm every object to be removed
belongs to `iam-staging`; if any `vps-ai-pbx`, `zitadel-stack`, or unexpected
object appears, **stop and investigate**:

```
docker compose -f docker-compose.staging.yml -f docker-compose.staging.quicktunnel.yml ps -a
docker volume ls  --filter label=com.docker.compose.project=iam-staging
docker network ls --filter label=com.docker.compose.project=iam-staging
```

Only once every listed object is `iam-staging`:

```
docker compose -f docker-compose.staging.yml -f docker-compose.staging.quicktunnel.yml \
  --env-file .env.staging down -v
```

The Quick Tunnel has no account/DNS state, so it simply disappears when
cloudflared stops — nothing to delete in Cloudflare. No `docker prune`, no broad
wildcards, and no other Compose project is touched.

## Go / no-go

Staging is complete for pre-production only when steps 1–4 pass with retained
evidence and the Entra cross-tenant rejection is proven live. WS6 may remain
deferred with that fact recorded. Production stays **NO-GO** until the overall
completion criteria in [ROADMAP.md](ROADMAP.md) are met; a staging pass is
pre-production evidence, never production authorization.
