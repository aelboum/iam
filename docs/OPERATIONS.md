# Operating IAM

Operational guide for running the IAM engine. It complements
[DEPLOYMENT.md](DEPLOYMENT.md) (which covers the production stack, upgrades, and
migration recovery) and [SECURITY.md](SECURITY.md) (threat model and residual
risks). Values below are the engine's **actual defaults** from
`internal/config/config.go`; anything host-specific (backup tooling, metrics
backend, secret store) is explicitly marked **runbook** and must be supplied by
the deploying environment.

## Configuration (environment variables)

Required:

- `IAM_ISSUER` — absolute external URL of the engine (used for `callback_url`,
  passkey RP origin defaults, and the OIDC issuer). Must be reachable by the
  engine itself for any provider whose discovery points back at it.
- `IAM_DATABASE_URL` — Postgres DSN.
- `IAM_MASTER_KEY` — 32 bytes, base64 (`openssl rand -base64 32`). Encrypts
  secrets at rest.
- `IAM_BOOTSTRAP_ADMIN_KEY` — ≥32 characters; the initial instance-admin key
  (created once; not recreated if deleted).

Optional (default in parentheses, from `config.go`):

- `IAM_LISTEN_ADDR` (`:8080`), `IAM_ENABLE_DOCS` (`false`), `IAM_DEV_MODE`
  (`false` — never enable in production; it permits http/private issuers).
- `IAM_MASTER_KEY_PREVIOUS` — comma-separated old keys accepted for decryption
  during rotation; remove after `rotate-keys` completes.
- `IAM_TRUST_PROXY` (`false`) + `IAM_TRUSTED_PROXY_HOPS` (`1`, range 1–10) — see
  TLS / trusted proxy below.
- `IAM_SHARED_RATE_LIMITS` (`false`) — count rate limits in Postgres across
  instances (sliding one-minute window); each instance still applies the local
  limit first and uses a separate pool of 4 DB connections for counts.
- TTLs: `IAM_ACCESS_TOKEN_TTL` (`5m`), `IAM_REFRESH_IDLE_TTL` (`168h`),
  `IAM_SESSION_MAX_AGE` (`720h`), `IAM_LOGIN_TTL` (`15m`), `IAM_KEY_ROTATION`
  (`720h`), `IAM_LOCKOUT_DURATION` (`15m`), `IAM_AUDIT_RETENTION` (`8760h`).
- Password-hashing capacity (see "Capacity and overload" below):
  `IAM_HASH_SLOTS` (`0` = auto-size from GOMAXPROCS), `IAM_STRICT_SIZING`
  (`false`), `IAM_HASH_WAIT_TIMEOUT` (`3s`), `IAM_ORG_LOGIN_LIMIT` (`1200`
  password logins per org per minute).
- Passkeys: `IAM_WEBAUTHN_RP_ID` (defaults to the issuer host),
  `IAM_WEBAUTHN_ORIGINS` (defaults to the issuer origin) — set both to the login
  UI's real domain and origin(s); invalid values fail fast at boot.

Lockout threshold is 5 failed attempts (`MaxFailedLogins`, per factor).

## Secret management (runbook)

- Provide `IAM_MASTER_KEY`, `IAM_BOOTSTRAP_ADMIN_KEY`, DB credentials, and per-org
  IdP client secrets through the platform secret store (e.g. Kubernetes Secrets,
  cloud secret manager) injected as environment variables — **never** committed,
  never baked into images. CI and this repo contain no production secrets.
- Rotate `IAM_BOOTSTRAP_ADMIN_KEY` by issuing a new instance-admin key and
  retiring the bootstrap one.
- IdP client secrets are encrypted at rest with the master key and are never
  returned by any read or written to logs.

## TLS and trusted proxy

- Terminate TLS in front of the engine (the engine speaks plain HTTP on
  `IAM_LISTEN_ADDR`). Require TLS 1.2+ at the proxy (runbook).
- `X-End-User-IP` is trusted from login-API key holders; only issue keys to your
  own backends. If a proxy sets client IP, set `IAM_TRUST_PROXY=true` and
  `IAM_TRUSTED_PROXY_HOPS` to the exact number of trusted hops.

## Database and connection pooling

- Postgres 17. The engine opens a default pgx pool; when `IAM_SHARED_RATE_LIMITS`
  is on it adds a dedicated 4-connection pool for rate-limit counts. Size the
  Postgres `max_connections` for (instances × pool size) plus headroom (runbook;
  benchmark against expected login QPS).
- Per-tenant quotas (enforced in code): 100k users, 100 projects, 50 API keys per
  org; 50 apps and 200 roles per project. List endpoints paginate (`?limit=` max
  1000, `?offset=`).
- Schema migrations run automatically at startup under a Postgres advisory lock,
  so several instances starting at once (a rolling deploy) migrate safely: one
  applies pending migrations while the others wait, then find nothing to do.

## Capacity and overload (password hashing)

Password verification and password setting run argon2id, which is deliberately
expensive: at the engine's parameters each in-flight hash holds about **64 MiB**
resident and uses a full CPU core for tens of milliseconds. The engine bounds how
many run at once with a process-wide pool of *hash slots*; requests that cannot
get a slot within `IAM_HASH_WAIT_TIMEOUT` are shed with HTTP 503 (distinct from a
429 rate-limit) rather than queued without bound.

- **Slot count.** `IAM_HASH_SLOTS` sets the pool size. `0` (the default)
  auto-sizes to `GOMAXPROCS`, floored at 2. `GOMAXPROCS` honours a cgroup CPU
  quota on Go 1.25+, so inside a CPU-limited container the pool already scales to
  the quota, not to the host's physical cores. Set an explicit value only to
  override that.
- **Memory estimate.** Peak hashing memory ≈ `slots × 64 MiB`, plus ~128 MiB
  base for the runtime, DB pool and buffers. Example: 8 slots ≈ 512 MiB hashing +
  128 MiB ≈ **640 MiB**. Give the container a memory limit above that, or lower
  `IAM_HASH_SLOTS`.
- **Memory check.** At startup the engine reads the cgroup memory limit (v2
  `memory.max`, then v1 `memory.limit_in_bytes`). If that limit is **known and
  finite** and cannot hold the estimate, it logs a warning. With
  `IAM_STRICT_SIZING=true` the mismatch is fatal (fail fast rather than risk OOM
  under load). **Limitation:** the check is skipped silently when no cgroup memory
  limit is readable — non-Linux hosts, no cgroup memory controller, or an
  unlimited (`max`) setting. It never invents a limit, so it cannot protect a
  host with no enforced memory limit; set `IAM_HASH_SLOTS` by hand there.
- **Per-org budget.** `IAM_ORG_LOGIN_LIMIT` (default 1200/min) caps password
  logins per organization across all of that org's keys, accounts and IPs, so one
  tenant cannot monopolize the shared hashing pool.
- **Tuning.** Start with the auto default. If you see sustained 503s on login
  endpoints under legitimate load, raise `IAM_HASH_SLOTS` *and* the memory limit
  together, or scale out horizontally. Watch the `shed_total` fields in the
  "overloaded" / "per-org login budget" warning logs (see monitoring below).

## Health and readiness

- Liveness/readiness: `iamd healthcheck` (container `HEALTHCHECK`/probe) returns
  non-zero on failure. At the HTTP layer, a listening engine answers requests;
  `/` returns 404 by design (no root route) — probe a real endpoint or use the
  `healthcheck` subcommand.
- Startup fails fast (non-zero exit, logged `fatal`) on: missing/short
  `IAM_MASTER_KEY` or `IAM_BOOTSTRAP_ADMIN_KEY`, missing `IAM_ISSUER`/
  `IAM_DATABASE_URL`, invalid durations, or invalid WebAuthn origins. Migrations
  run automatically at startup (see DEPLOYMENT.md).

## Logging, metrics, and monitoring

- Logs are structured JSON (slog). Secrets are never logged; audit-relevant
  actions are also persisted as audit events (logins, lockouts, IdP create/trust
  changes, admin actions).
- Monitor at minimum (wire to your metrics/alerting backend — runbook):
  - authentication failure rate and lockouts (spikes → credential stuffing);
  - federated-login failures and discovery/SSRF-guard rejections;
  - rate-limiter fallback events (`shared rate limiter unavailable` log → DB
    pressure);
  - migration/startup `fatal` logs;
  - 5xx rate and DB connection errors.
- **Audit log:** retained `IAM_AUDIT_RETENTION` (default 365d) and purged by the
  engine; restrict read access to instance admins (org keys cannot read the
  instance-wide audit log).

## Backup and restore (runbook + DEPLOYMENT.md)

- Take regular Postgres backups (tooling/location/retention are environment-
  specific — define them in the deployment runbook). The master key is **not** in
  the database; back it up separately and securely, or encrypted data is
  unrecoverable.
- Restore procedure and the "restore to an isolated target first" rule are in
  DEPLOYMENT.md § *Recovering from a failed migration*. Never restore an older
  snapshot over a live/newer database without an approved recovery decision.

## Key rotation

Follow DEPLOYMENT.md: set the new `IAM_MASTER_KEY` and old `IAM_MASTER_KEY_PREVIOUS`,
restart, run `rotate-keys`, then `rotate-keys --check` (read-only; must report
nothing still needs the old key), then remove the previous key after the access-
token TTL. Everything issued before rotation keeps working until it expires.

## Incident response — credential compromise (runbook actions marked)

- **Leaked master key:** rotate immediately (key-rotation procedure); treat all
  previously sealed secrets as exposed — rotate IdP client secrets too.
- **Leaked login/instance-admin API key:** revoke the key (deleting a key also
  revokes keys it created); because a login key can trigger password resets for
  its users (residual risk D3 in SECURITY.md), review audit events for that key.
- **Suspected account takeover:** lock the user (`POST /v1/users/{id}/lock`),
  which invalidates their pending reset tokens; review audit trail.
- **Compromised IdP:** delete the IdP (`DELETE …/idps/{id}`) to stop logins; its
  sessions remain until expiry — revoke as needed.
- Preserve logs and audit events; follow the platform incident process (runbook).

## Dependency and vulnerability response

- CI runs `govulncheck` (reachable analysis) and `gitleaks` on every push/PR.
- On a new advisory: determine reachability with `govulncheck`; patch the module
  if a fix exists; if unreachable with no fix, record the disposition in
  SECURITY.md's residual-risk register (as done for GO-2026-5932).

## Startup / shutdown

- Startup: validate config → connect DB → migrate → listen. A failure at any step
  exits non-zero with a logged `fatal`; orchestrators should not route traffic
  until the health check passes.
- Shutdown: send SIGTERM; allow in-flight requests to drain (orchestrator grace
  period — runbook).

## Operator deploy checklist (new instance)

1. Provision Postgres 17; create the database and a least-privilege role.
2. Generate and store `IAM_MASTER_KEY` (32-byte base64) and a strong
   `IAM_BOOTSTRAP_ADMIN_KEY` (≥32 chars) in the secret store.
3. Set `IAM_ISSUER` to the external https URL; configure TLS termination.
4. Set `IAM_WEBAUTHN_RP_ID`/`IAM_WEBAUTHN_ORIGINS` to the login UI's domain/origin
   and validate in staging (bad values fail at boot).
5. Leave `IAM_DEV_MODE` unset/false. Set proxy vars only if behind a trusted proxy.
6. Decide `IAM_SHARED_RATE_LIMITS` and size the DB pool / `max_connections`.
7. Deploy; confirm the health check passes and `schema_migrations` lists all
   migrations (see DEPLOYMENT.md before upgrading an existing instance — note the
   one-time invalidation of pending resets/intents by migration 0006).
8. Rotate the bootstrap admin key to a managed instance-admin key.
9. Wire logs, metrics, alerts, and audit-log retention/access controls.
10. Verify a real login flow end to end before announcing the instance.
