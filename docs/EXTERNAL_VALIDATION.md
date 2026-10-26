# External-validation checklist

The production gates in [ROADMAP.md](ROADMAP.md) that source review and local
tests cannot close. Each item needs a non-production external resource or a
human action. Nothing here authorizes production; it is the evidence set a GO
decision requires. Detailed procedures live in [STAGING.md](STAGING.md),
[DEPLOYMENT.md](DEPLOYMENT.md), and [PENTEST.md](PENTEST.md); this is the
executable top-level checklist. Record evidence (logs, run ids, timings) for
every checked box and keep it with the release record.

Use throwaway/test tenants and identities only. Never use customer identities,
production keys, or production data. Do not paste secrets into chat — inject
them as documented in "Secret injection" below.

## 1. Entra application registration and test identities (WS7)

- [x] A dedicated **test Entra directory** (not production), its **Directory
      (tenant) ID** (GUID) recorded.
- [x] An **app registration** in that directory: supported account type
      "Accounts in this organizational directory only"; platform **Web**;
      redirect URI `https://<staging-host>/idp/callback`.
- [x] A **client secret** created for that app — the secret **Value** (not the
      Secret ID); captured into the secret store, never into chat or the repo.
- [x] A **test user** in that directory.
- [ ] A separate **out-of-directory identity** was **not** used; the cross-tenant
      gate (§ 2) was instead exercised by pinning an IdP to a *different*
      directory GUID and attempting login with the in-directory account.

## 2. Entra login + explicit cross-tenant rejection (WS7 → run under WS9 HTTPS staging)

- [x] Configure the IdP via the engine API: `provider_type=entra`,
      `tenant=<directory GUID>`, `client_id`, `client_secret`. Response
      `callback_url` equalled `{issuer}/idp/callback`; no secret was returned.
- [x] Mint the authorization URL and verify host
      `login.microsoftonline.com/<guid>/...`, byte-exact
      `redirect_uri=https://<staging-host>/idp/callback`, `state`, `nonce`,
      PKCE `code_challenge`+`S256`, `scope=openid profile email`.
- [x] Complete a **human browser login** as the directory test user; the redeemed
      session was `authenticated`, `amr=["fed"]`, `idp_checked`, `mfa_required=false`,
      the identity keyed on `(idp_id, subject)` (not email); redeem HTTP 201.
- [x] **Cross-tenant rejection (mandatory gate):** an IdP pinned to a *different*
      directory refused the login; `probe_check` confirmed no usable code reached
      the engine and **no session was issued**. The refusal occurred at Microsoft's
      authorize endpoint (single-tenant app), so the engine's strict `iss` equality
      backstop was **not reached live**; it remains covered by offline unit tests.
- [x] Live negatives pass: forged `state`→400, burned-intent redeem→401,
      uncompleted-intent redeem→401. (Isolated wrong `browser_binding` is covered by
      the offline self-IdP feature test, not as a separate live-provider test.)

> **Status — local non-prod (2026-10-26):** sections 1–2 first passed against a
> *local* engine (`http://localhost:8080`, `IAM_DEV_MODE=true`) — see ROADMAP.md WS7.
>
> **Status — HTTPS staging (2026-10-26):** the boxes above were then completed
> against the **public HTTPS staging** engine (issuer `https://<staging-host>` served
> via a Cloudflare Quick Tunnel, `IAM_DEV_MODE` off, dedicated Postgres). Both Google
> and Entra completed a real human browser login with redeem **HTTP 201**, correct
> issuer/callback/`state`/`nonce`/PKCE-`S256`, session `amr=["fed"]`+`idp_checked`
> with no unproven MFA, identity keyed on `(idp_id, subject)`, and the live negatives
> above. The cross-tenant probe yielded no usable session (caveat above). Each run
> used a short-lived instance-admin key (the permanent bootstrap key only minted and
> revoked it), created a throwaway org, and deleted it afterward
> (`orgs_remaining=0`); with dev mode off the engine required an **https**
> `return_url`, captured by a loopback HTTPS catcher. No secrets committed. Two Entra
> input errors were caught and produced **no session** (fail-closed): a Secret **ID**
> supplied in place of the secret **Value** (`AADSTS7000215`), and a `client_id`/tenant
> mismatch (`AADSTS700016`); the recorded pass is the corrected run only. Remaining
> WS9 items (§§ 3–5) — staging-config sign-off, migration/backup-restore and recovery
> time, external pentest — are still open.

## 3. Isolated HTTPS staging configuration and secret injection (WS9)

- [ ] Isolated host/cluster at a dedicated DNS name with **TLS 1.2+** terminated
      by a proxy in front of the engine; no production data/keys/traffic.
- [ ] Dedicated **Postgres 17** for staging only.
- [ ] `IAM_ISSUER=https://<staging-host>`; **`IAM_DEV_MODE` unset/false** (the
      engine must then accept only an https issuer — confirm it refuses http).
- [ ] `IAM_WEBAUTHN_RP_ID` / `IAM_WEBAUTHN_ORIGINS` set to the login UI's real
      domain/origin (invalid values fail fast at boot).
- [ ] Proxy trust: set `IAM_TRUST_PROXY=true` and `IAM_TRUSTED_PROXY_HOPS` to the
      exact trusted-hop count if the proxy sets client IP.
- [ ] **Secret injection:** `IAM_MASTER_KEY` (32-byte base64),
      `IAM_BOOTSTRAP_ADMIN_KEY` (≥32 chars), DB credentials, and per-org IdP
      client secrets supplied from the platform secret store as environment
      variables — freshly generated for staging, never reused, never committed,
      never baked into images.
- [ ] Rotate the bootstrap admin key to a managed instance-admin key after boot.

## 4. Migrations, backup/restore, recovery time, rollback (WS9 / WS4)

- [x] Run [`scripts/migration_rehearsal.sh`](../scripts/migration_rehearsal.sh)
      against the staging engine image; retain its `ALL_PASS` log (fresh install,
      backup/restore to an isolated target, pre-0007 upgrade path).
- [ ] Confirm on the live staging DB: `schema_migrations` lists every migration;
      health check passes; a real login flow succeeds; audit events are written.
      *(Partly done: live `schema_migrations=7` and `/healthz` pass confirmed, and
      real Google/Entra logins succeeded under HTTPS staging — §§ 1–2 / ROADMAP
      WS5/WS7; writing of audit events was not separately verified in this run.)*
- [x] **Real backup tooling** (not just the rehearsal script): take a backup with
      the environment's actual tooling, restore it onto an **isolated target
      first**, validate schema + data there before any reuse.
- [x] **Measure and record recovery time** (backup → validated restore) so an
      incident has a known bound.
- [ ] **Rollback criteria rehearsed** (STAGING.md § *Rollback and recovery
      criteria*): abort conditions defined; understand that a binary rollback
      does **not** undo committed schema (0006/0007); schema + binary recovery
      decided together.

> **Status — staging recovery rehearsal (2026-10-26):** executed against the running
> HTTPS staging stack.
> - **Audited rehearsal** (`scripts/migration_rehearsal.sh`, **unchanged**, run with
>   the `iam-staging-iam:latest` engine image): **ALL_PASS** — fresh install applies
>   all 7 migrations in order; a `pg_dump` backup restores onto a *separate* isolated
>   target with identical `schema_migrations` and seeded data and zero further
>   migrations; the pre-0007 database upgrades by applying exactly 0007 with the legacy
>   generic-OIDC provider defaulting to `provider_type='oidc'` and an empty tenant. It
>   created only disposable `iam-rehearsal-*` resources and removed them on exit (0 left
>   behind); the live staging stack and its volume were untouched.
> - **Real backup/restore of the live staging DB:** a `pg_dump` of the live staging
>   database (read-only on the source) restored onto a fresh, isolated disposable
>   Postgres target and validated there — `schema_migrations=7` and 24 public tables
>   (including `orgs`, `users`, `identity_providers`, `sessions`, `idp_intents`).
> - **Recovery time: 4.90 s.** T0 = start of `pg_dump` of the live staging DB; T1 =
>   isolated target restored and validated (`schema_migrations==7`); the span includes
>   provisioning the throwaway target, the restore, and validation. Backup size ≈ 40 KB.
>   **Representativeness caveat:** the staging DB was nearly empty (no organizations
>   remained after the federation tests were cleaned up), so this figure is **not** a
>   reliable predictor of production recovery under realistic load or larger datasets.
> - **Limited staging smoke test:** `/healthz` 200, discovery `issuer` matches, JWKS has
>   1 key, authorize and token endpoints present.
> - **Method notes (honest disclosure):** the first manual recovery-time attempt hit a
>   target-readiness race whose error was masked by a `|| true` in the measurement
>   wrapper; the recorded measurement re-ran with an explicit readiness check and
>   `ON_ERROR_STOP=1` restore error handling. The audited `migration_rehearsal.sh` was
>   **not modified**; running it on the VPS needed an engine-image override
>   (`IAM_REHEARSAL_IMAGE=iam-staging-iam:latest`) and a temporary `python`→`python3`
>   PATH shim, because the script's default image name and `python` command are not
>   present there. All disposable resources were removed afterward (verified).
>
> **Still open (unchecked above):** live-DB audit-event write verification, and the
> **rollback-criteria rehearsal**; see also § 3 (staging-config sign-off) and § 5
> (external pentest). Production remains **NO-GO**.

## 5. External penetration test and evidence retention

- [ ] Commission an external pentest using [PENTEST.md](PENTEST.md) as the scope
      brief; test against staging, not production.
- [ ] Triage findings; remediate Critical/High/Medium; record dispositions in
      SECURITY.md's residual-risk register.
- [ ] Retain the pentest report and remediation evidence with the release record.

## Supported-scope decision (resolved 2026-10-26)

- [x] Production scope states the supported federated providers: Google
      (`google`), organizational Microsoft Entra (`entra`), and generic `oidc`.
- [x] **Personal Microsoft accounts (MSA, `microsoft`) are excluded from the
      initial release.** WS6 is out of initial scope — deferred, not passed; the
      preset stays in the code but is unvalidated and unsupported for production.
      GO does not require WS6. (If a future release adds MSA, a live round trip
      — same shape as Entra, issuer pinned to the consumers tenant — is required
      first.)

When every applicable box is checked with retained evidence and all SECURITY.md
residual risks remain accepted, the go/no-go in ROADMAP.md can be revisited.
Until then production is **NO-GO**.
