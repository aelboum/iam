# IAM production-readiness roadmap

Status labels: `NOT STARTED` · `IN PROGRESS` · `PASS` · `PASS WITH FINDINGS` · `BLOCKED` · `FAIL`.

This roadmap separates **code readiness** (what source review and automated tests
establish), **staging readiness** (what a controlled non-production environment
establishes), and **production deployment authorization** (a separate human
decision). A `PASS` here never by itself authorizes production traffic.

Last updated against commit history ending at the `ci:` workflow commit.

| WS | Workstream | Status | Evidence | Remaining blocker | Next action | Affects prod-readiness |
|----|-----------|--------|----------|-------------------|-------------|------------------------|
| 1 | Baseline & remote sync | **PASS** | `main` fast-forwarded to the docs commit and pushed; local == `origin/main`. | none | — | no (hygiene) |
| 2 | CI & security gates | **IN PROGRESS** | `.github/workflows/ci.yml` (jobs: test, e2e, security). Hosted run **green** on `79b2d61` (run 40218923137, 1m26s) and the three preceding commits; `govulncheck` 0 reachable vulns; `gitleaks` 0 leaks. | Branch protection (required status checks) needs a repo-admin decision. | Enable required-status-check branch protection when the user chooses PR-vs-direct-push. | yes |
| 3 | Independent security assurance | **PASS WITH FINDINGS** | Full trace of M1–M12 / L1–L11 / D1,D3 (see SECURITY.md); no Critical/High/Medium; no preset issuer/trust/tenant bypass. | none (findings are Low/Informational, dispositioned) | Keep the threat model current as code changes. | yes |
| 4 | Migration & recovery assurance | **PASS (code + staging)** | Repeatable rehearsal script `scripts/migration_rehearsal.sh` — **ALL_PASS 2026-10-25** on disposable isolated containers: fresh install applies all 7 migrations in order; `pg_dump` backup restores onto a *separate* target with identical `schema_migrations` and data, and a second engine run applies zero further migrations; pre-0007 database upgraded by the engine applies exactly 0007 and a pre-existing generic OIDC provider survives as `provider_type='oidc'` with empty tenant. Each migration transactional (atomic per file); recovery documented in DEPLOYMENT.md § *Rehearsing migrations and recovery*. **Staging (2026-10-26):** the audited script (unchanged) ran **ALL_PASS** against the `iam-staging-iam:latest` image on the staging host; additionally a `pg_dump` of the **live staging DB** (read-only source) restored onto an isolated disposable target and validated there (`schema_migrations=7`, 24 public tables); measured **recovery time 4.90s** (T0 `pg_dump` start → T1 validated restore; includes throwaway-target provisioning; backup ≈40 KB) on the nearly-empty live DB; and, at a **larger synthetic volume** (71 MB: 1,000 orgs / 10,000 users / 500,000 audit rows), **total recovery 8.73s** (backup 1.11s, provision 2.72s, restore 2.87s, readiness 1.54s) with all row counts matching and `schema_migrations=7`. Both are bounded synthetic baselines, **not** a production SLA/RTO. Disposable resources removed afterward (verified); live staging untouched. | Platform-specific backup/restore commands/tooling still host-dependent (runbook); production-scale recovery timing not yet measured; rollback-criteria rehearsal still pending. | Rehearse rollback criteria; measure recovery at a representative data volume once a target is chosen. | yes |
| 5 | Live Google login | **PASS (local + HTTPS staging)** | Real Google OIDC round trip on 2026-10-25 against the local dev engine (issuer `http://localhost:8080`, `IAM_DEV_MODE=true`) with a dedicated non-production OAuth client. Verified: minted authorization URL (host `accounts.google.com`, byte-exact `redirect_uri=http://localhost:8080/idp/callback`, `state`, `nonce`, PKCE `code_challenge`+`S256`, `scope=openid profile email`); after human browser login the session was `authenticated`, `amr=["fed"]`, `idp_checked`; the identity was auto-provisioned and keyed on `(idp_id, subject)` — not email (confirmed in `user_identities`). Negative cases passed live: forged `state`→400, burned-intent redeem→401, uncompleted-intent wrong-binding→401. Smoke + feature suites green on a disposable isolated engine. All disposable infra and the test org/identity were removed afterward; no secrets committed. **HTTPS staging (2026-10-26):** the same round trip passed against the public HTTPS staging engine (issuer `https://<staging-host>` served via a Cloudflare Quick Tunnel, `IAM_DEV_MODE` off, dedicated Postgres): real human browser login, redeem **HTTP 201**, issuer `accounts.google.com`, byte-exact `redirect_uri=https://<staging-host>/idp/callback`, `state`/`nonce`/PKCE `S256`, `scope=openid profile email`, session `amr=["fed"]`+`idp_checked` with no unproven MFA, identity keyed on `(idp_id, subject)`; live negatives 400/401/401; throwaway org deleted (`orgs_remaining=0`); run on a short-lived instance-admin key (the permanent bootstrap key only minted/revoked it); no secrets committed. | none | — | yes (pre-production) |
| 6 | Live Microsoft personal (MSA) | **OUT OF INITIAL SCOPE** (2026-10-26) — *excluded by product-scope decision; deferred, not passed* | Issuer pinning to the consumers tenant verified offline only; **no passing live round trip has been recorded.** The live test had been deferred after an unresolved Microsoft account/tenant access error, and on 2026-10-26 the product-scope decision **excluded personal Microsoft accounts from the initial production scope.** The `microsoft` preset remains in the codebase but is unvalidated and unsupported for the initial release. | none for the initial release (excluded from scope). | Revisit only if a future release adds MSA to scope; a live round trip (harness identical to WS5/WS7) and a usable personal-account Azure app registration would then be required. | **no (excluded from initial scope)** |
| 7 | Live Microsoft Entra ID | **PASS (local + HTTPS staging)** | Real Entra ID OIDC round trip on 2026-10-26 against a disposable local engine (issuer `http://localhost:8080`, `IAM_DEV_MODE=true`) with a dedicated non-production app registration and test directory. Verified: the engine pins the issuer server-side to `https://login.microsoftonline.com/<tenant-guid>/v2.0` (built from live Entra discovery, not an admin-supplied value); the minted authorization URL was correct (host `login.microsoftonline.com`, authorize path under the configured tenant GUID, byte-exact `redirect_uri=http://localhost:8080/idp/callback`, `state`, `nonce`, PKCE `code_challenge`+`S256`, `scope=openid profile email`); `client_secret` was never returned. After a human browser login the session was `authenticated`, `amr=["fed"]`, `idp_checked`, `mfa_required=false`; the identity was auto-provisioned and keyed on `(idp_id, subject)` — not email. Live negatives passed: forged `state`→400, burned-intent redeem→401, uncompleted-intent wrong-binding→401. **Cross-tenant rejection (mandatory gate) proven live:** an IdP pinned to a different directory refused an out-of-directory identity at Microsoft's authorize endpoint (AADSTS "account does not exist in tenant / no access to the application"); no code reached the engine and no session was issued. (Refusal observed at the authorize/app layer for a single-tenant app; the engine's strict-`iss` equality backstop remains covered by offline unit tests.) Disposable engine/Postgres/image and all credential files were removed afterward; no secrets committed. **HTTPS staging (2026-10-26):** the round trip was repeated against the public HTTPS staging engine (issuer `https://<staging-host>` served via a Cloudflare Quick Tunnel, `IAM_DEV_MODE` off, dedicated Postgres): correct issuer pin `https://login.microsoftonline.com/<tenant-guid>/v2.0`, byte-exact `redirect_uri=https://<staging-host>/idp/callback`, `state`/`nonce`/PKCE `S256`, `scope=openid profile email`, `client_secret` never returned; after a human browser login the session was `authenticated`, `amr=["fed"]`, `idp_checked`, `mfa_required=false`, identity keyed on `(idp_id, subject)`; redeem **HTTP 201**; live negatives 400/401/401. **Cross-tenant probe:** an IdP pinned to a different directory was refused by Microsoft's authorize endpoint and `probe_check` confirmed no usable code reached the engine and no session was issued (refusal at the authorize/app layer; the engine's strict-`iss` equality backstop remains covered by offline unit tests). Each run used a short-lived instance-admin key (permanent bootstrap only minted/revoked it) and a throwaway org deleted afterward (`orgs_remaining=0`); dev mode off required an https `return_url`, captured by a loopback HTTPS catcher. Two provider-side input errors (Secret ID vs Value `AADSTS7000215`; `client_id`/tenant mismatch `AADSTS700016`) were caught and produced no session; the recorded pass is the corrected run only. No secrets committed. | none | — | yes (pre-production) |
| 8 | Operational readiness | **PASS WITH FINDINGS** | DEPLOYMENT.md (upgrade/recovery/key rotation) + OPERATIONS.md (config, secrets, TLS/proxy, pool sizing, health/readiness, monitoring signals, audit retention, incident response, dependency response, operator deploy checklist), grounded in `config.go` defaults. | Metrics backend, alert thresholds, and backup tooling are host-specific (marked runbook). | Fill host-specific values once the target platform is chosen. | yes |
| 9 | Staging rehearsal | **IN PROGRESS** | Isolated HTTPS staging stands up per `docs/STAGING.md` (dedicated Postgres 17, `IAM_DEV_MODE` off, issuer `https://<staging-host>` served via a Cloudflare Quick Tunnel, no published host ports). **Federation round trips complete (2026-10-26):** live HTTPS Google and Entra logins both passed (redeem HTTP 201, correct issuer/callback/`state`/`nonce`/PKCE-`S256`, `amr=["fed"]`+`idp_checked`, identity keyed on `(idp_id, subject)`, live negatives 400/401/401) and the Entra cross-tenant probe produced no usable session — see WS5/WS7. Every throwaway org was deleted (`orgs_remaining=0`) and ran on a short-lived instance-admin key; no secrets committed. **Recovery rehearsal complete (2026-10-26):** `scripts/migration_rehearsal.sh` (unchanged) ran **ALL_PASS** against the staging image; a backup of the **live staging DB** restored onto an isolated disposable target validated there (7 migrations, 24 public tables); measured **recovery time 4.90s** (nearly-empty DB — not a production estimate); a limited smoke test (`/healthz` 200, issuer match, JWKS 1 key) passed; all disposable resources removed (verified). **B1–B4 complete (2026-10-26):** staging-config sign-off **PASS** (with noted production follow-ups), rollback criteria documented + rehearsed on disposable resources, live audit-event persistence + tenant isolation verified, and recovery re-measured at a 71 MB synthetic volume (**total 8.73s**). See EXTERNAL_VALIDATION §§ 3–4. | External independent penetration test (Phase E) still outstanding; production hardening follow-ups noted (stable DNS vs ephemeral tunnel, managed secret store, DB TLS, bootstrap-admin rotation). | Prepare the external-pentest package and keep that gate open; apply the production hardening follow-ups at deploy time. | yes (pre-production) |

## Required external prerequisites (the only items blocking the remaining work)

To unblock WS5–7 (and therefore WS9), the following **non-production** registrations
are required. Create them against throwaway/test tenants only; never use customer
identities:

1. ~~**Google:** an OAuth 2.0 Web client in a test Google Cloud project — client id,
   client secret, and an authorized redirect URI set to the engine's
   `callback_url` (`{issuer}/idp/callback`).~~ **Done (local non-prod, 2026-10-25;
   HTTPS staging, 2026-10-26)** — see WS5.
2. **Microsoft personal:** an Azure app registration with the personal-Microsoft-account
   audience — application (client) id, a client secret, and the redirect URI; plus a
   disposable MSA test account. **Deferred (2026-10-25):** blocked by an unresolved
   Microsoft account/tenant access error during registration; resume when cleared.
3. ~~**Microsoft Entra:** a dedicated test directory (tenant) — its directory (tenant)
   GUID, an app registration in that directory (client id + secret + redirect URI),
   and a test user in the directory.~~ **Done (local non-prod + HTTPS staging,
   2026-10-26)** — see WS7, including the live cross-tenant probe.

Provide these as environment inputs to the live harness (never committed). WS5 (Google)
and WS7 (Entra) have now passed both locally and under HTTPS staging (2026-10-26); only
WS6 (personal Microsoft) remains out of initial scope. Production stays **NO-GO** per the
mandate's completion criteria until the remainder of the staging rehearsal (WS9 —
migration-recovery and backup-restore on staging with a recorded recovery time) and an
external penetration test are complete with retained evidence.

## Production go/no-go

**NO-GO.** The live-provider round trips required by the final supported scope
have now passed both in non-production and **under real HTTPS staging** (WS5 Google
and WS7 Entra, 2026-10-26), including the Entra cross-tenant probe (no usable IAM
session; authorize-layer refusal, with the engine's strict-`iss` backstop covered by
offline unit tests). Remaining gates before GO: the rest of the WS9 staging rehearsal
— migration-recovery and backup-restore run **on staging** with a measured, recorded
recovery time, plus staging-config sign-off — completed with retained evidence; an
external penetration test completed with retained evidence; and all residual risks in
SECURITY.md remaining accepted. (The WS6 supported-scope decision is resolved below:
MSA excluded from the initial release.) Code readiness and staging readiness are
tracked separately above.

**Supported-scope decision (resolved 2026-10-26):** the initial production scope
supports Google (`google`), organizational Microsoft Entra (`entra`), and generic
`oidc`. **Personal Microsoft accounts (MSA, `microsoft`) are excluded from the
initial release** — WS6 is out of initial scope, deferred and not passed. The
`microsoft` preset remains in the code but is unvalidated and unsupported for
production; it is not claimed to work. GO does **not** require WS6. If a later
release adds MSA to scope, WS6 must first pass a live round trip.

The external-validation steps that unblock these gates are enumerated as an
executable checklist in [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md).
