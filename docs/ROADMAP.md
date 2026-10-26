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
| 4 | Migration & recovery assurance | **PASS (code)** | Repeatable rehearsal script `scripts/migration_rehearsal.sh` — **ALL_PASS 2026-10-25** on disposable isolated containers: fresh install applies all 7 migrations in order; `pg_dump` backup restores onto a *separate* target with identical `schema_migrations` and data, and a second engine run applies zero further migrations; pre-0007 database upgraded by the engine applies exactly 0007 and a pre-existing generic OIDC provider survives as `provider_type='oidc'` with empty tenant. Each migration transactional (atomic per file); recovery documented in DEPLOYMENT.md § *Rehearsing migrations and recovery*. | Platform-specific backup/restore commands/tooling still depend on the chosen host (runbook). | Run the script in staging (WS9); fill host-specific restore commands when the target is known. | yes |
| 5 | Live Google login | **PASS (local non-prod)** | Real Google OIDC round trip on 2026-10-25 against the local dev engine (issuer `http://localhost:8080`, `IAM_DEV_MODE=true`) with a dedicated non-production OAuth client. Verified: minted authorization URL (host `accounts.google.com`, byte-exact `redirect_uri=http://localhost:8080/idp/callback`, `state`, `nonce`, PKCE `code_challenge`+`S256`, `scope=openid profile email`); after human browser login the session was `authenticated`, `amr=["fed"]`, `idp_checked`; the identity was auto-provisioned and keyed on `(idp_id, subject)` — not email (confirmed in `user_identities`). Negative cases passed live: forged `state`→400, burned-intent redeem→401, uncompleted-intent wrong-binding→401. Smoke + feature suites green on a disposable isolated engine. All disposable infra and the test org/identity were removed afterward; no secrets committed. | none for local | Repeat the round trip under HTTPS staging during WS9. | yes (pre-production) |
| 6 | Live Microsoft personal (MSA) | **OUT OF INITIAL SCOPE** (2026-10-26) — *excluded by product-scope decision; deferred, not passed* | Issuer pinning to the consumers tenant verified offline only; **no passing live round trip has been recorded.** The live test had been deferred after an unresolved Microsoft account/tenant access error, and on 2026-10-26 the product-scope decision **excluded personal Microsoft accounts from the initial production scope.** The `microsoft` preset remains in the codebase but is unvalidated and unsupported for the initial release. | none for the initial release (excluded from scope). | Revisit only if a future release adds MSA to scope; a live round trip (harness identical to WS5/WS7) and a usable personal-account Azure app registration would then be required. | **no (excluded from initial scope)** |
| 7 | Live Microsoft Entra ID | **PASS (local non-prod)** | Real Entra ID OIDC round trip on 2026-10-26 against a disposable local engine (issuer `http://localhost:8080`, `IAM_DEV_MODE=true`) with a dedicated non-production app registration and test directory. Verified: the engine pins the issuer server-side to `https://login.microsoftonline.com/<tenant-guid>/v2.0` (built from live Entra discovery, not an admin-supplied value); the minted authorization URL was correct (host `login.microsoftonline.com`, authorize path under the configured tenant GUID, byte-exact `redirect_uri=http://localhost:8080/idp/callback`, `state`, `nonce`, PKCE `code_challenge`+`S256`, `scope=openid profile email`); `client_secret` was never returned. After a human browser login the session was `authenticated`, `amr=["fed"]`, `idp_checked`, `mfa_required=false`; the identity was auto-provisioned and keyed on `(idp_id, subject)` — not email. Live negatives passed: forged `state`→400, burned-intent redeem→401, uncompleted-intent wrong-binding→401. **Cross-tenant rejection (mandatory gate) proven live:** an IdP pinned to a different directory refused an out-of-directory identity at Microsoft's authorize endpoint (AADSTS "account does not exist in tenant / no access to the application"); no code reached the engine and no session was issued. (Refusal observed at the authorize/app layer for a single-tenant app; the engine's strict-`iss` equality backstop remains covered by offline unit tests.) Disposable engine/Postgres/image and all credential files were removed afterward; no secrets committed. | HTTPS repeat under staging still pending (WS9). | Repeat the round trip under HTTPS staging during WS9. | yes (pre-production) |
| 8 | Operational readiness | **PASS WITH FINDINGS** | DEPLOYMENT.md (upgrade/recovery/key rotation) + OPERATIONS.md (config, secrets, TLS/proxy, pool sizing, health/readiness, monitoring signals, audit retention, incident response, dependency response, operator deploy checklist), grounded in `config.go` defaults. | Metrics backend, alert thresholds, and backup tooling are host-specific (marked runbook). | Fill host-specific values once the target platform is chosen. | yes |
| 9 | Staging rehearsal | **BLOCKED (plan ready)** | Rehearsal plan written: `docs/STAGING.md` defines prerequisites, the production-like config posture (HTTPS issuer, dev mode off), and the exact evidence-producing steps (reuses `scripts/migration_rehearsal.sh`, HTTPS Google/Entra round trips, Entra cross-tenant gate). | Needs an isolated staging host with TLS plus the WS6/WS7 provider credentials; WS6 currently deferred. | Execute `docs/STAGING.md` once a staging host and credentials exist. | yes (pre-production) |

## Required external prerequisites (the only items blocking the remaining work)

To unblock WS5–7 (and therefore WS9), the following **non-production** registrations
are required. Create them against throwaway/test tenants only; never use customer
identities:

1. ~~**Google:** an OAuth 2.0 Web client in a test Google Cloud project — client id,
   client secret, and an authorized redirect URI set to the engine's
   `callback_url` (`{issuer}/idp/callback`).~~ **Done (local non-prod, 2026-10-25)** —
   see WS5. A further round trip under HTTPS staging is folded into WS9.
2. **Microsoft personal:** an Azure app registration with the personal-Microsoft-account
   audience — application (client) id, a client secret, and the redirect URI; plus a
   disposable MSA test account. **Deferred (2026-10-25):** blocked by an unresolved
   Microsoft account/tenant access error during registration; resume when cleared.
3. ~~**Microsoft Entra:** a dedicated test directory (tenant) — its directory (tenant)
   GUID, an app registration in that directory (client id + secret + redirect URI),
   and a test user in the directory.~~ **Done (local non-prod, 2026-10-26)** — see WS7,
   including the live cross-tenant rejection gate. A further round trip under HTTPS
   staging is folded into WS9.

Provide these as environment inputs to the live harness (never committed). WS5 (Google)
and WS7 (Entra) have now passed locally; only WS6 (personal Microsoft) remains deferred.
Production stays **NO-GO** per the mandate's completion criteria until the staging
rehearsal (WS9) and external penetration test are complete with retained evidence.

## Production go/no-go

**NO-GO.** The live-provider round trips required by the final supported scope
have now passed in non-production (WS5 Google and WS7 Entra, 2026-10-25/26), and
Entra cross-tenant rejection was proven live (WS7). Remaining gates before GO:
the WS9 staging rehearsal under real HTTPS (including HTTPS repeats of the WS5/WS7
round trips, migration-recovery, and backup-restore) completed with retained
evidence; an external penetration test completed with retained evidence; the WS6
supported-scope decision resolved (below); and all residual risks in SECURITY.md
remaining accepted. Code readiness and staging readiness are tracked separately above.

**Supported-scope decision (resolved 2026-10-26):** the initial production scope
supports Google (`google`), organizational Microsoft Entra (`entra`), and generic
`oidc`. **Personal Microsoft accounts (MSA, `microsoft`) are excluded from the
initial release** — WS6 is out of initial scope, deferred and not passed. The
`microsoft` preset remains in the code but is unvalidated and unsupported for
production; it is not claimed to work. GO does **not** require WS6. If a later
release adds MSA to scope, WS6 must first pass a live round trip.

The external-validation steps that unblock these gates are enumerated as an
executable checklist in [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md).
