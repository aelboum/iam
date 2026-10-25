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
| 6 | Live Microsoft personal (MSA) | **BLOCKED / DEFERRED** (2026-10-25) — *deferred, not passed; no live evidence exists* | Issuer pinning to the consumers tenant verified offline only. Live test **deferred by the user** after an unresolved Microsoft account/tenant access error during Azure app-registration setup; not troubleshooting further now. **No passing live round trip has been recorded.** | Needs a usable **Azure app registration** (personal-account audience) and a test MSA; the account/tenant access issue must be resolved first. **Also a product-scope decision:** production scope must explicitly resolve whether personal Microsoft accounts are a supported sign-in option at all — if not, this workstream is dropped rather than completed. | Resume once the access issue is cleared *and* MSA support is confirmed in scope; harness pattern identical to WS5. | yes (pre-production) |
| 7 | Live Microsoft Entra ID | **BLOCKED** | Tenant-GUID validation and issuer pinning verified offline; cross-tenant rejection argued from strict issuer equality. | Needs a **single-directory test tenant**, an app registration, and the directory GUID. | Execute the live harness; cross-tenant rejection is a mandatory gate. | yes (pre-production) |
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
3. **Microsoft Entra:** a dedicated test directory (tenant) — its directory (tenant)
   GUID, an app registration in that directory (client id + secret + redirect URI),
   and a test user in the directory.

Provide these as environment inputs to the live harness (never committed). Until then,
WS5–7 remain `BLOCKED` and production stays **NO-GO** per the mandate's completion criteria.

## Production go/no-go

**NO-GO** until: the live-provider round trips required by the final supported
scope pass in non-production, Entra cross-tenant rejection is proven live, WS9
staging rehearsal (including migration-recovery and backup-restore) is completed
with retained evidence, an external penetration test is completed with retained
evidence, and all residual risks in SECURITY.md remain accepted. Code readiness
and staging readiness are tracked separately above.

**Supported-scope decision (prerequisite to GO):** production scope must state
which federated providers are actually supported. WS5 (Google) passed locally.
WS6 (personal Microsoft accounts) is **deferred, not passed** — before GO, scope
must explicitly decide whether MSA sign-in is supported: if yes, WS6 must pass a
live round trip; if no, MSA is declared out of scope and WS6 is dropped. GO may
not silently treat a deferred, never-tested provider as available.

The external-validation steps that unblock these gates are enumerated as an
executable checklist in [EXTERNAL_VALIDATION.md](EXTERNAL_VALIDATION.md).
