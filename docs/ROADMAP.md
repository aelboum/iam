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
| 2 | CI & security gates | **IN PROGRESS** | `.github/workflows/ci.yml` added (jobs: test, e2e, security). Local evidence: `govulncheck` 0 reachable vulns; `gitleaks` 0 leaks. | Confirm the hosted run is green; branch protection needs repo-admin action. | Watch the run, fix any failure, then enable required-status-check branch protection. | yes |
| 3 | Independent security assurance | **PASS WITH FINDINGS** | Full trace of M1–M12 / L1–L11 / D1,D3 (see SECURITY.md); no Critical/High/Medium; no preset issuer/trust/tenant bypass. | none (findings are Low/Informational, dispositioned) | Keep the threat model current as code changes. | yes |
| 4 | Migration & recovery assurance | **PASS (code)** | Isolated-DB rehearsal: fresh install applies 0001–0007 in order; upgrade path verified; pre-0007 generic OIDC survives as `provider_type=oidc`; each migration transactional (atomic per file); recovery documented in DEPLOYMENT.md. | Platform-specific backup/restore commands depend on the chosen host. | Add a repeatable rehearsal script; fill in host-specific restore commands when the target is known. | yes |
| 5 | Live Google login | **BLOCKED** | Offline config/pinning covered by `providers_test.go` + feature suite (engine as its own IdP). | Needs a dedicated **non-production Google OAuth 2.0 client** (client id + secret) and an authorized redirect URI. | Build/confirm the live harness; execute once credentials are supplied. | yes (pre-production) |
| 6 | Live Microsoft personal (MSA) | **BLOCKED** | Issuer pinning to the consumers tenant verified offline. | Needs a dedicated **Azure app registration** (personal-account audience) and a test MSA. | Same as WS5. | yes (pre-production) |
| 7 | Live Microsoft Entra ID | **BLOCKED** | Tenant-GUID validation and issuer pinning verified offline; cross-tenant rejection argued from strict issuer equality. | Needs a **single-directory test tenant**, an app registration, and the directory GUID. | Execute the live harness; cross-tenant rejection is a mandatory gate. | yes (pre-production) |
| 8 | Operational readiness | **PASS WITH FINDINGS** | DEPLOYMENT.md (upgrade/recovery/key rotation) + OPERATIONS.md (config, secrets, TLS/proxy, pool sizing, health/readiness, monitoring signals, audit retention, incident response, dependency response, operator deploy checklist), grounded in `config.go` defaults. | Metrics backend, alert thresholds, and backup tooling are host-specific (marked runbook). | Fill host-specific values once the target platform is chosen. | yes |
| 9 | Staging rehearsal | **BLOCKED** | — | Needs an isolated staging environment and the provider credentials from WS5–7. | Run once WS5–7 prerequisites and a staging env exist. | yes (pre-production) |

## Required external prerequisites (the only items blocking the remaining work)

To unblock WS5–7 (and therefore WS9), the following **non-production** registrations
are required. Create them against throwaway/test tenants only; never use customer
identities:

1. **Google:** an OAuth 2.0 Web client in a test Google Cloud project — client id,
   client secret, and an authorized redirect URI set to the engine's
   `callback_url` (`{issuer}/idp/callback`).
2. **Microsoft personal:** an Azure app registration with the personal-Microsoft-account
   audience — application (client) id, a client secret, and the redirect URI; plus a
   disposable MSA test account.
3. **Microsoft Entra:** a dedicated test directory (tenant) — its directory (tenant)
   GUID, an app registration in that directory (client id + secret + redirect URI),
   and a test user in the directory.

Provide these as environment inputs to the live harness (never committed). Until then,
WS5–7 remain `BLOCKED` and production stays **NO-GO** per the mandate's completion criteria.

## Production go/no-go

**NO-GO** until: WS5–7 live round trips pass in non-production, Entra cross-tenant
rejection is proven live, WS9 staging rehearsal (including migration-recovery and
backup-restore) is completed with retained evidence, and all residual risks in
SECURITY.md remain accepted. Code readiness and staging readiness are tracked
separately above.
