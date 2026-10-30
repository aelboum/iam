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
| 3 | Independent security assurance | **PASS WITH FINDINGS** | Full trace of M1–M12 / L1–L11 / D1,D3 (see SECURITY.md); no Critical/High/Medium; no preset issuer/trust/tenant bypass. A **third** independent adversarial review (2026-10-26) found no new Critical/High/Medium and fixed three items with regression tests — cross-factor lockout (a temporary password/TOTP lockout no longer blocks passkey/SSO/finalize), SSRF denylist extension, API-key expiry cap — and dispositioned four others (SECURITY.md N7–N10). CI green on `1d48e51`. | none (remaining items are Low/Informational, dispositioned) | Keep the threat model current as code changes; an independent external pentest remains outstanding (separate gate). | yes |
| 4 | Migration & recovery assurance | **PASS (code + staging)** | Repeatable rehearsal script `scripts/migration_rehearsal.sh` — **ALL_PASS 2026-10-25** on disposable isolated containers: fresh install applies all 7 migrations in order; `pg_dump` backup restores onto a *separate* target with identical `schema_migrations` and data, and a second engine run applies zero further migrations; pre-0007 database upgraded by the engine applies exactly 0007 and a pre-existing generic OIDC provider survives as `provider_type='oidc'` with empty tenant. Each migration transactional (atomic per file); recovery documented in DEPLOYMENT.md § *Rehearsing migrations and recovery*. **Staging (2026-10-26):** the audited script (unchanged) ran **ALL_PASS** against the `iam-staging-iam:latest` image on the staging host; additionally a `pg_dump` of the **live staging DB** (read-only source) restored onto an isolated disposable target and validated there (`schema_migrations=7`, 24 public tables); measured **recovery time 4.90s** (T0 `pg_dump` start → T1 validated restore; includes throwaway-target provisioning; backup ≈40 KB) on the nearly-empty live DB; and, at a **larger synthetic volume** (71 MB: 1,000 orgs / 10,000 users / 500,000 audit rows), **total recovery 8.73s** (backup 1.11s, provision 2.72s, restore 2.87s, readiness 1.54s) with all row counts matching and `schema_migrations=7`. Both are bounded synthetic baselines, **not** a production SLA/RTO. Disposable resources removed afterward (verified); live staging untouched. | Platform-specific backup/restore commands/tooling still host-dependent (runbook); production-scale recovery timing not yet measured; rollback-criteria rehearsal still pending. | Rehearse rollback criteria; measure recovery at a representative data volume once a target is chosen. | yes |
| 5 | Live Google login | **PASS (local + HTTPS staging)** | Real Google OIDC round trip on 2026-10-25 against the local dev engine (issuer `http://localhost:8080`, `IAM_DEV_MODE=true`) with a dedicated non-production OAuth client. Verified: minted authorization URL (host `accounts.google.com`, byte-exact `redirect_uri=http://localhost:8080/idp/callback`, `state`, `nonce`, PKCE `code_challenge`+`S256`, `scope=openid profile email`); after human browser login the session was `authenticated`, `amr=["fed"]`, `idp_checked`; the identity was auto-provisioned and keyed on `(idp_id, subject)` — not email (confirmed in `user_identities`). Negative cases passed live: forged `state`→400, burned-intent redeem→401, uncompleted-intent wrong-binding→401. Smoke + feature suites green on a disposable isolated engine. All disposable infra and the test org/identity were removed afterward; no secrets committed. **HTTPS staging (2026-10-26):** the same round trip passed against the public HTTPS staging engine (issuer `https://<staging-host>` served via a Cloudflare Quick Tunnel, `IAM_DEV_MODE` off, dedicated Postgres): real human browser login, redeem **HTTP 201**, issuer `accounts.google.com`, byte-exact `redirect_uri=https://<staging-host>/idp/callback`, `state`/`nonce`/PKCE `S256`, `scope=openid profile email`, session `amr=["fed"]`+`idp_checked` with no unproven MFA, identity keyed on `(idp_id, subject)`; live negatives 400/401/401; throwaway org deleted (`orgs_remaining=0`); run on a short-lived instance-admin key (the permanent bootstrap key only minted/revoked it); no secrets committed. | none | — | yes (pre-production) |
| 6 | Live Microsoft personal (MSA) | **OUT OF INITIAL SCOPE** (2026-10-26) — *excluded by product-scope decision; deferred, not passed* | Issuer pinning to the consumers tenant verified offline only; **no passing live round trip has been recorded.** The live test had been deferred after an unresolved Microsoft account/tenant access error, and on 2026-10-26 the product-scope decision **excluded personal Microsoft accounts from the initial production scope.** The `microsoft` preset remains in the codebase but is unvalidated and unsupported for the initial release. | none for the initial release (excluded from scope). | Revisit only if a future release adds MSA to scope; a live round trip (harness identical to WS5/WS7) and a usable personal-account Azure app registration would then be required. | **no (excluded from initial scope)** |
| 7 | Live Microsoft Entra ID | **PASS (local + HTTPS staging)** | Real Entra ID OIDC round trip on 2026-10-26 against a disposable local engine (issuer `http://localhost:8080`, `IAM_DEV_MODE=true`) with a dedicated non-production app registration and test directory. Verified: the engine pins the issuer server-side to `https://login.microsoftonline.com/<tenant-guid>/v2.0` (built from live Entra discovery, not an admin-supplied value); the minted authorization URL was correct (host `login.microsoftonline.com`, authorize path under the configured tenant GUID, byte-exact `redirect_uri=http://localhost:8080/idp/callback`, `state`, `nonce`, PKCE `code_challenge`+`S256`, `scope=openid profile email`); `client_secret` was never returned. After a human browser login the session was `authenticated`, `amr=["fed"]`, `idp_checked`, `mfa_required=false`; the identity was auto-provisioned and keyed on `(idp_id, subject)` — not email. Live negatives passed: forged `state`→400, burned-intent redeem→401, uncompleted-intent wrong-binding→401. **Cross-tenant rejection (mandatory gate) proven live:** an IdP pinned to a different directory refused an out-of-directory identity at Microsoft's authorize endpoint (AADSTS "account does not exist in tenant / no access to the application"); no code reached the engine and no session was issued. (Refusal observed at the authorize/app layer for a single-tenant app; the engine's strict-`iss` equality backstop remains covered by offline unit tests.) Disposable engine/Postgres/image and all credential files were removed afterward; no secrets committed. **HTTPS staging (2026-10-26):** the round trip was repeated against the public HTTPS staging engine (issuer `https://<staging-host>` served via a Cloudflare Quick Tunnel, `IAM_DEV_MODE` off, dedicated Postgres): correct issuer pin `https://login.microsoftonline.com/<tenant-guid>/v2.0`, byte-exact `redirect_uri=https://<staging-host>/idp/callback`, `state`/`nonce`/PKCE `S256`, `scope=openid profile email`, `client_secret` never returned; after a human browser login the session was `authenticated`, `amr=["fed"]`, `idp_checked`, `mfa_required=false`, identity keyed on `(idp_id, subject)`; redeem **HTTP 201**; live negatives 400/401/401. **Cross-tenant probe:** an IdP pinned to a different directory was refused by Microsoft's authorize endpoint and `probe_check` confirmed no usable code reached the engine and no session was issued (refusal at the authorize/app layer; the engine's strict-`iss` equality backstop remains covered by offline unit tests). Each run used a short-lived instance-admin key (permanent bootstrap only minted/revoked it) and a throwaway org deleted afterward (`orgs_remaining=0`); dev mode off required an https `return_url`, captured by a loopback HTTPS catcher. Two provider-side input errors (Secret ID vs Value `AADSTS7000215`; `client_id`/tenant mismatch `AADSTS700016`) were caught and produced no session; the recorded pass is the corrected run only. No secrets committed. | none | — | yes (pre-production) |
| 8 | Operational readiness | **PASS WITH FINDINGS** | DEPLOYMENT.md (upgrade/recovery/key rotation) + OPERATIONS.md (config, secrets, TLS/proxy, pool sizing, health/readiness, monitoring signals, audit retention, incident response, dependency response, operator deploy checklist), grounded in `config.go` defaults. | Metrics backend, alert thresholds, and backup tooling are host-specific (marked runbook). | Fill host-specific values once the target platform is chosen. | yes |
| 9 | Staging rehearsal | **PASS (staging rehearsal)** | Isolated HTTPS staging stands up per `docs/STAGING.md` (dedicated Postgres 17, `IAM_DEV_MODE` off, issuer `https://<staging-host>` served via a Cloudflare Quick Tunnel, no published host ports). **Federation round trips complete (2026-10-26):** live HTTPS Google and Entra logins both passed (redeem HTTP 201, correct issuer/callback/`state`/`nonce`/PKCE-`S256`, `amr=["fed"]`+`idp_checked`, identity keyed on `(idp_id, subject)`, live negatives 400/401/401) and the Entra cross-tenant probe produced no usable session — see WS5/WS7. Every throwaway org was deleted (`orgs_remaining=0`) and ran on a short-lived instance-admin key; no secrets committed. **Recovery rehearsal complete (2026-10-26):** `scripts/migration_rehearsal.sh` (unchanged) ran **ALL_PASS** against the staging image; a backup of the **live staging DB** restored onto an isolated disposable target validated there (7 migrations, 24 public tables); measured **recovery time 4.90s** (nearly-empty DB — not a production estimate); a limited smoke test (`/healthz` 200, issuer match, JWKS 1 key) passed; all disposable resources removed (verified). **B1–B4 complete (2026-10-26):** staging-config sign-off **PASS** (with noted production follow-ups), rollback criteria documented + rehearsed on disposable resources, live audit-event persistence + tenant isolation verified, and recovery re-measured at a 71 MB synthetic volume (**total 8.73s**). See EXTERNAL_VALIDATION §§ 3–4. | External independent penetration test (Phase E) still outstanding; production hardening follow-ups noted (stable DNS vs ephemeral tunnel, managed secret store, DB TLS, bootstrap-admin rotation). | Pentest package prepared (PENTEST.md); commission an independent tester (separate authorization); apply the production hardening follow-ups at deploy time. | yes (pre-production) |

## N12 — CPU/RAM protection, overload classification, migration safety (code readiness, 2026-10-27)

Added on branch `n12-bounded-hash-slot`, **local commits only — not pushed, not
yet exercised by hosted CI.** Commits: `dde81f3`, `d6bda11`, `6055a2e`,
`4969ceb`, `8b438c9`. Validated locally with Go 1.27.3 (`go build`, `go vet`,
`gofmt`, `go test ./...` serial and parallel) and against a disposable Postgres
16 container (`IAM_TEST_DATABASE_URL`); `govulncheck ./...` reports 0
code-reachable vulnerabilities under the patched toolchain and `gitleaks` reports
0 leaks over full history. An independent in-session code review of the diff
found **no Critical/High/Medium**; its four Low items were dispositioned (two
fixed in `8b438c9`, two kept for consistency with existing conventions).

| Item | Status | Evidence | Remaining uncertainty / operator action | Closable without prod/external? |
|------|--------|----------|------------------------------------------|---------------------------------|
| Bounded hash-slot sizing (A) | **PASS (code + local tests)** | `d6bda11`. `internal/sizing` auto-sizes the hashing pool from `GOMAXPROCS` (cgroup-CPU-aware on Go 1.25+, unlike `NumCPU`); `IAM_HASH_SLOTS` (0=auto, 1..1024) and `IAM_STRICT_SIZING` added; startup reads the cgroup v2/v1 memory limit and warns, or fails fast under strict. Unit tests cover the v1/v2 parsers (incl. unlimited/unreadable), the GOMAXPROCS floor, the sufficient/insufficient/unknown/exact-fit decisions, config validation bounds, and the `ConfigureHashSlots` floor. | Memory check is **skipped silently** where no finite cgroup limit is readable (non-Linux, no controller, or `max`) — it never invents a limit, so a host with no enforced limit is unprotected; set `IAM_HASH_SLOTS` by hand there (documented in OPERATIONS.md). `GOMEMLIMIT` and parent-cgroup limits are not consulted (conservative). | yes |
| Migration concurrency (B) | **PASS (code + local tests)** | `dde81f3`, hardened in `8b438c9`. `db.Migrate` had no concurrency guard; `TestMigrateConcurrent` (8 goroutines, fresh DB) reproduced 7/8 failures (`pg_type_typname_nsp_index` duplicate) on the old code. Fixed with a session-level Postgres advisory lock on a dedicated connection, released before the connection returns to the pool (and the connection destroyed if the unlock fails, so a lock-holding connection can never re-enter the pool). Passes 5× and under the full parallel suite against a real DB. Protects simultaneous replica startup during a rolling deploy. | **Deployment caveat:** session advisory locks are unsafe behind a transaction-mode connection pooler (e.g. PgBouncer in `transaction` mode); run migrations against a direct/`session`-mode connection. | yes |
| Overload vs. invalid-credentials (B) | **PASS (code + local tests)** | `4969ceb`. The N12 integration review found a hash-overload shed (a) was reported as `ErrInvalidCredentials` (401) for unknown/locked/passwordless users while a known user got `ErrOverloaded` (503) — an account-enumeration oracle under load — and (b) left the `ReserveAttempt` lockout increment unsettled, so transient sheds advanced a real user toward lockout. Fixed: `verifyDummy` surfaces overload uniformly and new `store.ReleaseAttempt` undoes an unevaluated attempt (decrement floored at 0; no lockout bypass — the attempt was never evaluated). `TestOverloadDoesNotLeakOrEnumerate` (disposable DB) asserts both a known and a passwordless user get `ErrOverloaded` and `failed_logins` stays 0. | Release uses the request context (same pre-existing property as `attemptFailed`); affects only the requester's own account, not a bypass. | yes |
| Race detector (`go test -race`) | **NOT RUN locally** | The local toolchain has `CGO_ENABLED=0` and no C compiler, which the race detector requires. | Hosted CI runs `go test -race ./...` (ci.yml); rely on CI for the race gate once these changes are pushed. | **no** (needs CI or a cgo-capable host) |
| e2e smoke/feature suites | **NOT RUN this session** | Require a running engine + Python `cryptography`; CI job `e2e` covers them. | Re-run via CI when pushed, or locally against a disposable engine. | partial |
| Independent penetration test | **NOT PERFORMED** | Unchanged by this work. Internal AI review, unit/integration tests, `govulncheck`, `gitleaks` and successful CI do **not** substitute for it. | Commission an independent external tester (PENTEST.md); separate authorization. Production remains **NO-GO** while this gate is open. | **no** |

## OIDC token-lifecycle & machine-client authorization audit (code readiness, 2026-10-28)

Read-only audit of the OIDC token-lifecycle and machine-client authorization
surface, plus **test-only** regression guards on local branch
`test-oidc-token-lifecycle` (off `main` `0ac28ee`) — **no production code
changed; not pushed; no defect found.** Validated with Go 1.27.3 (`gofmt`,
`go vet ./...`, `go build ./...`, `go test ./...`) against disposable Postgres
16; `-race` and `e2e` remain CI-only here. `govulncheck ./...` reports 0
code-reachable vulnerabilities on this line of work (1 vuln in a required module
not called — the documented GO-2026-5932 disposition); `gitleaks` is CI-only
(not installed locally).

| Guard | Commit | Property pinned | Status |
|-------|--------|-----------------|--------|
| OIDC logout / refresh rotation / reuse | `2424965` | `TerminateTokens` = per user+client (not whole user); `RotateRefreshToken` consumes the presented token and issues the next in the same family; presenting a rotated-out (used) refresh token revokes the **whole family** and nothing else; unknown/expired → existing error contract. | PASS (code + local tests) |
| RFC 7009 `RevokeToken` scope | `ea9936f` | Refresh-token revoke = whole family; access-token revoke = that token only (family stays); client_id mismatch → `invalid_client`, nothing revoked (both token types); unknown / already-revoked = idempotent no-op; other family/user/client+tenant untouched. | PASS (code + local tests) |
| `DeleteAccessToken` dangling contract | `e741ed0` | No FK between access/refresh tokens (plain uuid; subject/client_id text), so the delete removes only the target access token, leaves the linked refresh family alive, touches no other token; unknown id = no-op. | PASS (code + local tests) |
| Live introspection after grant change | `e741ed0` | `SetIntrospectionFromToken` is a live decision on an **opaque** bearer token: narrowing a project grant drops the forbidden roles and revoking it reports the token inactive on the next call; a caller from another project cannot introspect it; a second tenant stays isolated. Scope limit documented: self-contained **JWT** access tokens are validated at the resource server and are **not** retroactively invalidated by a grant change until they expire (≈5m TTL). | PASS (code + local tests) |
| Machine-user introspection | `b76f39e` | Machine token carries its project via `urn:iam:project:<id>` scope; authorized like a human via `checkUserCanUseProject`→`AvailableRoles(project, machine.OrgID)`. Naming a project in the scope grants nothing; the owner org is always authorized without a grant row (documented difference). Store `DeleteProjectGrant` fails only the live check (token row survives); `RevokeProjectTokens` physically deletes the scope-matched token — two separate guarantees. | PASS (code + local tests) |
| Machine `client_credentials` grant re-check | `9b951ee` | A new token request re-checks the scoped project live via `AvailableRoles`; after the org's grant is revoked the next request is refused with `invalid_scope` (no new token), while another granted tenant is unaffected. Machine users have only the client_credentials grant (no refresh flow). | PASS (code + local tests) |
| Machine `client_credentials` scope-storage contract | `3c1be3f` | Only one `urn:iam:project:<uuid>` with a usable grant is honoured; empty-string safely dropped; `openid`/`offline_access`/unknown/second-project/malformed-uuid each **explicitly** refused `invalid_scope` (no silent pass-through); the stored/issued token carries only the validated scope; a refused request writes no token/refresh row and mutates no grant. | PASS (code + local tests) |
| Independent penetration test | — | **NOT PERFORMED.** Unchanged by this work; internal/AI/automated analysis is not a substitute. Production remains **NO-GO** while criterion 12 is open. | NOT PERFORMED |

## Tenant isolation & authorization audit (code readiness, 2026-10-28)

Read-only audit of the multi-tenant authorization boundary, plus **test-only**
regression guards. On local branches off `main` (`0ac28ee`), each its own draft
PR awaiting the operator's merge decision — **no production code changed; merges
not authorized**. Validated with Go 1.27.3 (`gofmt`, `go vet`, package tests)
against disposable Postgres 16; `-race` remains CI-only here.

- **Session scope (PR #6, `68ff1b1`).** A session presented with another org's
  id is rejected (`ErrSessionInvalid`) on every path; `loadSession` already
  enforces it. Guard only.
- **AvailableRoles (PR #6, `d19de5c`).** Project roles are offered only to the
  owning org or an org holding an explicit project grant; any other org gets
  `ok=false` and no roles. Guard only.
- **EffectiveRoles (PR #6, `a942acd`, unpushed).** A user's effective roles are
  the intersection of their assigned roles and what their org may currently hand
  out, recomputed at read time — so narrowing or revoking the org's project grant
  drops roles on the next resolution without rewriting each `user_grant` row.
  Inspected chain: `api.userForCaller`→`canAccessOrg` blocks cross-org user ids
  (404, no existence leak); `CreateUserGrant`/`UpdateUserGrant` enforce roleKeys ⊆
  `AvailableRoles(user.OrgID)`; OIDC `checkUserCanUseClient`→app project→
  `AvailableRoles`; `tokenProject` returns the app's own project (scope cannot
  override); machine project-scope validated in `ClientCredentialsTokenRequest`.
  No defect; guard only.
- **Project-grant token revocation (PR #6, `d2a5250`, unpushed).** Research
  question: can already-issued access tokens outlive a narrowed/removed grant?
  **No defect — intended and safe by three independent layers.** (1) The API
  handlers `updateProjectGrant`/`deleteProjectGrant` follow the grant change with
  `store.RevokeProjectTokens(projectID, grantedOrgID)`, which deletes the org's
  access **and** refresh tokens for the project's apps and any machine tokens
  carrying the project scope, scoped to exactly that org+project. (2) Bearer-token
  introspection (`SetIntrospectionFromToken`) re-runs `checkUserCanUseProject`, so
  a revoked grant reports the token **inactive immediately** and a narrowed grant
  yields reduced roles via a live `EffectiveRoles` recomputation — independent of
  whether the row was deleted. (3) Access-token TTL is short (5m default) and the
  refresh family is revoked, so no fresh token is minted. Regression guard
  `TestProjectGrantChangeRevokesTokens` pins the scoping (a second tenant's tokens
  for the same project and the same tenant's tokens for another project survive).
  **Accepted limitation (not a defect):** a *self-contained JWT* access token
  (`access_token_type=jwt`), validated by signature without introspection, is not
  reflected until it expires; the bound is the access-token TTL plus the eager
  refresh-family revocation — the standard short-lived-JWT tradeoff.
  **Recommended follow-up — now done** (see the next bullet): the `internal/api`
  handler-wiring test asserting the handlers call `RevokeProjectTokens` was added
  in `3008d53`, closing the gap the store-level test could not see.
- **Handler revocation wiring (PR #6, `3008d53`/`7084fb9`/`f291155`/`0866a5e`,
  unpushed).** The `internal/api` guards now cover the handler->store
  token-revocation wiring the store tests cannot see: `updateProjectGrant`/
  `deleteProjectGrant` (org+project scoped, other tenant/project survive),
  `lockUser`/`deleteUser` (only that user), `setPassword` (admin: revokes target
  only; weak password → non-2xx, no revoke), and the self-service reset path
  `ConfirmPasswordReset` (authn-level — **atomic in `CompletePasswordReset`'s
  transaction**: access+refresh tokens, sessions and password_resets dropped
  together; another user untouched; a bad token revokes nothing). `deleteApp`
  (`f291155`) revokes only the deleted app's client tokens — a sibling app in the
  same project and an app in another tenant survive, and a missing app fails at
  the owner lookup before any revoke. `logoutUser` (`0866a5e`, force-logout via
  `RevokeUserTokens`) revokes the target user across every client while other
  users and other tenants stay intact — distinct from OIDC end-session
  (`TerminateTokens`, per user+client). Established invariant: federation login
  (`RedeemFederatedLogin`) and SSO account-linking (`LinkIdentity`) deliberately
  **preserve** existing sessions and carry no revocation. All guards only.
- **Org deletion token revocation (PR #6, unpushed).** `deleteOrg` revokes
  **before** deleting (`RevokeOrgTokens` then `DeleteOrg`), because the token
  lookup resolves subjects through the org's users, which must still exist; org
  deletion cascades its users via FK, but access/refresh tokens have no FK
  (subject is text), so a delete-first order would orphan them. `RevokeOrgTokens`
  is a single transaction scoped to `subject IN (users WHERE org_id = $1)`, so
  only the deleted org's tokens go; another org's survive. Guard
  `TestDeleteOrgHandlerRevokesOnlyThatOrgsTokens` pins this (deleted org's tokens
  gone, other org's survive, a non-existent org id yields a non-2xx error and no
  revocation). **Atomicity (documented, not a defect):** revoke and delete are
  two separate transactions. A failure of `DeleteOrg` after `RevokeOrgTokens`
  leaves the org present with its tokens revoked — a fail-safe direction (users
  re-authenticate; no access retained). A token minted by a concurrent login in
  the narrow window between the two is not cascade-deleted, but its subject user
  is gone, so introspection reports it inactive and it expires with its TTL; it
  is also swept by `PurgeExpired`. No production change made; wrapping both in
  one transaction is a possible future hardening, not required by a demonstrated
  defect.

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
external penetration test — **waived by the owner (2026-10-28), risk accepted**
(SECURITY.md register W1), so no longer a blocking gate; and all residual risks in
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

## Production-readiness matrix

Authoritative status as of commit `323075c` (CI `test`/`e2e`/`security`/`image-scan` green).

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | No unresolved Critical/High security findings | **PASS** | SECURITY.md; three independent reviews, none open above Low |
| 2 | Every Medium fixed or dispositioned | **PASS** | D3 accepted-by-design (SECURITY.md register). The 2026-10-29 internal audit (docs/security/INTERNAL_SECURITY_AUDIT.md) found two further Medium items, both now fixed: container `mem_limit` in the prod/staging compose files, and the CSP/`form_post` break (M-01) fixed in PR #21 (merged to `main`, commit `48649bf`) with regression tests — see the reconciliation note below. |
| 3 | Required CI jobs pass on the final commit | **PASS** | `323075c`: `test`, `e2e`, `security`, `image-scan` success |
| 4 | Migration/upgrade paths tested | **PASS** | WS4; `migration_rehearsal.sh` ALL_PASS (local + staging) |
| 5 | Backup/restore + recovery with reproducible evidence | **PASS** | EXTERNAL_VALIDATION §4; 4.90s (empty) and 8.73s (71 MB synthetic) |
| 6 | Rollback criteria documented and rehearsed | **PASS** | STAGING.md; disposable rehearsal 2026-10-26 (B2) |
| 7 | Staging configuration signed off | **PASS (noted follow-ups)** | EXTERNAL_VALIDATION §3 (B1); production follow-ups listed |
| 8 | Audit persistence + tenant isolation verified | **PASS** | EXTERNAL_VALIDATION §4 (B3); cross-tenant 403 |
| 9 | Live IdP flows + negative cases evidenced | **PASS** | WS5/WS7; Google + Entra over HTTPS staging |
| 10 | Cross-tenant rejection verified | **PASS (with caveat)** | Live refusal at the authorize layer; engine strict-`iss` via offline tests (SECURITY.md) |
| 11 | Secret/key/bootstrap-admin lifecycle reviewed | **PASS (follow-up)** | SECURITY.md; bootstrap-admin rotation is a documented production follow-up |
| 12 | Independent external penetration test completed | **NOT PERFORMED — WAIVED (risk accepted by owner, 2026-10-28)** | No independent engagement performed; the owner has deliberately waived this gate and accepted the risk — see SECURITY.md "Waived gate" entry (register W1). This is a waiver, **not** a pass; internal and AI-assisted audits remain explicitly **not** a substitute (PENTEST.md). Tester selection/brief retained should the owner reverse: PENTEST_VENDOR_SELECTION.md. |
| 13 | Operational monitoring / IR / recovery documented | **PASS** | OPERATIONS.md, DEPLOYMENT.md (WS8) |
| 14 | Every exception/residual risk explicit and reviewed | **PASS** | SECURITY.md residual register N1–N20 |
| 15 | Final code, docs, migrations, config, CI agree | **PASS** | Reconciled; CI green on `323075c` |

**Overall: `NO-GO — PENDING OWNER RELEASE AUTHORIZATION`.** Every technical gate that can
be satisfied internally has passed with evidence on `323075c`. The one mandatory gate that
cannot be satisfied internally — **criterion 12, an independent external penetration test** —
has been **waived by the owner** (2026-10-28), who formally accepted the risk of releasing
without it (SECURITY.md, register W1 and the "Waived gate" subsection); it is recorded as
**NOT PERFORMED — WAIVED**, not passed, and internal/AI-assisted testing is still not
represented as equivalent. With that gate waived, no *technical* gate remains blocking (the
CSP/`form_post` Medium from the 2026-10-29 internal audit was fixed in PR #21), but
production stays **NO-GO** until the owner **explicitly authorizes release** and the production
hardening follow-ups (stable DNS instead of the ephemeral tunnel, a managed secret store, DB
TLS, bootstrap-admin rotation — step-by-step runbook with verification and rollback:
[DEPLOY_HARDENING.md](DEPLOY_HARDENING.md)) are applied at deploy time.

An internal security audit (2026-10-27) — two independent reviews, every finding
verified against the code — fixed four lower-severity issues (OIDC auth-request
parameter caps, federated-provisioning quota, invalid-key log throttling, and
canonical rate-limit/audit IP keys; see SECURITY.md) with regression tests, and
dispositioned the rest (register N11–N20). These changes are validated locally
(`go build`/`go vet`, `go test ./...` against a disposable Postgres, and the
smoke + feature suites) but are **not yet committed**. This internal hardening
does **not** satisfy criterion 12 and does **not** change the overall status:
production remains **NO-GO** pending the independent external penetration test,
its remediation, and retest.

**Reconciliation note (2026-10-30).** The matrix pin advanced from `1d48e51` to `323075c`.
Eight pull requests merged in between, each with CI green: deploy-hardening follow-ups
(#14), a Trivy image/config scan CI job (#15, #16), a production plaintext-database-URL
warning (#16), mandatory PKCE for every interactive client (#17), a breached/common
password denylist (#18), org-level MFA enforcement with an enrollment gate (#19), and MFA
backup/recovery codes (#20). A fourth internal, source-first audit (2026-10-29,
docs/security/INTERNAL_SECURITY_AUDIT.md) reviewed commit `2f78ab6` and found **no Critical
and no High**, two Medium, six Low, and eight Informational. Of the two Medium items: the
missing container `mem_limit` (which left the N12 sizing guard disengaged) is **fixed** —
`docker-compose.prod.yml` and `docker-compose.staging.yml` now set `mem_limit: 1g`; the
global CSP (`default-src 'none'; … form-action 'self'`) that broke `response_mode=form_post`
for relying parties (M-01) is now **fixed** — PR #21 (merged to `main`, commit `48649bf`) adds a
page-scoped `relaxCSPForFormPost` middleware that permits the auto-submit and the single
cross-origin POST to the validated redirect origin on the form_post page only, keeping the
strict policy everywhere else, with regression test `TestFormPostCSP`. The six Low items are now all
dispositioned: L-02 (IdP-delete leaves tokens), L-03 (factor removal leaves tokens) and L-05
(session-token transport) are **fixed** in PR #23 (merged to `main`, commit `92235e4`); L-06
(Postgres service hardening) was already **fixed** on `main`; L-01 (`end_session` without
`id_token_hint` silently revokes nothing) and L-04 (discovery advertises implicit/JWT-bearer
capabilities the engine does not implement) are **fixed** in a follow-up change — L-01 by
implementing `op.CanTerminateSessionFromRequest` to reject hint-less logout with a clear
`invalid_request` instead of a false "signed out" (regression test
`TestTerminateSessionFromRequestRequiresHint`), and L-04 by an `honestDiscovery` middleware that
strips the unsupported `response_types_supported` / `grant_types_supported` entries from the served
discovery document (regression test `TestHonestDiscovery`). This audit and these remediations do
**not** satisfy criterion 12 and are **not** an independent external penetration test; production
readiness remains NO-GO pending that and the remaining P1/P2 work.
