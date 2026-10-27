# Security overview, threat model, and residual-risk register

IAM is a headless, API-driven identity engine (Go, chi, pgx/Postgres). It issues
and verifies sessions, OAuth/OIDC tokens, passkeys, and per-organization SSO
("bring your own IdP", including Google / Microsoft / Entra presets). It renders
no user interface; the calling login UI owns all screens.

This document records the threat model, how each area is defended (with code
references), the disposition of the remediated audit findings, and the residual
risks that are explicitly accepted. It is a code-review and design artifact; it
does **not** substitute for the live-provider and staging validation tracked in
[ROADMAP.md](ROADMAP.md).

## Trust boundaries

- **Login API keys** are issued to the operator's own backends. They may start
  logins, redeem intents, and request password resets for the users they serve.
  They are trusted; give them only to backends you control (see D3 below).
- **Organization admins** configure their own org (users, IdPs, grants). They are
  **not** trusted to set instance-wide policy.
- **Instance admins** set instance-wide trust policy (`trust_email`, `trust_mfa`).
- **External IdPs** are configured by a tenant and are **not** trusted for email
  or MFA unless an instance admin opts in per IdP.
- **End users** authenticate; authentication never by itself grants org membership
  or product authorization.

## Threat model by area

| Area | Primary threats | Controls (code) |
|------|-----------------|-----------------|
| Authentication & account recovery | Credential stuffing, enumeration, reset-token abuse | Per-factor lockout (`internal/store/users.go:196-212`); unknown-user path matches real failure incl. hashing time (`internal/authn/authn.go:424`); reset tokens single-use/30 min, cooldown looks like unknown user (`internal/store/email.go:88-133`), invalidated on credential/lock change (M12). |
| Session & token lifecycle | Token replay, non-revocation | Opaque access tokens + refresh family; revoke by subject/org/app/project (`internal/store/oidc.go:206-248`); refresh rotation CAS (`:259-265`). |
| OIDC auth-code + PKCE | Code interception, CSRF | Standard auth-code with PKCE and state; engine-as-OP via zitadel/oidc `op`. |
| Federation & identity linking | Login CSRF, intent replay, email-based takeover | Browser binding required (`internal/authn/federation.go:111,275-279`), intent burned on redeem even on mismatch (`internal/store/idp.go:173`); identity keyed on `(idp_id, sub)` never email (`federation.go:205-210`); email link only with instance `trust_email`+`link_by_email` (`internal/api/orgs.go:294`). |
| MFA & passkeys | MFA bypass, passkey clone/replay/enumeration | `amr: fed` is not MFA; federated login satisfies MFA only if `trust_mfa` set (`authn.go:581`); passkey challenge expiry (`authn/passkeys.go:181,223-227`), counter-must-grow CAS (`store/passkeys.go:46-52`), clone regression reject (`authn/passkeys.go:201`), no credential-ID disclosure; RP settings validated at boot (`:234`). |
| Machine users & project scopes | Scope escalation | Only one `urn:iam:project:<uuid>` scope; unsupported/extra/invalid scopes rejected `invalid_scope` (`internal/oidcop/storage.go:598-616`); grant removal revokes tokens (L5). |
| Org vs instance admin | Privilege escalation to instance policy | `trust_email`/`trust_mfa` instance-admin-only on create (`orgs.go:290`) and via the admin-gated `PUT …/idps/{id}/trust`; org admin → 403 (feature-tested). |
| Rate limiting / DoS | Lockout evasion, limiter fail-open | Shared PG limiter with dedicated small pool, local-first, falls back to local on DB error (never fail-open), bounded latency (`internal/store/ratelimit_test.go`, M10/L11). |
| SSRF & outbound IdP | Internal network access via issuer/discovery | `SafeIdPURL` on authorize + every discovery endpoint (`federation.go:94-130`); `guardedTransport` dial guard via `PublicAddress`, header/body caps (`:397-435,473`, M4/L4). |
| Encryption & key rotation | Plaintext at rest, rotation data loss | Secrets sealed (AES-GCM); previous-key decryption during rotation (`internal/config/config.go`, M6); batched CAS re-encrypt; `rotate-keys --check` strictly read-only (`cmd/iamd/main.go:263-301`, M9). |
| DB failure & concurrency | Race double-spend, fail-open | Per-factor lockout bounded under parallel guesses (`users.go:179`); counter CAS (L9); limiter fallback (M10). |
| Audit & sensitive data | Secret leakage, missing trail | Client secrets encrypted, never returned/logged; audit records issuer/provider_type/trust changes, logins, lockouts (`orgs.go` audit calls, `authn.go:702`). |
| Tenant isolation | Cross-tenant token acceptance (Entra) | Issuer pinned to tenant GUID (`internal/authn/providers.go:91-95`); other tenants' tokens differ in `iss` and are rejected by strict equality. Verified live 2026-10-26 (local non-prod, WS7): an IdP pinned to a different directory refused an out-of-directory identity and issued no session. |
| Migration & recovery | Partial upgrade, data loss | Forward-only, per-migration transactional incl. version record (`internal/db/db.go:52-91`); upgrade/recovery documented (`DEPLOYMENT.md`). |

## Remediated audit findings

Findings **M1–M12, L1–L11, D1, D3** were remediated in commit
`1c4dfb7` (`fix(security): …`) with regression tests, and independently
re-traced; **no Critical/High/Medium** issue remains and no preset
issuer-pinning / trust / tenant-isolation bypass exists. (D2 has no code or
documentation annotation in this repository and could not be mapped; flagged
rather than assumed.) The per-finding matrix with file/line evidence is in the
post-push review notes and mirrored by the controls table above.

A later independent adversarial re-review (2026-10-25) found no new exploitable
defect and one Low PII-hygiene issue, now fixed: the federated-login refusal
path logged the raw `resolveFederatedUser` error, which for a database
unique-violation echoes the conflicting value (e.g. a user's email) into logs.
The refusal now logs a coarse reason (`locked` / `no_account`) and, for an
unexpected error, only its Go type — no user data (`authn/federation.go`).

A third independent adversarial review (2026-10-26) found **no new Critical,
High or Medium** defect. Three items were fixed and three dispositioned:

- **Fixed — cross-factor lockout (Low, availability).** A temporary lockout from
  failed password/TOTP guesses had blocked passkey login, federated (SSO) login,
  and auth-request finalize, because those paths used `IsLocked()` (manual lock
  **or** active temporary lockout). An attacker who knew a username could then
  deny all factors — including a phishing-resistant passkey — by guessing
  passwords ~5 times per lockout window, renewably. These paths now check the
  **manual** `Locked` flag only, matching the deliberate OP-storage rule
  (`oidcop/storage.go`); the password/TOTP steps still enforce their own lockout
  (`authn.go` `CheckPassword`/`CheckTOTP`). Regression: `features_test.py`
  (passkey succeeds during a password lockout). Files: `authn/passkeys.go`,
  `authn/federation.go`, `authn/authn.go`.
- **Fixed — SSRF denylist gaps (Informational, hardening).** `PublicAddress` now
  also blocks `168.63.129.16/32` (Azure wireserver), `192.88.99.0/24` (6to4
  relay anycast), `::/96` (IPv4-compatible), `fec0::/10` (site-local) and
  `3fff::/20` (documentation). Regression: `TestPublicAddress`
  (`authn/federation_test.go`). None was shown exploitable (https-only outside
  dev, Linux does not route `::/96`); added as defense-in-depth.
- **Fixed — API-key self-renewal (Low).** A leaked but still-valid key could mint
  a successor that outlived it, indefinitely. `issueAPIKey` now caps a child's
  expiry at the parent key's expiry (`api/orgs.go`); keys with no expiry
  (instance/bootstrap) are unaffected. Regression: `features_test.py`
  (child cannot outlive parent).
- **Dispositioned** (see register rows N7–N10 below): federated step-up is not
  forwarded to the IdP; the TOTP failure counter is intentionally sticky;
  `SafeIdPURL` is not re-run in `HandleCallback` (the dial guard and https-only
  transport still hold); and rate limits key on the full IPv6 address, not a /64.

A fourth internal audit (2026-10-27) ran as two independent reviews — one
implementation-first (route and enforcement map) and one attacker-first (abuse
cases) — with every finding verified against the code and exercised by a test or
the suites before being acted on. It found **no new Critical or High**, and no
cross-tenant data access, authentication bypass, or privilege escalation. Four
items were fixed with regression coverage; the rest were dispositioned (register
rows N11–N20):

- **Fixed — unauthenticated auth-request storage caps (Low, availability).**
  `/authorize` stored `state`, `nonce`, `login_hint` and scopes with no length
  bound (they live 30 minutes), so a valid `client_id` + `redirect_uri` could be
  used to inflate the database. `CreateAuthRequest` now rejects over-long
  parameters and excessive scopes (`oidcop/storage.go`). Regression:
  `TestAuthRequestParamCaps`.
- **Fixed — federated auto-provisioning ignored the per-org user quota (Low).**
  The just-in-time create path bypassed the API-layer `QuotaUsersPerOrg` cap, so
  a tenant's own IdP could create unbounded users. Both paths now share
  `store.MaxUsersPerOrg` and the federation path enforces it before creating a
  user (`authn/federation.go`, `store/page.go`, `api/api.go`).
- **Fixed — invalid-API-key log flood (Informational).** The "invalid API key"
  warning was logged before the per-address throttle, so a bad-key flood also
  flooded the logs at line rate; it now logs only after the limiter admits the
  caller (`api/api.go`).
- **Fixed — non-canonical rate-limit / audit IP key (Informational).** A trusted
  `X-End-User-IP` was used verbatim, so one address written several ways became
  several limiter and audit keys; it is now reduced to its canonical form
  (`api/api.go`). Regression: `TestClientIPCanonical`.
- **Dispositioned** (register N11–N20): the temporary lockout is account-wide by
  design — a per-factor split was prototyped and **reverted** because it weakened
  the tested rule that a TOTP lockout must also block the password and reset
  steps; a shared argon2 hashing pool is a noisy-neighbour availability risk;
  federated auto-provisioning stores an untrusted IdP email as the identity;
  authorization-code reuse does not revoke already-issued tokens; a
  client-credentials timing distinguisher; an org-admin key may revoke its
  sibling and parent keys; authorization codes are stored unhashed; minor
  metadata and audit-logging gaps; and an existing project grant's role set is
  adjustable by the project owner.

Follow-up (2026-10-27): **N13** was fixed — auto-provisioning now stores a
synthetic `idp-<hash>@idp.invalid` placeholder instead of an untrusted IdP email,
with regression tests for trusted/untrusted claims, no-squat and no-adoption.
**N20/F2** was decided as **owner self-service** (Option A): creating a grant to
another org stays instance-admin-only because it establishes a cross-tenant
relationship, while adjusting an existing grant's role set is the project owner
configuring its own project; the granted org and unrelated orgs cannot modify it,
and roles stay confined to the owning project — all enforced by `features_test.py`.

## Residual-risk register

| ID | Risk | Severity | Impact | Compensating control | Disposition / owner |
|----|------|----------|--------|----------------------|---------------------|
| N1 | Migration 0006 invalidates pending password-reset tokens and in-flight federation intents | Low | Short-lived disruption on upgrade; users retry | Documented in DEPLOYMENT.md; maintenance window | **Accepted** — intentional remediation effect. Owner: deployment owner / release manager. |
| N2 | No automatic down-migration | Low | A bad upgrade needs fix-and-retry or restore-from-backup | Per-migration atomicity + documented recovery procedure | **Accepted** — forward-only by design. Owner: platform/DBA. |
| D3 | A login-scoped API key can reset passwords / redeem logins for its users | Medium (by design) | A compromised login key enables account recovery for served users | Keys issued only to trusted operator backends; rotate on suspicion; audit trail | **Accepted** — documented trust assumption. Owner: operator / security owner. |
| GO-2026-5932 | `golang.org/x/crypto/openpgp` advisory in a required module | Informational | None reachable — IAM does not call openpgp; `govulncheck` reports code affected by 0 | govulncheck gate in CI; no fix available upstream (Fixed: N/A) | **Accepted (unreachable)** — revisit if a dependency starts calling openpgp. Owner: maintainer. |
| N4 | Entra accepts the MSA consumers GUID as a tenant | Informational | None — resolves to the real MSA directory (same as the `microsoft` preset) | Tenant-GUID validation; documented | **Accepted.** Owner: maintainer. |
| N5 | Preset scopes are caller-supplied | Informational | None — upstream provider rejects unsupported scopes | `validList` validation | **Accepted.** Owner: maintainer. |
| N6 | Generic-OIDC issuer has its trailing `/` trimmed (`api/orgs.go:268`) | Low (functional) | A provider whose canonical issuer ends in `/` (e.g. Auth0) fails `iss` strict-equality and login is refused — fails closed, no security impact; presets are unaffected (issuer pinned server-side) | Strict issuer equality is intentional; failure is closed, not a bypass | **Open — needs a live generic-OIDC provider that uses a trailing-slash issuer to verify any fix; not changed blind because it touches issuer equality.** Owner: maintainer. |
| N7 | Federated step-up is not enforced at the IdP: `prompt=login` / `max_age` are not forwarded, and `auth_time` is stamped from the engine's `IDPCheckedAt` | Low | A relying party's step-up demand can be satisfied by an existing IdP session with no fresh IdP interaction | Documented in PENTEST.md; a relying party needing hard step-up should require a local factor after SSO | **Accepted (documented).** Owner: maintainer. |
| N8 | TOTP failure counter (`mfa_failed_logins`) does not decay and is not cleared by a password success | Low | After a few bad TOTP guesses a later legitimate typo can trigger a 15-minute lockout | The sticky counter is an intentional TOTP brute-force bound; clearing it on password success would let a password holder reset the TOTP guess budget | **Accepted (intended).** Owner: maintainer. |
| N9 | `SafeIdPURL` is not re-checked in `HandleCallback` (endpoints are re-read from discovery) | Informational | A generic-OIDC org admin could aim a blind token-endpoint POST at any public https URL | The dial guard (`PublicAddress`), https-only transport, and body caps hold on every hop and redirect | **Accepted.** Owner: maintainer. |
| N10 | Rate limits key on the full IPv6 address, not a /64 | Low | A /64 holder can rotate addresses to evade IP-based limits | Per-account lockout and 256-bit secrets hold; `X-End-User-IP` is trusted only from login-API keys; `/idp/callback` needs a valid state | **Accepted (known).** Owner: maintainer. |
| N11 | The temporary failed-login lockout is account-wide; a password-guess lockout also delays a SSO/passkey user's mandatory TOTP second factor | Low (availability) | A known login name can be locked for ~15-min windows, delaying its TOTP step; SSO/passkey *admission* is already exempt | Lockout is temporary and bounded; manual unlock clears it | **Accepted (intended).** A per-factor split was prototyped and reverted because it weakened the tested anti-bypass that a TOTP lockout must also block the password/reset step; any change is an owner decision. Owner: maintainer. |
| N12 | The shared argon2 hashing pool can be saturated by one tenant (noisy neighbour) | Medium (availability) | Login latency degrades for all tenants under a crafted flood of hash operations | Per-key login (1200/min), per-IP, and per-key management limits bound the rate; non-GET work is time-bounded by server timeouts | **Accepted (known).** The mitigation (context-aware, bounded slot acquisition) needs load testing, which is not permitted on shared staging. Owner: maintainer. |
| N13 | Federated auto-provisioning could store an untrusted IdP email as the account identity | Low | (Was) same-org account squat, or a persistent SSO link to an account a victim may later adopt | Identity keyed on `(idp_id, sub)`; email linking needs instance `trust_email`; `auto_create_users` off by default | **Fixed (2026-10-27).** When the trust policy does not treat the IdP email as verified, auto-provisioning stores a synthetic `idp-<hash>@idp.invalid` placeholder instead of the claimed address, so an untrusted email never becomes a login identity, squats the real address, or becomes a reset/verification target (`authn/federation.go`). Existing accounts unchanged; no data migration. Regressions in `features_test.py` (trusted, untrusted, no-squat, no-adoption). Owner: maintainer. |
| N14 | A reused authorization code's already-issued tokens are not revoked (RFC 6749 §4.1.2 SHOULD) | Low | An intercepted-then-first-exchanged code is not retroactively detected | Code is single-use; PKCE and client authentication gate the exchange | **Accepted.** Owner: maintainer. |
| N15 | Client-credentials timing distinguishes an existing machine `client_id` from an absent one | Informational | Confirms a client_id exists; guessing is infeasible (128-bit IDs) | 128-bit client IDs; per-IP limit | **Accepted.** Owner: maintainer. |
| N16 | A compromised org-admin key can revoke its sibling and parent org keys (cascade) | Low | Denial of service on the org's own management plane; no cross-tenant effect | Keys reach only their own org; the instance admin re-issues; a key cannot delete itself | **Accepted (by design).** Owner: operator. |
| N17 | Authorization codes are stored as the op-crypto ciphertext, not hashed | Informational | A database/backup reader could redeem a still-live (≤5-min) code | PKCE / client secret still gate redemption; 5-minute TTL | **Accepted.** Hash-at-rest is a possible hardening. Owner: maintainer. |
| N18 | A granted org can read the project's `owner_org_id` | Informational | Minor cross-tenant metadata exposure | The grant is an intentional relationship between the two orgs | **Accepted.** Owner: maintainer. |
| N19 | Refused cross-tenant attempts are not separately audited; a trust-policy change does not end already-issued federated sessions | Informational | Reduced forensic signal; a trust downgrade applies only to new sessions (≤15-min TTL) | Refusals return 403/404; sessions are short-lived | **Accepted.** Owner: maintainer. |
| N20 | `updateProjectGrant` / `deleteProjectGrant` (owner path) require the project owner, while `createProjectGrant` requires an instance admin | Low (by design) | A vendor org adjusts the role set of an existing grant to its own project without instance-admin review | Roles confined to the owning project's defined roles; the granted org cannot modify its grant (403); an unrelated org cannot (404); creating a cross-org grant still needs an instance admin | **Accepted (Option A, 2026-10-27).** Deliberate: *creating* a grant establishes a cross-tenant relationship (operator-gated), while adjusting an *existing* grant's role set is the owner configuring its own project. Boundaries enforced by `features_test.py`. Owner: maintainer. |

Review this register whenever dependencies, migrations, or the trust model change.

## Automated security evidence

- **`govulncheck ./...`**: 0 reachable vulnerabilities (only GO-2026-5932, unreachable). Run in CI (`security` job) and verified locally.
- **gitleaks** (full history): 0 leaks. Run in CI (`security` job) and verified locally.
- CI also runs gofmt, `go vet`, build, `go test -race` against a disposable Postgres, and the smoke + feature suites against a booted engine.

## What source review does NOT establish

Source review and the offline/local test suites do **not** prove live-provider
behavior. The following require a controlled non-production environment with
dedicated test registrations (see ROADMAP.md): real Google / Microsoft-personal /
Entra round trips, live Entra cross-tenant rejection, and staging rehearsal of
migration recovery and backup restoration. Production remains **NO-GO** until
those are completed.
