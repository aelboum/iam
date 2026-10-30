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
| Authentication & account recovery | Credential stuffing, enumeration, reset-token abuse | Per-factor lockout (`internal/store/users.go:196-212`); unknown-user path matches real failure incl. hashing time (`internal/authn/authn.go:424`); reset tokens single-use/30 min, cooldown looks like unknown user (`internal/store/email.go:88-133`), invalidated on credential/lock change (M12); new passwords are checked against a breached/common-password denylist (`internal/authn/weakpasswords.go`, extendable via `IAM_WEAK_PASSWORD_FILE`); an org may require MFA for all its users (`PUT /v1/orgs/{id}/mfa-policy`), blocking a factorless login until enrolment (`mfa_enrollment_required`); single-use MFA backup codes (`mfa_recovery_codes`, stored only as HMAC hashes) can stand in for the second factor under the same lockout and rate limits. |
| Session & token lifecycle | Token replay, non-revocation | Opaque access tokens + refresh family; revoke by subject/org/app/project (`internal/store/oidc.go:206-248`); refresh rotation CAS (`:259-265`). |
| OIDC auth-code + PKCE | Code interception, CSRF | Standard auth-code with PKCE and state; engine-as-OP via zitadel/oidc `op`. The `state` CSRF token is echoed verbatim per RFC 6749 §10.12; binding it to the end user's browser session is the relying party's responsibility (see "Integrator responsibility" below). |
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

Follow-up (2026-10-27): **N11** was fixed with the corrected asymmetric design
(the earlier naive split had been reverted for breaking the anti-bypass): a new
`mfa_locked_until` column bounds TOTP guessing while `locked_until` bounds
password guessing; the password/reset path is blocked by *either* lockout
(anti-bypass preserved) and the TOTP step only by its own, so a password-guess
lockout no longer blocks a valid SSO user's second factor. Migration `0007`;
regressions in `store` (`TestPerFactorLockout`, incl. a concurrency row) and
`features_test.py`. **N13** was fixed — auto-provisioning now stores a
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
| N10 | Rate limits key on the full IPv6 address, not a /64 | Low | A /64 holder can rotate addresses to evade IP-based limits | Per-account lockout and 256-bit secrets hold; `X-End-User-IP` is trusted only from login-API keys; `/idp/callback` needs a valid state | **Fixed (2026-10-30, PR #25).** `limiterKey` now collapses an IPv6 source to its /64 prefix before bucketing (IPv4 keeps its full address); the same PR also extended per-IP coverage to every public provider endpoint. Regressions `TestLimiterKeyCollapsesIPv6To64` / `TestOAuthLimiterSharesIPv6Slash64Bucket`. Owner: maintainer. |
| N11 | A password-guess lockout used to also block a valid SSO user's mandatory TOTP second factor (shared `locked_until`) | Low (availability) | (Was) a known login name could delay its own post-SSO TOTP step for ~15-min windows | Per-factor lockout; manual unlock clears both | **Fixed (2026-10-27, Option A).** `locked_until` bounds password guessing, `mfa_locked_until` bounds TOTP; the password/reset path is blocked by either lockout (anti-bypass preserved), the TOTP step only by its own. Migration `0007`; regressions `store.TestPerFactorLockout` + `features_test.py`. Owner: maintainer. |
| N12 | The shared argon2 hashing pool can be saturated by one tenant (noisy neighbour) | Medium (availability) | Login latency degrades for all tenants under a crafted flood of hash operations | Per-key login (1200/min), per-IP, and per-key management limits bound the rate; non-GET work is time-bounded by server timeouts | **Accepted (known).** The mitigation (context-aware, bounded slot acquisition) needs load testing, which is not permitted on shared staging. Owner: maintainer. |
| N13 | Federated auto-provisioning could store an untrusted IdP email as the account identity | Low | (Was) same-org account squat, or a persistent SSO link to an account a victim may later adopt | Identity keyed on `(idp_id, sub)`; email linking needs instance `trust_email`; `auto_create_users` off by default | **Fixed (2026-10-27).** When the trust policy does not treat the IdP email as verified, auto-provisioning stores a synthetic `idp-<hash>@idp.invalid` placeholder instead of the claimed address, so an untrusted email never becomes a login identity, squats the real address, or becomes a reset/verification target (`authn/federation.go`). Existing accounts unchanged; no data migration. Regressions in `features_test.py` (trusted, untrusted, no-squat, no-adoption). Owner: maintainer. |
| N14 | A reused authorization code's already-issued tokens are not revoked (RFC 6749 §4.1.2 SHOULD) | Low | An intercepted-then-first-exchanged code is not retroactively detected | Code is single-use; PKCE and client authentication gate the exchange | **Accepted.** Owner: maintainer. |
| N15 | Client-credentials timing distinguishes an existing machine `client_id` from an absent one | Informational | Confirms a client_id exists; guessing is infeasible (128-bit IDs) | 128-bit client IDs; per-IP limit | **Accepted.** Owner: maintainer. |
| N16 | A compromised org-admin key can revoke its sibling and parent org keys (cascade) | Low | Denial of service on the org's own management plane; no cross-tenant effect | Keys reach only their own org; the instance admin re-issues; a key cannot delete itself | **Accepted (by design).** Owner: operator. |
| N17 | Authorization codes are stored as the op-crypto ciphertext, not hashed | Informational | A database/backup reader could redeem a still-live (≤5-min) code | PKCE / client secret still gate redemption; 5-minute TTL | **Fixed (2026-10-30, PR #27).** Codes are now stored as the SHA-256 of the op-crypto ciphertext, so a table reader who also holds the master key cannot recover a redeemable code. Regression `TestAuthCodeStoredHashedAtRest`. Owner: maintainer. |
| N18 | A granted org can read the project's `owner_org_id` | Informational | Minor cross-tenant metadata exposure | The grant is an intentional relationship between the two orgs | **Accepted.** Owner: maintainer. |
| N19 | Refused cross-tenant attempts are not separately audited; a trust-policy change does not end already-issued federated sessions | Informational | Reduced forensic signal; a trust downgrade applies only to new sessions (≤15-min TTL) | Refusals return 403/404; sessions are short-lived | **Accepted.** Owner: maintainer. |
| N20 | `updateProjectGrant` / `deleteProjectGrant` (owner path) require the project owner, while `createProjectGrant` requires an instance admin | Low (by design) | A vendor org adjusts the role set of an existing grant to its own project without instance-admin review | Roles confined to the owning project's defined roles; the granted org cannot modify its grant (403); an unrelated org cannot (404); creating a cross-org grant still needs an instance admin | **Accepted (Option A, 2026-10-27).** Deliberate: *creating* a grant establishes a cross-tenant relationship (operator-gated), while adjusting an *existing* grant's role set is the owner configuring its own project. Boundaries enforced by `features_test.py`. Owner: maintainer. |
| N21 | The periodic purge sequentially scanned six hot tables (no `expires_at` index) and `audit_events.at`; one failing table aborted the whole loop | Medium (availability) | Seconds of I/O every 10 min on the tables that grow fastest, on the same disks that serve logins | — | **Fixed (2026-10-29).** Migration `0008` adds the indexes and drops the superseded `users_org_id_username_key`; `PurgeExpired` continues past a failing table. Measured 133 ms → 31 ms at 200k rows, now proportional to expired rows. Owner: maintainer. |
| N22 | Token, introspection, revocation and userinfo responses were cacheable (RFC 6749 §5.1 MUST) | Medium | A shared/browser cache can serve a token response after revocation | — | **Fixed (2026-10-29).** `noStore` middleware on exactly those paths. Owner: maintainer. |
| N23 | TOTP enrollment codes were verifiable without any attempt cap | Low | A management key could brute-force a six-digit pending code and activate TOTP on a user whose secret nobody holds, locking them out of the second factor | — | **Fixed (2026-10-29).** Five attempts per enrollment (`users.totp_enroll_attempts`, reset on re-enroll), then 429. Owner: maintainer. |
| N24 | No CORS at all: `OPTIONS` returned 405, so no browser SPA could call the API | Low (functional) | Browser-based integrators had to proxy | — | **Fixed (2026-10-29).** Opt-in `IAM_CORS_ORIGINS` (exact origins, https outside dev mode) + 204 preflight. Owner: maintainer. |
| N25 | `userinfo` answers 403 with an empty body once the token is revoked, not 401 `invalid_token` | Low | Integrators that branch on 401 mis-handle revocation | Library behaviour; the token is refused either way | **Accepted.** Documented in the assessment report. Owner: maintainer. |
| N26 | Quota checks are check-then-insert, so a concurrent burst can exceed a cap by a few rows | Low | Marginal over-quota, no security effect | Caps are 100k users / 100 projects / 50 keys / 50 apps / 200 roles / 10 IdPs | **Accepted.** Owner: maintainer. |
| N27 | `/healthz` is unauthenticated, unthrottled and pings the database | Low | A flood consumes pool connections | Cheap query; container healthchecks are low-rate | **Accepted.** Owner: operator. |
| N28 | `sessions.user_id::text` cast defeated the index on every credential change, lock, logout and delete | Medium (availability) | Full scan of `sessions`/`password_resets` per operation | — | **Fixed (2026-10-29).** Compared as `$1::uuid`; indexes added. Owner: maintainer. |
| CRYPTO-06 | `secret.Derive` uses `SHA-256(master ‖ purpose)` rather than HKDF | Informational | None. The construction is sound for a uniformly-random 32-byte secret master: the purpose label gives domain separation, and a secret-keyed hash truncated to 32 bytes is not length-extensible in any way an attacker can use | HKDF would be a standards-alignment change only; switching the derivation would re-key all derived material (the at-rest `Box`, the email-code HMAC, the op-crypto key) and so would need a backward-compatibility path for existing sealed data | **Accepted (2026-10-30, owner decision).** HKDF not adopted: the marginal hygiene benefit does not justify a breaking change to the key-derivation root of a pre-release system. Revisit if the master key ever stops being uniformly random, or if a future consumer needs HKDF's extract-then-expand. Owner: aelboum (repository owner). |
| W1 | Independent external penetration test (readiness criterion 12) not performed | High (process) | No independent third party has adversarially tested the running system; classes of authentication, tenant-isolation and OAuth/OIDC flaws that internal code review and automated tooling can miss may remain undetected in production | Three internal code reviews (none open above Low), AI-assisted reviews, static analysis, `govulncheck`, `gitleaks`, and CI (`test`/`-race`/`e2e`/`security`) — explicitly **not** equivalent to an independent external penetration test | **Accepted — WAIVED by owner (2026-10-28).** Criterion 12 remains **NOT PERFORMED**; the owner has deliberately accepted the risk of releasing without an independent external test. This is a waiver, not a pass. See the "Waived gate" subsection below. Owner: aelboum (repository owner / operator). |

Review this register whenever dependencies, migrations, or the trust model change.

## Waived gate — independent external penetration test (criterion 12)

The owner has elected **not** to commission an independent external penetration
test and to **waive** production-readiness criterion 12 (see ROADMAP.md),
formally accepting the associated risk.

- **Decision.** Release may proceed without an independent external penetration
  test. Criterion 12 is recorded as **NOT PERFORMED — WAIVED**; it is *not*
  marked passed, and nothing in this repository represents internal or automated
  testing as equivalent to an independent external test.
- **Decision owner / date.** aelboum (repository owner / operator), 2026-10-28.
- **Residual risk accepted (register W1).** No independent third party has
  adversarially tested the running system. Internal code review and automated
  tooling can miss whole classes of findings — authentication and lockout
  bypasses, cross-tenant access, OAuth/OIDC code/redirect/token handling,
  federation and SSRF, and business-logic flaws — that an independent tester is
  more likely to surface. These may remain undetected in production. The risk is
  heightened because IAM is intended to replace an established identity provider
  for live tenants.
- **Compensating controls (not a substitute).** Three internal code reviews with
  no finding open above Low, AI-assisted reviews, static analysis, `govulncheck`
  and `gitleaks`, and CI (`test` incl. `-race`, `e2e`, `security`). An optional
  internal AI-pentest tool may be run against a disposable target as additional
  internal assurance; it is likewise **not** equivalent to an independent test.
- **Re-evaluation triggers.** Revisit this waiver — i.e. reconsider commissioning
  an independent external test — before widening scope (for example adding
  personal-Microsoft-account support), on any material change to the
  authentication, tenant-isolation, token, or federation code, or after a
  security incident.

This waiver removes the *external-testing* blocker by the owner's acceptance of
risk; it does not by itself authorize release. Production stays **NO-GO** until
the owner **explicitly authorizes release** and the deploy-time hardening
follow-ups ([DEPLOY_HARDENING.md](DEPLOY_HARDENING.md)) are applied.

## Integrator responsibility — OAuth `state` and login CSRF

IAM is the OpenID Provider (OP). In the authorization-code flow the `state`
parameter is the **relying party's** CSRF defence: the client generates it,
binds it to the end user's browser session, and verifies it on the callback.
Per RFC 6749 §10.12 the OP echoes `state` back unchanged and does not bind it to
a browser session of its own — provider-side binding is neither required nor
sufficient for the client's CSRF protection. Relying parties integrating with
IAM **must** implement their own `state` (or PKCE) session binding and reject
callbacks whose `state` does not match the one stored for that browser session.

This split is deliberate and standard, and differs from federation, where IAM is
itself the relying party to an upstream IdP and therefore *does* bind the flow
to the browser (`browserBinding`, `internal/authn/federation.go`; see the
Federation row above). An internal assurance review (2026-10-29) flagged the
OP's lack of provider-side `state` binding; on review it was confirmed to be by
design per the responsibility split above, not a defect.

## Automated security evidence

- **`govulncheck ./...`**: 0 vulnerabilities, after the toolchain was pinned to
  Go 1.27.3 (`toolchain` directive + pinned build image). At the assessed commit
  the module pinned Go 1.26.10 and 12 standard-library vulnerabilities were
  reachable (GO-2026-6599/6600/6603/6605/6607/6608/6610/6611/6612/6613/6617/6809).
- **gitleaks** (full history): 0 leaks. Run in CI (`security` job) and verified locally.
- **`gosec -severity medium`**: 0 issues, with five `#nosec` suppressions that
  each carry a written justification (three G101 SQL column lists, G704 on the
  operator-set healthcheck address, G710 on the validated federation redirect).
  Run in CI.
- **`staticcheck`**: clean. Run in CI.
- CI also runs gofmt, `go vet`, build, `go test -race` against a disposable Postgres, and the smoke + feature suites against a booted engine.

## Independent assessment (2026-10-29)

A full-source, tool-assisted and dynamic assessment of `origin/main` `69015ac`
was performed on branch `security/assessment-2026-10-29`; the report, evidence
and re-test output are in
[SECURITY_ASSESSMENT_2026-10-29.md](SECURITY_ASSESSMENT_2026-10-29.md).

It found **no Critical or High** issue, three Medium and fourteen Low, and
remediated every Medium and Low in the same branch with regression tests. The
Medium findings were operational rather than exploitable: unindexed expiry
purges (six hot tables sequentially scanned every ten minutes), a `user_id::text`
cast that defeated the index on every credential change, and token responses
that were cacheable (RFC 6749 §5.1). Low findings covered missing CSP/CORS,
an uncapped TOTP enrollment code, body-limit and JSON-trailing-data handling,
an unthrottled `/userinfo`, a dotless-email inconsistency, a `uint64 → int`
narrowing, a bootstrap-marker ordering bug, IdP deletion leaving sessions alive,
and a per-request `last_used_at` write. Twelve reachable standard-library
vulnerabilities were also closed by pinning the toolchain.

Register rows added: **N21** (purge/index gaps), **N22** (cacheable token
responses), **N23** (uncapped TOTP enrollment), **N24** (no CORS), **N25**
(`userinfo` 403 after revocation), **N26** (quota check-then-insert race),
**N27** (`/healthz` unthrottled). N21–N24 are fixed; N25–N27 are accepted with
the compensating controls noted in the report.

## What source review does NOT establish

Source review and the offline/local test suites do **not** prove live-provider
behavior. The following require a controlled non-production environment with
dedicated test registrations (see ROADMAP.md): real Google / Microsoft-personal /
Entra round trips, live Entra cross-tenant rejection, and staging rehearsal of
migration recovery and backup restoration. Production remains **NO-GO** until
those are completed.
