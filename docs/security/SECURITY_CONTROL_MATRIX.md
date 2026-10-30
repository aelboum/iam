# IAM — Security Control Matrix

**Type:** Internal control inventory with verification status and framework mapping (read-only assessment). **Not** an independent penetration test.
**Date:** 2026-10-30. **Code baseline:** `origin/main` `323075c` (== HEAD `c246fe3` code tree).
Companion to `ARCHITECTURE_GAP_ASSESSMENT.md`, `ATTACK_PATH_ANALYSIS.md`, `SECURITY_MATURITY_ASSESSMENT.md`, `SECURITY_REMEDIATION_ROADMAP.md`.

## Status legend and the verification bar

| Code | Meaning |
|------|---------|
| **IV** | IMPLEMENTED AND VERIFIED — code exists **and** evidence (a test that asserts the property, or a live probe recorded in the audits) demonstrates the security property holds. |
| **IU** | IMPLEMENTED BUT INSUFFICIENTLY VERIFIED — code exists; no test/probe proves the property, or the only proof is offline where live behaviour matters. |
| **PI** | PARTIALLY IMPLEMENTED — the control exists for some paths/conditions but not all. |
| **M** | MISSING. |
| **NA** | NOT APPLICABLE to this architecture. |
| **BME** | BLOCKED BY MISSING EVIDENCE — cannot be assessed without an action outside the read-only boundary (live-provider round trip, load test, external pentest). |

**Bar for IV:** code presence alone is never IV. Line-number citations inherited from `INTERNAL_SECURITY_AUDIT.md` are as-of `2f78ab6`; citations marked **(tip)** were re-read this session on `323075c`. Priority codes (P0–P3) map to `SECURITY_REMEDIATION_ROADMAP.md`.

---

## 1. Control inventory

Each control: **ID · requirement · implementation (evidence) · tests · status · gap · attack scenario · risk · recommended improvement · regression test · priority · dependencies.**

### Authentication (AUTHN)

**AUTHN-01 — Phishing-resistant MFA (WebAuthn/passkeys).**
Impl: registration/login with challenge expiry, counter-must-grow CAS, clone-reject, no credential-ID disclosure (`authn/passkeys.go`; `store/passkeys.go`); RP settings validated at boot. Tests: `authn/factor_invariants_test.go`, passkey counter CAS + clone-reject regressions, `features_test.py`. **Status: IV.** Gap: none material. Attack: passkey clone/replay → rejected by counter CAS. Risk: Low. Improvement: optional attestation-policy enforcement. Priority: —.

**AUTHN-02 — Password hashing argon2id with resource limits.**
Impl: `zitadel/passwap` argon2id; hashing-pool sizing guard (`sizing.go`) cgroup-CPU-aware; `mem_limit` now set in prod/staging compose **(tip)**. Tests: `sizing/sizing_test.go`. **Status: IV** (algorithm/sizing) / **IU** (load behaviour). Gap: pool saturation unmeasured (N12). Attack: hash flood → latency for all tenants (now bounded by `mem_limit`). Risk: Medium availability. Improvement: load test; explicit `IAM_HASH_SLOTS` to fit the limit; compose-lint CI. Regression: compose-limit lint. Priority: P2. Deps: capacity budget.

**AUTHN-03 — TOTP second factor with brute-force bound.**
Impl: per-factor lockout `mfa_locked_until` separate from `locked_until`, anti-bypass preserved; enrollment capped at 5 attempts (N23, migration 0008). Tests: `store` `TestPerFactorLockout` (+ concurrency row), `features_test.py`. **Status: IV.** Gap: sticky counter (N8, accepted). Risk: Low. Priority: —.

**AUTHN-04 — MFA enrollment protection + org enforcement.**
Impl: org `mfa_required` blocks factorless login until enrolment (`mfa_enrollment_required`, migration 0009) **(tip)**; TOTP enroll cap (N23). Tests: `features_test.py`. **Status: IU** (code + tip migration verified; focused unit assertion of the gate state-machine across entry paths not confirmed this session). Attack: factorless login against an MFA-required org → blocked. Risk: Low. Improvement: handler test asserting the gate across password/passkey/federated entry. Priority: P2.

**AUTHN-05 — MFA recovery/backup codes.**
Impl: single-use codes stored **only as HMAC hashes**; `sessions.recovery_code_checked_at` satisfies the 2nd factor; migration 0010; `store/recovery_codes.go` **(tip)**. Tests: `store/recovery_codes_test.go` **(tip)**. **Status: IV** (hashing + single-use). Gap: confirm recovery-code attempts share lockout/rate limits (SECURITY.md claims they do). Attack: recovery-code brute force → must be under lockout. Risk: Low. Improvement: assert lockout/rate parity. Regression: recovery-code lockout test. Priority: P2.

**AUTHN-06 — Breached/common-password denylist.**
Impl: new passwords checked against a denylist, extendable via `IAM_WEAK_PASSWORD_FILE` (`authn/weakpasswords.go`) **(tip)**. Tests: `authn/weakpasswords_test.go` **(tip)**. **Status: IV.** Gap: built-in list size is a policy choice; no HIBP k-anonymity range check. Risk: Low. Improvement: wire a larger curated list at deploy. Priority: —.

**AUTHN-07 — Enumeration resistance + uniform failure.**
Impl: unknown-user path matches real failure incl. hashing time (`authn/authn.go`); reset cooldown looks like unknown user (`store/email.go`); foreign user id → 404. Tests: store/authn layer; **handler-level 404-on-foreign-user is a noted gap (audit §15).** **Status: IV** (store/authn) / **PI** (handler layer). Attack: timing/response enumeration → uniform. Risk: Low. Improvement: handler test. Priority: P3.

**AUTHN-08 — Session/token invalidation after sensitive change.**
Impl: `setPassword`/`lockUser`/`deleteUser` call `RevokeUserTokens` + `DeleteUserSessions`; reset tokens invalidated on credential/lock change. Tests: `grant_revocation_test.go`, `password_reset_lockout_test.go`. **Status: IV** (those paths). Gap: **`removeTOTP`/`deletePasskey` clear sessions but not tokens (L-03); `DeleteIDP` clears sessions not tokens (L-02).** Attack: stolen refresh token survives a factor/IdP removal meant to contain it. Risk: Low (5-min access TTL). Improvement: add `RevokeUserTokens` to those paths. Regression: mirror `TestSetPasswordHandlerRevokesOnlyTargetUser` for TOTP/passkey/IdP delete. Priority: P3.

**AUTHN-09 — Step-up authentication.**
Impl: none at the IdP; `prompt=login`/`max_age` not forwarded; `auth_time` from engine (N7). **Status: PI/M.** Attack: an RP step-up demand satisfied by an existing IdP session. Risk: Low (documented). Improvement: forward `prompt`/`max_age`, or document "require a local factor after SSO". Priority: P3.

**AUTHN-10 — Secure account recovery.**
Impl: reset tokens single-use/30 min, cooldown, invalidated on credential/lock change (`store/email.go`); reset does not bypass lockout (`password_reset_lockout_test.go`). **Status: IV.** Risk: Low. Priority: —.

### Authorization (AUTHZ)

**AUTHZ-01 — Default-deny + central gate.**
Impl: `requireAPIKey` router-wide on `/v1`; `requireAdminScope` on management; login-scope keys limited to session API (`api/api.go`, `api/sessions.go`). Tests: audit §9 coverage matrix (13-route live cross-tenant probe), `tenant_isolation_test.go`. **Status: IV.** Risk: Low. Priority: —.

**AUTHZ-02 — Tenant/org isolation.**
Impl: every store method takes the owner id; object routes `userForCaller`/`projectForOwner`/`projectForReader` → 404/403; machine scope one project. Tests: `store/tenant_isolation_test.go`, `authn/tenant_isolation_test.go`, live 13-route probe. **Status: IV** (application layer). Gap: **no RLS** — one missed `WHERE org_id` leaks cross-tenant. Attack: future store method omits the owner predicate → cross-tenant read/write. Risk: Medium (latent, test-gated). Improvement: RLS defense-in-depth, or a review/lint gate requiring an owner predicate. Regression: RLS policy tests. Priority: P2. Deps: schema policy design.

**AUTHZ-03 — Ownership / privilege-escalation prevention.**
Impl: foreign object 404 / container 403; `createProjectGrant` instance-admin-only; child key cannot outlive parent; key cannot self-delete (N16/N20 dispositioned). Tests: `features_test.py`, `grant_revocation_test.go`. **Status: IV.** Risk: Low. Priority: —.

**AUTHZ-04 — Fine-grained API-key scopes.**
Impl: admin vs login scope; org vs instance keys; parent-bounded expiry. Tests: `features_test.py`, audit §9. **Status: IV.** Gap: org-admin key can revoke sibling/parent keys (N16, accepted — same-org DoS). Risk: Low. Priority: —.

**AUTHZ-05 — Consistent revocation / no stale authz cache.**
Impl: grant removal revokes tokens; **authorization never cached — every check hits the DB** (no stale window); revoke by subject/org/app/project (`store/oidc.go:206-248`). Tests: `grant_revocation_test.go`. **Status: IV.** Attack: stale-cache privilege retention → NA. Risk: Low. Priority: —.

**AUTHZ-06 — Central policy engine / ABAC.**
Impl: none (per-handler RBAC). **Status: M (by design).** Risk: Low for first-party RBAC. Improvement: **not recommended** unless multi-product policy complexity grows (would add complexity). Priority: P3 (optional).

### OAuth/OIDC (OIDC)

**OIDC-01 — Auth-code + PKCE S256 for every interactive client.**
Impl: `plain` refused, S256 required, empty challenge rejected (`oidcop/storage.go:68-78` **(tip)**); code claimed only after PKCE + client auth. Tests: `oidcop` refresh/reuse tests; `features_test.py`. **Status: IV.** Attack: code interception without verifier → cannot redeem. Risk: Low. Priority: —.

**OIDC-02 — Exact redirect-URI + post-logout-URI validation.**
Impl: validated against the registered list by the library; presets server-side. **Status: IV** (library) / **IU** (no negative test asserted here). Improvement: negative redirect-URI test. Priority: P3.

**OIDC-03 — Refresh rotation + reuse detection.**
Impl: single `UPDATE … WHERE used_at IS NULL` CAS; reuse revokes family + audits (`oidcop/storage.go:256-284`). Tests: `oidcop/refresh_reuse_test.go`. **Status: IV.** Risk: Low. Priority: —.

**OIDC-04 — Revocation + introspection.**
Impl: `/revoke` (RFC 7009) client/family-scoped; introspection scoped to caller's project; `no-store` (N22). Tests: `revocation_test.go`, `introspection_test.go`, `machine_introspection_test.go`. **Status: IV.** Priority: —.

**OIDC-05 — Issuer/audience validation + signing-alg restriction.**
Impl: `op.StaticIssuer` pins issuer; RS256 only. Tests: offline. **Status: IV** (issuer) / **IU** (alg-confusion negative test not asserted). Improvement: negative test rejecting non-RS256 / `alg=none`. Priority: P3.

**OIDC-06 — `response_mode=form_post`.** *(M-01)*
Impl: stored and honoured, but the **global CSP breaks the auto-submit and cross-origin form** (`cmd/iamd/main.go:388`, router-wide `:192`, provider `/` `:210` **(tip)**). Tests: `headers_test.go` asserts the CSP string, **not** that OP HTML works under it. **Status: PI (broken).** Attack: RP using `form_post` gets a blank page; fallback to `query` re-exposes code-in-URL/`Referer`. Risk: Medium (functional). Improvement: scope a relaxed CSP (`script-src` for inline submit; `form-action` covering redirect origins) to OP HTML responses only. Regression: boot + `form_post` flow asserts a working CSP on the callback. Priority: **P2 (highest confirmed open item).** Deps: none.

**OIDC-07 — `end_session` / logout semantics.** *(L-01)*
Impl: `id_token_hint` logout works; **hint-less `end_session` revokes nothing** (`oidcop/storage.go` `TerminateSession`). Tests: **none for `end_session`.** **Status: PI.** Attack: false sense of logout; token valid ≤5 min on a shared machine. Risk: Low. Improvement: require `id_token_hint` or implement `CanTerminateSessionFromRequest`. Regression: hint-less logout → `/userinfo` fails. Priority: P3.

**OIDC-08 — Discovery honesty.** *(L-04)*
Impl: advertises `id_token`/`id_token token` + `jwt-bearer` that are stubs. **Status: PI.** Attack: integrator builds a non-working flow (fails closed). Risk: Low. Improvement: implement or stop advertising. Regression: every advertised `response_type` accepted. Priority: P3.

**OIDC-09 — Login CSRF / `state`.**
Impl: OP echoes `state`; binding is the RP's responsibility per RFC 6749 §10.12 (SECURITY.md). **Status: NA (RP responsibility)** + a documentation control the platform owns. Improvement: keep the integrator note prominent. Priority: —.

**OIDC-10 — Sender-constrained tokens (DPoP/mTLS).**
Impl: none; opaque bearer. **Status: M (optional).** Attack: stolen bearer usable anywhere until revoked. Risk: Low–Medium. Improvement: consider DPoP if cross-SaaS blast-radius grows. Priority: P3 (optional).

### Federation (FED)

**FED-01 — Browser-bound federation flow.**
Impl: 256-bit state/nonce/PKCE; state hashed + burned on claim; intent burned even on mismatch; redemption requires browser cookie (`authn/federation.go`). Tests: `federation_session_preserve_test.go`, `federation_test.go`. **Status: IV** (offline). Attack: login-CSRF / intent replay → blocked. Risk: Low. Priority: —.

**FED-02 — Identity keyed on `(idp_id, sub)`; trust-gated linking.**
Impl: `(idp_id, sub)`; email link needs instance `trust_email`+`link_by_email`; untrusted email → `idp-<hash>@idp.invalid` (N13). Tests: `features_test.py` (trusted/untrusted/no-squat/no-adoption). **Status: IV.** Attack: email-based takeover/squat → blocked. Risk: Low. Priority: —.

**FED-03 — Server-pinned preset issuers; Entra tenant GUID.**
Impl: issuers server-side; Entra pinned to tenant GUID (`authn/providers.go:91-95`). Tests: offline; live cross-tenant reported 2026-10-26 (not repeated). **Status: IU / BME** (no live Entra round trip). Attack: provider substitution / cross-tenant token → rejected by strict `iss`. Risk: Low offline, unproven live. Improvement: live Entra cross-tenant re-test in controlled non-prod. Priority: P2. Deps: test IdP registrations.

**FED-04 — Outbound SSRF guard.**
Impl: `SafeIdPURL` on authorize + discovery; dial guard `PublicAddress` (post-DNS), https-only, 1 MiB cap, ≤3 redirects. Tests: `TestPublicAddress`, `TestSafeIdPURL`. **Status: IV.** Gap: not re-run in `HandleCallback` (N9). Risk: Informational. Priority: P3.

**FED-05 — Containment on IdP delete.** *(L-02)*
Impl: `DeleteIDP` deletes sessions, **not tokens** (`store/idp.go:100-116`). **Status: PI.** Attack: removing a compromised IdP leaves refresh tokens minting access. Risk: Low. Improvement: revoke linked users' tokens in-transaction. Regression: extend `TestDeleteIDPRevokesLinkedSessions` to tokens. Priority: P3.

### Session/token (SESS)

**SESS-01 — Entropy/rotation/expiry.** Impl: 256-bit tokens; refresh rotation CAS; access ~5 min / refresh 7 d idle, 30 d absolute. Tests: `token_lifecycle_test.go`. **Status: IV.** Priority: —.

**SESS-02 — Token hashing at rest.** Impl: `token_hash`/`key_hash`/`state_hash`/recovery-code HMAC-hashed; **auth codes stored as ciphertext, not hashed (N17)**. **Status: PI.** Attack: DB/backup reader redeems a live ≤5-min code. Risk: Informational. Improvement: hash codes at rest. Priority: P3.

**SESS-03 — Cross-application token containment.** Impl: project-scoped introspection; per-app/project revocation; machine scope one project. Tests: `machine_scope_contract_test.go`, `delete_access_token_test.go`. **Status: IV.** Risk: Low. Priority: —.

### Crypto/keys (CRYPTO)

**CRYPTO-01 — Standard primitives, no custom crypto.** Impl: AES-256-GCM, RS256, SHA-256, HMAC-SHA256, argon2id, `crypto/rand`, constant-time compare (`secret/secret.go`). Tests: `secret_test.go`. **Status: IV.** Priority: —.

**CRYPTO-02 — Secret encryption at rest + master-key rotation.** Impl: `Box` seals TOTP secrets, IdP client secrets, signing keys, PKCE verifiers, auth codes; multi-key open; `rotate-keys` re-encrypt, `--check` read-only. Tests: `rotation_test.py`, `secret_test.go`. **Status: IV.** Priority: —.

**CRYPTO-03 — Signing-key lifecycle.** Impl: RSA-2048, interval rotation + publish-lead overlap, advisory-lock serialised (`oidcop/keys.go`). Tests: `oidcop` key tests. **Status: IV** (rotation). Priority: —.

**CRYPTO-04 — External KMS/HSM + signing-key isolation.** Impl: **none** — master key is env var (`.env.prod` on disk); signing keys decrypted into process memory; no HSM/KMS signing; no key-mgmt privilege separation. **Status: M.** Attack: host/memory/`.env` compromise → master key → all sealed secrets + signing keys → forge any token. Risk: **High if realised** (single root of trust). Improvement: external KMS/HSM for the master key (envelope) and ideally signing (sign-via-KMS); isolate the signer. Regression: KMS-backed seal/open + sign tests. Priority: **P1** (architecture) / deploy-dependent. Deps: KMS choice.

**CRYPTO-05 — Emergency key revocation.** Impl: **none** — a compromised signing key stays in JWKS until time-based `ExpiresAt`. **Status: M.** Attack: a leaked signing key keeps verifying forged tokens until expiry. Risk: Medium. Improvement: a "revoke key now" path that drops it from JWKS and forces re-sign. Regression: revoke-key removes it from `/keys`. Priority: P2.

**CRYPTO-06 — KDF.** Impl: `Derive = SHA-256(master||purpose)`. **Status: PI** (adequate, non-standard). Improvement: HKDF-SHA256. Priority: P3.

### Database/tenant (DB)

**DB-01 — SQL-injection safety.** Impl: all queries parameterised; fixed-identifier concatenation only; no `Sprintf` into SQL. Tests: `gosec` gate + store tests. **Status: IV.** Priority: —.

**DB-02 — Migration integrity.** Impl: forward-only, per-migration transactional, advisory-lock serialised, cancellable (`db/db.go`). Tests: `migrate_lockcancel_test.go`, `TestMigrateConcurrent`, `migration_rehearsal.sh`. **Status: IV.** Gap: duplicate `0007_` prefix (I-01); no down-migration (N2). Priority: P3.

**DB-03 — DB TLS + least privilege.** Impl: `sslmode=disable` on compose network; **production plaintext-DB-URL warning (tip, PR #16)**; single app DB role. **Status: PI** (warning only; TLS a deploy follow-up). Attack: on-network DB sniff; compromised app role has full DB rights. Risk: Medium (deploy-dependent). Improvement: `sslmode=verify-full` in prod; least-privilege roles. Regression: config rejects plaintext DB URL in prod. Priority: P2 (deploy).

**DB-04 — Row-Level Security.** Impl: **none.** **Status: M.** (See AUTHZ-02.) Priority: P2.

**DB-05 — Backup/restore + encryption.** Impl: restore rehearsed (EXTERNAL_VALIDATION §4); **backup encryption is a placeholder (I-08).** **Status: PI** (restore IV; encryption M). Risk: Medium (dump holds sealed secrets + context). Improvement: mandate encrypted, access-controlled backups + retention. Priority: P2 (deploy).

### Abuse/availability (ABUSE)

**ABUSE-01 — Multi-level rate limiting, never fail-open.** Impl: shared PG limiter, local-first, fallback-to-local on DB error; per-key/-IP/-client; canonical IP key (`api/api.go`). Tests: `ratelimit_test.go` (fallback), `TestClientIPCanonical`. **Status: IV.** Gap: `/end_session`/`/keys`/discovery/`/device_authorization` unlimited (I-05); IPv6 full-address keying (N10). Risk: Low. Improvement: add those paths; key IPv6 on /64. Regression: limiter-map coverage test. Priority: P3.

**ABUSE-02 — Argon2 resource exhaustion / noisy neighbour.** (See AUTHN-02 / N12.) **Status: IU.** Priority: P2 (load test). Deps: non-shared load env.

**ABUSE-03 — Request-size / body limits.** Impl: 413 via `MaxBytesReader`, trailing-JSON rejected (`api/decode.go`). Tests: `decode_test.go`. **Status: IV.** Priority: —.

**ABUSE-04 — Per-tenant DoS isolation.** Impl: per-key limits bound rate, but shared argon2 pool + shared DB let one tenant degrade others. **Status: PI.** Risk: Medium availability. Improvement: per-tenant resource ceilings / separate hash budget. Priority: P2/P3.

### Monitoring/IR (MON)

**MON-01 — Central audit events.** Impl: logins, lockouts, trust/issuer/provider changes, revocations (`store`, `authn.go`, `orgs.go`); `GET /v1/audit` instance-admin. Tests: `assessment_test.go`, handler tests. **Status: IV** (capture). Priority: —.

**MON-02 — Audit integrity / tamper resistance.** Impl: **none** — no hash chain/append-only grant; `Store.Audit` swallows write failures (I-04). **Status: M.** Attack: DB-level actor rewrites history; transient failure drops an event. Risk: Medium (forensic). Improvement: hash-chain or append-only grant + surface write failures. Regression: tamper-detection test; write-failure surfaced. Priority: **P2.** Deps: schema change (out of this phase).

**MON-03 — Detection / anomaly / alerting.** Impl: **none** — events recorded, nothing watches them; no login-anomaly, suspicious-session, privilege-change, API-key-abuse, token-reuse, signing-key-change alerts. **Status: M.** Attack: incident proceeds unnoticed. Risk: Medium–High. Improvement: log shipping + SIEM/alert rules on the existing events. Priority: **P2/P3** (deploy + rules). Deps: monitoring stack.

**MON-04 — Incident-response procedures.** Impl: `OPERATIONS.md`/`DEPLOYMENT.md` (IR, recovery, emergency session invalidation via revoke APIs, key rotation). **Status: IV** (documented). Gap: emergency **key** revocation path missing (CRYPTO-05). Priority: P2.

### Infrastructure (INFRA)

**INFRA-01 — Container hardening.** Impl: `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, distroless nonroot, binary healthcheck, `mem_limit` **(tip)**. **Status: IV** (config-derived) / **IU** (no running deployment observed). Gap: Postgres container unhardened (L-06); no `tmpfs:/tmp` (I-07). Improvement: harden Postgres service; add `tmpfs`. Note: Trivy config scan gates misconfig. Priority: P3.

**INFRA-02 — Secret management.** Impl: `.env.prod` on disk (deploy follow-up). **Status: PI/M.** (See CRYPTO-04.) Priority: P1/P2 (deploy).

**INFRA-03 — TLS / edge.** Impl: Caddy TLS, HSTS, `Server` strip, one trusted proxy hop. **Status: IU** (read, not probed). Improvement: live TLS/cipher probe at deploy. Priority: P3.

**INFRA-04 — Network segmentation / DB isolation.** Impl: Postgres `expose`-only on private network. **Status: IV** (compose) / host firewall assumed. Priority: —.

### Supply chain (SUPPLY)

**SUPPLY-01 — Dependency vuln scanning.** Impl: `govulncheck` 0 reachable, pinned toolchain; CI gate. **Status: IV.** Priority: —.

**SUPPLY-02 — Secret scanning.** Impl: `gitleaks` full history, CI gate. **Status: IV.** Priority: —.

**SUPPLY-03 — SAST.** Impl: `gosec -severity medium` + `staticcheck`, CI gates; 5 justified `#nosec`. **Status: IV.** Priority: —.

**SUPPLY-04 — Image/IaC scanning.** Impl: **Trivy image + config scan, pinned `0.58.1`, CI gate (tip)**. **Status: IV.** Priority: —.

**SUPPLY-05 — SBOM.** Impl: **none.** **Status: M.** Improvement: CycloneDX/SPDX in CI. Priority: P3.

**SUPPLY-06 — Build provenance / release signing (SLSA).** Impl: **none** — no `cosign`, no attestation. **Status: M.** Risk: Medium. Improvement: sign images + emit SLSA provenance. Priority: P2/P3.

**SUPPLY-07 — CI access control / injection.** Impl: `permissions: contents: read`, no `pull_request_target`. **Status: IV.** Gap: **Actions pinned by tag, not SHA**; no image digest pinning. Risk: Medium. Improvement: pin Actions + base images by digest. Priority: P2.

### Assurance (ASSURE)

**ASSURE-01 — Independent external penetration test (criterion 12).** Impl: **NOT PERFORMED — WAIVED** by owner 2026-10-28 (register W1). **Status: BME.** Risk: **High (process)** — internal/automated testing is **not** equivalent. Improvement: commission an external test before scope widening / on material auth-tenant-token-federation change / after any incident. Priority: owner decision (outside this phase).

---

## 2. Framework mapping

Condensed mapping to formal frameworks. **Compliance is not claimed** — these are self-assessed control alignments pending formal assessment and (for pentest-dependent items) independent evidence.

### OWASP ASVS 5.0 (selected)
| ASVS area | Requirement (paraphrased) | IAM control | Status |
|---|---|---|---|
| V2 Authentication | argon2id, breached-password check, MFA, uniform failure, lockout | AUTHN-01..10 | **IV/PI** (step-up PI) |
| V3 Session mgmt | high-entropy tokens, rotation, revoke on sensitive change | SESS-01, AUTHN-08 | **IV/PI** |
| V4 Access control | default-deny, ownership, no stale authz | AUTHZ-01..05 | **IV** (RLS M) |
| V6 Cryptography | approved algorithms, key mgmt, rotation | CRYPTO-01..06 | **IV** primitives / **M** KMS-HSM |
| V7 Error/logging | audit events, no sensitive data in logs, log integrity | MON-01, MON-02 | **PI** (integrity M) |
| V9 Comms | TLS, HSTS | INFRA-03 | **IU** |
| V11 Business logic | quota/lockout anti-abuse | AUTHZ-03, ABUSE-01 | **IV** |
| V13 API/web service | OAuth/OIDC correctness | OIDC-01..08 | **IV/PI** |

### OWASP API Security Top 10 (2023)
| Risk | IAM position | Status |
|---|---|---|
| API1 BOLA | object-level ownership re-check, 404 foreign | **IV** |
| API2 Broken auth | PKCE, MFA, lockout, revocation | **IV/PI** |
| API3 BOPLA | struct tags hide secret fields; machine scope one project | **IV** |
| API4 Resource consumption | rate limits, 413, sizing guard | **IV/PI** (N12) |
| API5 BFLA | admin-scope gate, per-route ownership | **IV** |
| API6 Sensitive business flows | grant/trust changes instance-admin-gated | **IV** |
| API7 SSRF | `SafeIdPURL` + dial guard | **IV** (N9 minor) |
| API8 Security misconfig | fail-closed config, Trivy config scan | **IV/PI** |
| API9 Inventory mgmt | OpenAPI matches 50 routes; **discovery honesty L-04** | **PI** |
| API10 Unsafe third-party API | outbound IdP https-only + caps | **IV** |

### OAuth 2.0 BCP (RFC 9700) / OIDC Core
| Requirement | IAM | Status |
|---|---|---|
| PKCE for code flow | required S256, all interactive clients | **IV** |
| Exact redirect-URI match | library-enforced | **IV/IU** |
| No token in cacheable response | `no-store` (N22) | **IV** |
| Refresh rotation + reuse detection | CAS + family revoke | **IV** |
| Sender-constrained tokens (DPoP/mTLS) | none | **M (optional)** |
| Mix-up defense | fixed pinned issuer | **PI/NA** |
| `form_post` support | broken by CSP (M-01) | **PI** |

### NIST SP 800-63B-4
| Requirement | IAM | Status |
|---|---|---|
| AAL2 via OTP / AAL3 via WebAuthn | TOTP + passkeys | **IV** |
| Memorized-secret breached-list check | denylist (tip) | **IV** |
| Throttling of auth attempts | per-factor lockout + rate limits | **IV** |
| Reauthentication / session timeouts | short access TTL, session expiry | **IV/PI** |
| Verifier-impersonation resistance (phishing) | WebAuthn | **IV** |

### NIST SP 800-53 (selected families)
| Control | IAM | Status |
|---|---|---|
| IA-2/IA-5 Identification & authn, authenticator mgmt | AUTHN-* | **IV/PI** |
| AC-3/AC-6 Access enforcement, least privilege | AUTHZ-* (app); DB role not split | **IV/PI** |
| AU-9 Protection of audit information | MON-02 | **M** |
| SC-12/SC-13 Key mgmt, cryptographic protection | CRYPTO-* | **IV/M** (KMS) |
| SI-4 System monitoring | MON-03 | **M** |
| CM-* Config mgmt / baseline | INFRA, Trivy config | **IV/PI** |

### CIS Benchmarks
| Area | IAM | Status |
|---|---|---|
| Docker/container (CIS Docker) | nonroot, cap_drop, read_only, no-new-priv; Postgres unhardened | **IV/PI** (L-06) |
| Postgres (CIS PG) | TLS off on net, single role, no cap_drop | **PI** |

### SLSA (supply chain)
| Aspect | IAM | Status |
|---|---|---|
| Scripted/pinned build | reproducible flags, pinned toolchain/builder | **IV** |
| Provenance / attestation | none | **M** |
| Signed artifacts | none | **M** |
| Source/Actions integrity | tag-pinned (not SHA) | **PI** |

---

## 3. Status roll-up

| Status | Count (indicative) | Notable members |
|--------|--------------------|-----------------|
| IV | ~30 | PKCE, refresh rotation/reuse, passkeys, tenant-isolation enforcement, parameterised SQL, rate-limit fallback, Trivy/gosec/govulncheck gates |
| IU | ~6 | container hardening (unobserved), org-MFA gate, Entra pin (no live round trip), TLS edge |
| PI | ~12 | `form_post` (M-01), logout (L-01), factor-removal revocation (L-03), audit capture, DB-TLS, discovery honesty |
| M | ~10 | KMS/HSM, emergency key revocation, audit integrity, detection/alerting, RLS, SBOM, provenance/signing, DPoP (optional), ABAC (optional) |
| BME | 2 | criterion-12 external pentest; live federation round trips |
| NA | — | Redis failure behaviour (no Redis); OP-side `state` binding (RP responsibility) |

No control is marked IV on code presence alone. The **M** cluster in Crypto/keys and Monitoring is the enterprise-maturity core of the remediation roadmap.
