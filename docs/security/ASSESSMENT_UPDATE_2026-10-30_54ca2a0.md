# IAM — Security Assessment Update (delta)

**Type:** Delta re-assessment of the five `docs/security/` deliverables. **Read-only phase** — no code or remediation implemented here; this file is the only artifact created.
**Date:** 2026-10-30. **Audited HEAD:** `54ca2a0` (`origin/main` == HEAD, working tree clean, 0 open PRs).
**Prior assessment baseline:** `323075c` (the five existing deliverables, all dated 2026-10-30).
**Delta:** 34 commits merged since `323075c` (PRs #21–#34). This update records what those merges changed in the security posture; everything not listed here is unchanged and the existing deliverables remain authoritative.

> **This internal AI-assisted assessment is not an independent external penetration test.** Production readiness remains **NO-GO**. Independent-pentest **criterion 12 remains NOT PERFORMED** (owner-waived, SECURITY.md register W1 — a waiver, not a pass).

---

## 1. Existing deliverables (not overwritten, per instruction §8)

All five target files already exist at baseline `323075c` and are **left untouched**:

| File | Baseline | Role |
|------|----------|------|
| `ARCHITECTURE_GAP_ASSESSMENT.md` | 323075c | Current-vs-target architecture; Ping/Okta/Keycloak benchmark |
| `SECURITY_CONTROL_MATRIX.md` | 323075c | Per-control status + evidence (ASVS/RFC9700/NIST mapping) |
| `ATTACK_PATH_ANALYSIS.md` | 323075c | 16 attack paths, controls, residual risk |
| `SECURITY_MATURITY_ASSESSMENT.md` | 323075c | Per-domain maturity (0–5) |
| `SECURITY_REMEDIATION_ROADMAP.md` | 323075c | P0–P3 prioritised program + target architecture |

(`INTERNAL_SECURITY_AUDIT.md` also present.) This delta references them rather than re-deriving the unchanged analysis.

---

## 2. What changed since `323075c` (controls now IMPLEMENTED AND VERIFIED)

Each row was a **[VULN] / PARTIAL / MISSING** item in the prior deliverables and is now implemented **with a regression test on `main`**. Evidence is cited by file + symbol + merge commit (line numbers shift; symbols and tests are durable).

| Prior ID | Control | Now | Evidence (symbol · test · commit) |
|----------|---------|-----|-----------------------------------|
| **M-01 / P2-1** | `form_post` response mode broken by global CSP | **IMPLEMENTED+VERIFIED** | `relaxCSPForFormPost` (`cmd/iamd/main.go:490`) scopes the relaxed CSP to the OP HTML page only · `TestFormPostCSP` · PR #21 `48649bf` |
| **L-02 / P3-2** | IdP delete left tokens valid | **IMPLEMENTED+VERIFIED** | `RevokeUserTokens` on `DeleteIDP` · `assessment_test.go` (token revocation) · PR #23 `92235e4` |
| **L-03 / P3-1** | Factor removal left tokens valid | **IMPLEMENTED+VERIFIED** | token revoke in `removeTOTP`/`deletePasskey` · PR #23 `92235e4` |
| **L-05 / P3-5** | `X-Session-Token` not accepted on all session routes | **IMPLEMENTED+VERIFIED** | session-token header on POST session routes · PR #23 `92235e4` |
| **L-06 / P3-6** | Postgres container not hardened | **IMPLEMENTED** | `cap_drop`/`mem_limit`/`shm_size` on the PG service (compose) · already on `main` |
| **L-01 / P3-3** | `end_session` without `id_token_hint` silently revoked nothing | **IMPLEMENTED+VERIFIED** | `Storage.TerminateSessionFromRequest` (`internal/oidcop/storage.go:349`) rejects hint-less logout with `invalid_request` · `TestTerminateSessionFromRequestRequiresHint` · PR #24 `e324ec4` |
| **L-04 / P3-4** | Discovery advertised implicit/JWT-bearer the engine does not implement | **IMPLEMENTED+VERIFIED** | `honestDiscovery` (`cmd/iamd/main.go:570`) strips unsupported `response_types`/`grant_types` · `TestHonestDiscovery` · PR #24 `e324ec4` |
| **I-05 / P3-8** | Several public endpoints unthrottled | **IMPLEMENTED+VERIFIED** | limiter now covers `/userinfo`, `/end_session`, `/device_authorization`, `/keys`, discovery · `TestOAuthLimiterCoversAllProviderEndpoints` · PR #25 |
| **N10 / P3-8** | Rate limits keyed on full IPv6 /128 | **IMPLEMENTED+VERIFIED** | `limiterKey` (`cmd/iamd/main.go:757`) collapses IPv6 to /64 · `TestLimiterKeyCollapsesIPv6To64`, `TestOAuthLimiterSharesIPv6Slash64Bucket` · PR #25 |
| **N17 / P3-7(1)** | Authorization codes not hashed at rest | **IMPLEMENTED+VERIFIED** | `SaveAuthCode`/`AuthRequestByCode` store SHA-256 (`internal/oidcop/storage.go:176`) · `TestAuthCodeStoredHashedAtRest` · PR #27 |
| **CRYPTO-05 / P2-7** | No emergency signing-key revocation | **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED** (initially claimed IMPLEMENTED+VERIFIED; **corrected** — see `FINAL_ASSESSMENT_VERIFICATION_2026-10-30_54ca2a0.md` and `CRYPTO_05_EMERGENCY_REVOCATION_DESIGN.md`) | `Store.DeleteSigningKey` (`internal/store/oidc.go:384`) + `iamd revoke-key <id>` (`cmd/iamd/main.go:62`); gone from JWKS within keyCacheTTL (~1 min) · `TestDeleteSigningKeyRemovesFromList` (store-level only; end-to-end test removed in #34) · PR #29 |
| **SUPPLY-05/06 / P2-6** | No SBOM; floating Action tags | **IMPLEMENTED** | CI emits CycloneDX SBOM of the runtime image; all Actions SHA-pinned (now v7 line) + `.github/dependabot.yml` · PRs #26, #30–#33 |

**Owner decision recorded (not a code change):**

| Prior ID | Item | Disposition |
|----------|------|-------------|
| **CRYPTO-06 / P3-7(2)** | Use HKDF in `secret.Derive` | **ACCEPTED, no change** — `SHA-256(master ‖ purpose)` is sound for a uniformly-random 32-byte secret master; HKDF would re-key all derived material (breaking). SECURITY.md register row **CRYPTO-06 (Accepted)**; PR #28. |

**Net effect on the confirmed-defect list:** the prior deliverables' open **[VULN]** rows (M-01 Medium + L-01…L-06 Lows) are **all closed and regression-tested**. On `54ca2a0` there is **no known open confirmed vulnerability** (consistent with "no Critical/High" across all prior reviews).

---

## 3. Control-matrix status deltas

Relative to `SECURITY_CONTROL_MATRIX.md`:

- **OAuth/OIDC (RFC 9700 / OIDC Core):** logout semantics (L-01) and discovery honesty (L-04) move from **PARTIALLY IMPLEMENTED → IMPLEMENTED+VERIFIED**. Authorization-code at-rest protection (N17) → **IMPLEMENTED+VERIFIED**. PKCE-S256 enforced for every interactive client (landed earlier, #17) remains IV. **Still accepted/open:** N14 (a reused code's already-issued tokens are not revoked — RFC 6749 §4.1.2 SHOULD) remains **Accepted** (single-use + PKCE + client-auth gate).
- **Abuse prevention (ASVS V11 / NIST 800-63B throttling):** rate-limit **coverage** (I-05) and **IPv6 /64 keying** (N10) → **IMPLEMENTED+VERIFIED**. The limiter surface is now complete across public endpoints. **Still open:** P2-5 load-test of the argon2 pool + limiter under a real flood (no non-shared load env) → remains **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED**.
- **Session/token (ASVS V3/V7):** session-invalidation-after-sensitive-change strengthened — token revocation on factor removal (L-03) and IdP delete (L-02) → **IMPLEMENTED+VERIFIED**; `X-Session-Token` transport consistency (L-05) → **IMPLEMENTED+VERIFIED**.
- **Cryptography/key management:** emergency signing-key revocation (CRYPTO-05) → **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED** (corrected from IMPLEMENTED+VERIFIED; the end-to-end revocation chain is untested and the external window is engine-unbounded — see the verification and design docs). Key-derivation (CRYPTO-06) → **Accepted (sound)**. **Unchanged gaps:** private signing/master key still on disk (no external KMS/HSM); no key-management privilege separation; no signing-key isolation.
- **Supply chain (SLSA):** SBOM availability (SUPPLY-05) and Action digest pinning (SUPPLY-06) → **IMPLEMENTED**. **Still MISSING:** release signing + build provenance (SLSA ≥ L2) and image base-layer digest pinning (both deliberately deferred — no publish/release pipeline; floating minor base tags by design).
- **Infrastructure:** PG container hardening (L-06) → **IMPLEMENTED**.

Everything else in the matrix is **unchanged** by this delta.

---

## 4. Maturity re-score (vs `SECURITY_MATURITY_ASSESSMENT.md`)

| Domain | Prior | Now | Why |
|--------|-------|-----|-----|
| Authentication | 3 | 3 | Revocation-on-change hardened (L-02/L-03); no new capability. |
| Authorization | 3 | 3 | Unchanged (per-handler RBAC remains consistent; no central engine/RLS). |
| Federation | 2–3 | 2–3 | Unchanged; still offline-validated only (P2-8 live retest open). |
| Token & session | 3 | 3 | Logout honesty + auth-code hash + revocation consistency reduce deviations; no tier change. |
| Cryptography & key mgmt | 1–2 | **2** | Emergency revocation (CRYPTO-05) adds a real key-lifecycle control; blast radius unchanged (no KMS/HSM) so it stays sub-3. |
| Tenant isolation | 3 | 3 | Unchanged (app-enforced; no RLS defense-in-depth). |
| API security | 3 | 3 | Discovery honesty + full rate-limit coverage; no tier change. |
| Abuse prevention | 2–3 | **3** | Limiter coverage complete + IPv6 /64; still no measured load test → not 4. |
| Monitoring & IR | 1–2 | 1–2 | **Unchanged** — still no SIEM/alerting; only a minor IR addition (key-revocation runbook). |
| Infrastructure | 3 | 3 | PG hardening done; deploy-time items (DNS/secret store/DB-TLS) still open. |
| Software supply chain | 2 | **3** | SBOM + Action SHA-pinning + Dependabot = systematic; no signing/provenance → not 4. |
| Security testing & assurance | 1 | 1 | **Unchanged** — internal/AI only; independent external pentest NOT PERFORMED (waived). |

**Aggregate:** still an engineering-led **Level 3 core**. Supply chain moved **2 → 3**; crypto/key-mgmt nudged within **2**; abuse-prevention consolidated at **3**. The three persistent drags are **unchanged**: monitoring/detection (1–2), key-management blast radius (2, no KMS/HSM), and independent assurance (1). Headline stands: *a well-built, under-watched, internally-validated system* — now with its previously-open low/medium defects closed.

---

## 5. Attack-path deltas (vs `ATTACK_PATH_ANALYSIS.md`)

- **Signing-key compromise (path 9):** detection/containment improved — a leaked key can now be dropped from JWKS within ~1 minute via `iamd revoke-key` instead of surviving to `ExpiresAt`. Residual: still a large blast radius while the master key lives on disk (no KMS); revocation is reactive, not prevented.
- **Refresh-token replay / session termination (paths 8, 11):** logout now actually revokes (L-01); factor/IdP removal revokes tokens (L-02/L-03) — fewer stale-credential windows.
- **Denial of service (path 14):** previously-unthrottled endpoints (`/keys`, discovery, `/end_session`, `/device_authorization`) and the IPv6-rotation evasion (N10) are closed; the **noisy-neighbour argon2** exhaustion remains the top availability residual (load-test still pending, P2-5).
- **CI/CD supply-chain compromise (path 15):** mutable-tag Action substitution is closed (SHA pinning); SBOM gives post-incident inventory. Residual: no release signing/provenance, so artifact authenticity is still unverifiable downstream.
- **Unchanged high-residual paths:** database compromise (no RLS, no audit-trail integrity), authorization-cache inconsistency, and "one SaaS app compromise affecting another" (shared master key / no per-app key isolation) are **not** addressed by this delta.

---

## 6. Benchmark delta (Ping / Okta / Keycloak)

The strategic gaps in `ARCHITECTURE_GAP_ASSESSMENT.md` are **unchanged**: no adaptive/risk-based authentication or identity-threat protection (Okta), no identity-governance/lifecycle or authentication orchestration (Ping), no central authorization-services/policy engine and no external KMS (all three). Those remain **optional for a first-party internal-SaaS use case** and are not security defects to lack.

This delta narrows only **operational-hardening** gaps, mostly relative to **Keycloak's** self-hosted posture: supply-chain integrity (SBOM + pinned CI) and emergency signing-key revocation are now present. The engine remains a lean, auditable OIDC OP + WebAuthn + argon2id monolith; nothing in this delta argues for adopting a benchmark product's heavier machinery.

---

## 7. Framework-mapping deltas

- **RFC 9700 / OIDC Core:** + honest discovery metadata, + honest RP-initiated logout, + authorization-code hashed at rest (defense-in-depth), with PKCE-S256 already enforced for all interactive clients. Open: N14 (code-reuse token revocation SHOULD).
- **OWASP ASVS 5.0:** + V7 (session termination on sensitive change), + V11 (anti-automation coverage complete). Unchanged weak areas: V1/V10 (central policy, logging/monitoring).
- **NIST SP 800-63B-4:** throttling now complete across entry points; verifier/secret handling unchanged (already strong).
- **SLSA:** the build emits an SBOM and pins its CI actions (supply-chain hygiene), but this meets **no SLSA level** — SLSA requires a build **provenance attestation**, which the pipeline does not generate. Provenance/signing is **MISSING** (see `FINAL_ASSESSMENT_VERIFICATION_2026-10-30_54ca2a0.md` §SLSA).
- **CIS / NIST 800-53:** PG-container hardening (CM/AC) added; SI (monitoring/alerting) and SC (KMS/key isolation) controls unchanged and still the main gaps.

---

## 8. Remaining prioritised work (top items still open at `54ca2a0`)

Confirmed **[VULN]** open: **none known**. The rest are **[ARCH]/[OPS]/[TEST]** — owner/infra/schema, not autonomous code:

1. **P1-1 [ARCH/OPS]** Master key → external **KMS/HSM**; managed secret store (largest blast-radius reduction, AP-09).
2. **P1-2 [OPS]** Bootstrap-admin rotation + **DB TLS `verify-full`** in prod.
3. **P2-2 [ARCH]** **Audit-trail integrity** (hash-chain / append-only) + surface `Store.Audit` write failures.
4. **P2-3 [OPS]** **Monitoring**: log shipping + SIEM + alert rules (signing-key change, lockout storm, token-family reuse, API-key abuse).
5. **P2-4 [ARCH]** **Row-Level Security** defense-in-depth + mandatory-owner-predicate lint gate.
6. **P2-5 [TEST]** **Load-test** argon2 pool + limiter in a non-shared env; compose-limit lint.
7. **P2-6 remainder [ARCH]** **Release signing + SLSA provenance (`cosign`)**; image base-layer digest pinning — deferred (no publish pipeline; floating base tags).
8. **P2-8 [TEST]** **Live federation** round trips + Entra cross-tenant retest.
9. **P2-10 [OPS]** Encrypted, access-controlled **backups** + restore rehearsal.
10. **P3-9 [VULN/OPS]** Housekeeping (I-01 migration renumber, I-02 dead env vars, I-03 criterion-12 wording, I-07 `tmpfs:/tmp`) — not part of PRs #21–#34; verify against the existing roadmap.
11. **P3-10 [OPT]** Step-up forwarding (`prompt`/`max_age`) to the IdP, or document "require a local factor after SSO".
12. **Gates (process, not code):** independent external pentest (criterion 12 — **WAIVED**, not a pass); explicit **owner release authorization** + deploy-time hardening (`DEPLOY_HARDENING.md`).

(Optional enterprise features — DPoP/mTLS, adaptive auth, CAEP, SAML/SCIM, central policy engine — remain **not recommended unless a concrete need appears**; see the existing roadmap §Optional.)

---

## 9. Execution-boundary confirmations (instruction §11/§12)

- **Audited branch/HEAD:** `main` @ `54ca2a0`; `origin/main` identical; working tree **clean**; **0 open PRs**.
- **No application code changed** in this assessment phase.
- **No remote action / deployment / merge / push / branch / commit** performed for this assessment. (This file is created in the working tree only; per §11 it is **not** committed or pushed.)
- **No staging / production / DB / migration / credential / DNS / IdP / CI change.** `vps-ai-pbx` and `zitadel-stack` untouched.
- **No secrets printed; no discovered credentials used.**
- **No external penetration testing; no vendor contacted; no purchase.**
- Internal AI-assisted assessment is **not** equivalent to an independent external penetration test. **Production readiness: NO-GO. Criterion 12: NOT PERFORMED (waived).**

---

## 10. Stop condition

Delta re-assessment complete. The existing five deliverables remain valid for all unchanged analysis; this file records only the `323075c → 54ca2a0` security delta. **No remediation implemented.** Await separate, explicit authorization before implementing any of the remaining items in §8.
