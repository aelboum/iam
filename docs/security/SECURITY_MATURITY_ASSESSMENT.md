# IAM — Security Maturity Assessment

**Type:** Internal maturity assessment (read-only). **Not** an independent penetration test.
**Date:** 2026-10-30. **Code baseline:** `origin/main` `323075c` (== HEAD `c246fe3` code tree).
Companion to `ARCHITECTURE_GAP_ASSESSMENT.md`, `SECURITY_CONTROL_MATRIX.md`, `ATTACK_PATH_ANALYSIS.md`, `SECURITY_REMEDIATION_ROADMAP.md`.

## Scale

- **Level 0** — not implemented.
- **Level 1** — basic implementation.
- **Level 2** — defined and tested controls.
- **Level 3** — systematic security engineering.
- **Level 4** — advanced adversarial validation and monitoring.
- **Level 5** — independently validated and continuously improved.

**Scoring rule applied here:** scores are evidence-anchored, not documentation-anchored. A domain cannot reach **Level 4** without adversarial validation *and* monitoring of that domain, and cannot reach **Level 5** without *independent* validation. Because the independent external penetration test (criterion 12) is **NOT PERFORMED (waived)**, **no domain can score Level 5**, and domains whose only "adversarial validation" is internal are capped below Level 4 unless they also have monitoring. Half-steps (e.g. 3−) denote "meets the level, with a named shortfall toward the next".

---

## Scorecard

| # | Domain | Score | One-line basis |
|---|--------|-------|----------------|
| 1 | Authentication | **3** | Phishing-resistant MFA + argon2id + breached-list + per-factor lockout, tested; no adaptive signals, no monitoring |
| 2 | Authorization | **3** | Default-deny, per-object ownership, live cross-tenant probe + tests; no RLS defense-in-depth, no central policy engine |
| 3 | Federation | **2+** | Strong offline design + tests; **no live round trip**, IdP-delete token-containment gap |
| 4 | Token & session security | **3** | Rotation + reuse detection + revocation tested; code-at-rest hashing + factor-removal revocation gaps |
| 5 | Cryptography & key management | **2** | Standard primitives, sealed secrets, rotation; **no KMS/HSM, no emergency key revocation, master key on disk** |
| 6 | Tenant isolation | **3** | App-enforced, probed and heavily tested; **no RLS**, refusals not audited |
| 7 | API security | **3** | OWASP-API aligned, OpenAPI matches routes; discovery honesty + `form_post` gaps |
| 8 | Abuse prevention / availability | **2+** | Rate limiting tested + fail-closed + `mem_limit` now set; **noisy-neighbour hashing unmeasured under load** |
| 9 | Monitoring & incident response | **1** | Audit capture + IR docs only; **no integrity, no detection, no alerting** |
| 10 | Infrastructure | **3−** | Good container hardening + Trivy config gate; secret store/DB-TLS/bootstrap-rotation deploy-time + unexecuted, no running deployment observed |
| 11 | Software supply chain | **3** | govulncheck/gitleaks/gosec/staticcheck/Trivy gates enforced; **no SBOM/provenance/signing, tag not SHA pinning** |
| 12 | Security testing & assurance | **2** | Strong internal tests + static analysis + three internal reviews; **no independent external pentest** (criterion 12 waived) → capped |

**Aggregate posture:** an engineering-led **Level 3** across the authentication/authorization/token/API/tenant/supply-chain core, pulled down by **Level 1–2** in monitoring, key management, and independent assurance. A *well-built, under-watched, internally-validated* system: the code is disciplined, but it is not yet continuously monitored, its key-management blast radius is large, and no third party has tested it.

---

## Evidence per domain

### 1. Authentication — Level 3
**Evidence.** WebAuthn passkeys (challenge expiry, counter CAS, clone-reject, `authn/passkeys.go`, `factor_invariants_test.go`); argon2id (`passwap`); per-factor lockout, anti-bypass preserved (`store/users.go`, migration 0007, `TestPerFactorLockout` + concurrency row); breached-password denylist (`authn/weakpasswords.go` + test, **tip**); org MFA enforcement (migration 0009, **tip**); recovery codes HMAC-hashed single-use (migration 0010, **tip**); uniform unknown-user timing; reset single-use/cooldown/lockout-safe.
**Why not 4.** No adaptive/risk-based signals; step-up not enforced at the IdP (N7); factor-removal doesn't revoke tokens (L-03); auth events **not monitored** for anomalies.
**Limitations.** Lockout/enumeration proven offline, not under live load (N12); org-MFA gate lacks a focused per-entry-path test.
**Target for 4:** anomaly detection + alerting; adaptive step-up; close L-03; gate test.

### 2. Authorization — Level 3
**Evidence.** Router-wide `requireAPIKey`, `requireAdminScope`, per-object ownership (404 foreign / 403 container); machine scope one project; **live 13-route cross-tenant probe all 404/403** (audit §9); `store/tenant_isolation_test.go` (413), `grant_revocation_test.go` (476); authorization never cached (no stale window).
**Why not 4.** No RLS; no central policy engine/ABAC; refusals not audited (N19).
**Target for 4:** RLS or a mandatory-owner-predicate review gate; audit refusals.

### 3. Federation — Level 2+
**Evidence.** Browser-bound state/nonce/intent, hashed + burned (`authn/federation.go`, `federation_session_preserve_test.go`); `(idp_id, sub)` identity; server-side preset issuers; Entra tenant-GUID pin; SSRF dial guard (`TestPublicAddress`, `TestSafeIdPURL`); N13 placeholder-email fix tested.
**Why not 3.** **No live Google/Microsoft/Entra round trip** in any current assessment (the 2026-10-26 Entra cross-tenant check was local non-prod, not repeated); IdP-delete leaves tokens alive (L-02); `SafeIdPURL` not re-run in callback (N9).
**Limitations.** Live behaviour is the gating evidence and is BME under the read-only boundary.
**Target for 3/4:** live round trips + Entra cross-tenant re-test in controlled non-prod; close L-02.

### 4. Token & session security — Level 3
**Evidence.** 256-bit opaque tokens; refresh rotation CAS + family reuse-revocation (`oidcop/storage.go`, `refresh_reuse_test.go`); revoke by subject/org/app/project (`grant_revocation_test.go`); project-scoped introspection; `no-store` (N22); parent-bounded key expiry; `token_lifecycle_test.go`.
**Why not 4.** Auth codes stored as ciphertext not hashed (N17); factor-removal doesn't revoke tokens (L-03); no sender-constraining; no token-reuse alerting.
**Target for 4:** hash codes at rest; close L-03; alert on family-reuse events.

### 5. Cryptography & key management — Level 2
**Evidence.** Standard primitives, no custom crypto (`secret/secret.go`, `secret_test.go`): AES-256-GCM, RS256, SHA-256, HMAC, argon2id, `crypto/rand`, constant-time compare. Sealed secrets with multi-key open; master-key rotation (`rotate-keys`, `rotation_test.py`); signing-key rotation with publish-lead + advisory lock (`oidcop/keys.go`).
**Why only 2.** **No external KMS/HSM** — master key is an env var / `.env.prod` on disk; signing keys decrypted into process memory; **no signing-key isolation**; **no emergency key revocation**; no key-management privilege separation; `Derive` is SHA-256 concat not HKDF; RS256-only. The root of trust is a single environment secret, and its compromise forges any token (AP-09).
**Limitations.** Rotation is proven; blast-radius containment is not addressed at all.
**Target for 3/4:** KMS/HSM envelope for the master key, isolated/externalised signing, emergency key revocation, HKDF. **Top enterprise-maturity gap.**

### 6. Tenant isolation — Level 3
**Evidence.** Every store method takes an owner id; uniqueness constraints on tenant-scoping columns; live probe + `tenant_isolation_test.go` (store 413 + authn).
**Why not 4.** **No RLS**; refusals not audited; not validated under adversarial multi-tenant load.
**Target for 4:** RLS; audit refusals; a cross-tenant adversarial test battery.

### 7. API security — Level 3
**Evidence.** OWASP-API-aligned (BOLA/BFLA/BOPLA/SSRF controls present and tested); OpenAPI documents exactly the 50 `/v1` routes (no drift); 413 + trailing-JSON handling (`decode_test.go`); canonical IP keys.
**Why not 4.** Discovery advertises non-working capabilities (L-04); `form_post` broken (M-01); some endpoints unthrottled (I-05); no API-abuse anomaly detection.
**Target for 4:** fix M-01/L-04; complete limiter coverage; API-abuse alerting.

### 8. Abuse prevention / availability — Level 2+
**Evidence.** Shared PG limiter local-first with **fallback never fail-open** (`ratelimit_test.go`); per-key/-IP/-client limits; sizing guard + **`mem_limit` now set (tip)** so it engages; 413 cap.
**Why not 3.** **Noisy-neighbour argon2 pool unmeasured under load** (N12); no per-tenant resource ceilings; unlimited endpoints (I-05); limiter shares the primary DB.
**Limitations.** Load behaviour is BME (no non-shared load env permitted).
**Target for 3/4:** load-test + capacity budget; per-tenant ceilings; DoS alerting.

### 9. Monitoring & incident response — Level 1
**Evidence.** Central `audit_events` capture (logins, lockouts, trust/revocation changes); `GET /v1/audit`; PII-safe refusal logging; IR/recovery docs (`OPERATIONS.md`, `DEPLOYMENT.md`).
**Why only 1.** **No audit-trail integrity** (no hash chain/append-only; `Store.Audit` swallows write failures — I-04); **no anomaly/risk detection**; **no alerting**; **no SIEM/log shipping**; security-relevant events (signing-key change, token-reuse, privilege change) are recorded but **nothing watches them**; refusals not separately audited (N19).
**Limitations.** An operator can reconstruct *recorded* events but cannot *trust* them against DB compromise and gets *no proactive signal*.
**Target for 2/3:** log shipping + SIEM + alert rules on existing events; audit integrity (hash chain / append-only); surface audit-write failures. **Second-largest enterprise gap.**

### 10. Infrastructure — Level 3−
**Evidence.** `read_only`, `cap_drop: [ALL]`, `no-new-privileges`, distroless nonroot, binary healthcheck, one trusted proxy hop, dev-mode/docs off in prod, fail-closed config, `mem_limit` (**tip**); Trivy **config** scan gates misconfig.
**Why not a clean 3.** Secret store / DB TLS / bootstrap-admin rotation are deploy-time and **unexecuted**; Postgres container unhardened (L-06); no `tmpfs:/tmp` (I-07); **no running deployment observed** (claims config-derived); no monitoring/log-shipping config in-repo.
**Target for 3/4:** execute the deploy-hardening follow-ups; harden Postgres; observe a running deployment.

### 11. Software supply chain — Level 3
**Evidence.** `govulncheck` 0 reachable (pinned toolchain/builder); `gitleaks` clean full history; `gosec -severity medium` + `staticcheck` gates; **Trivy image + config scan pinned `0.58.1` (tip)**; `permissions: contents: read`, no `pull_request_target`; reproducible build flags.
**Why not 4.** **No SBOM**; **no release signing / SLSA provenance**; **Actions pinned by tag not SHA**; **no image digest pinning**.
**Target for 4:** SBOM in CI; sign + attest artifacts; pin Actions + base images by digest.

### 12. Security testing & assurance — Level 2
**Evidence.** ~91 test functions incl. cross-tenant, per-factor-lockout-with-concurrency, refresh-family reuse, passkey CAS, migration concurrency, limiter fallback, revocation scoping; static-analysis + secret + vuln + image CI gates; **three internal adversarial reviews + a fourth internal audit**, each verified against code.
**Why capped at 2.** The reviews are thorough but **internal**; the **independent external penetration test (criterion 12) is NOT PERFORMED — waived** (W1). Per the scoring rule, no independent validation → **cannot exceed Level 2**, and the repo itself states internal/AI testing is not equivalent.
**Target for 3+:** continuous internal adversarial testing (and, for Level 5, an independent external test — an owner decision currently waived).

---

## Limitations of this assessment

- **Read-only / desk-based.** No exploitation, no live-provider round trip, no load test — several domains (federation live behaviour, availability under load, TLS at the edge) are **BME** and scored on offline evidence only, noted per domain.
- **Line-number provenance.** Code evidence combines this session's tip reads (marked **(tip)**) with the internal audit's citations as-of `2f78ab6`.
- **Not independent.** An internal AI-assisted review; it does not and cannot satisfy criterion 12, and nothing here represents it as equivalent.
- **No running system observed.** Infrastructure and operational scores are config/doc-derived, not from a live deployment.

## Improvement targets (summary)

| Priority | Lift | Domains moved |
|----------|------|---------------|
| P1 | Key-management envelope (KMS/HSM) + managed secret store | 5 → 3 |
| P2 | Audit integrity + log shipping + alerting | 9 → 2/3 |
| P2 | RLS + refusal auditing | 2, 6 → 3+/4 |
| P2 | Fix `form_post` (M-01); load-test hashing pool | 7, 8 |
| P2 | SBOM + signing/provenance + digest pinning | 11 → 4 |
| P3 | Close L-01/L-02/L-03/L-04; HKDF; emergency key revocation | 1, 3, 4, 5 |
| Owner | Independent external pentest (criterion 12, waived) | lifts the 12 ceiling toward 5 |

Scores are a snapshot; re-score after each P1/P2 lands and after any live-provider or load validation. Full program in `SECURITY_REMEDIATION_ROADMAP.md`.
