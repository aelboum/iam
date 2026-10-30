# IAM — Security Remediation Roadmap & Recommended Target Architecture

**Type:** Internal planning deliverable (read-only phase). **Nothing in this roadmap has been implemented.** **Not** an independent penetration test.
**Date:** 2026-10-30. **Code baseline:** `origin/main` `323075c` (== HEAD `c246fe3` code tree).
Companion to `ARCHITECTURE_GAP_ASSESSMENT.md`, `SECURITY_CONTROL_MATRIX.md`, `ATTACK_PATH_ANALYSIS.md`, `SECURITY_MATURITY_ASSESSMENT.md`.

**Production readiness remains NO-GO. Independent-pentest criterion 12 remains NOT PERFORMED (waived).** This roadmap is a plan to be authorized separately before any implementation; it does not change readiness status by itself.

---

## 1. How items are classified

The task requires separating five categories; every item carries one:

- **[VULN]** confirmed defect (functional/availability/hardening) in current code. *None are Critical/High; all Low/Medium.*
- **[ARCH]** architectural gap (not a defect — a capability the enterprise target wants).
- **[TEST]** insufficiently validated control (code exists; proof missing or offline-only).
- **[OPS]** missing operational control (deploy-time / runtime).
- **[OPT]** optional enterprise feature (not a security defect to lack).

**Do not read every [ARCH]/[OPT] item as a vulnerability.** The confirmed defects are the [VULN] rows only.

Priority bands: **P0** Critical/blockers · **P1** high-risk auth/authz/crypto · **P2** advanced controls + regression coverage · **P3** operational hardening + defense-in-depth.

---

## 2. Priority bands

### P0 — Critical / blockers
**None.** No Critical or High finding exists in current code across three internal reviews, a fourth internal audit, this assessment, and the automated gates (`govulncheck` 0 reachable, `gitleaks` clean, `gosec`/`staticcheck` clean, Trivy gated). The only *process* blocker is the waived criterion-12 external pentest — an owner decision, not a code item.

### P1 — High-risk auth / authz / crypto
| ID | Cat | Item | Benefit | Regression test | Impl. risk | Deps |
|----|-----|------|---------|-----------------|-----------|------|
| P1-1 | [ARCH]/[OPS] | **Key-management envelope: master key in an external KMS/HSM; managed secret store (remove `.env.prod` from disk).** Optionally sign via KMS to isolate signing keys. | Shrinks AP-09 blast radius — a host/`.env` compromise no longer hands over the root of trust and token-forgery capability. | KMS-backed `Box` seal/open + sign round-trip tests; boot fails closed without KMS access. | Medium — touches the crypto root; preserve rotation and `--check`; stage (master key first, signer later). | KMS/HSM choice; deploy env. |
| P1-2 | [OPS] | **Bootstrap-admin key rotation at deploy** (DEPLOY_HARDENING §4) + **DB TLS `verify-full` in prod** (§3). | Removes two standing deploy-time exposures (live bootstrap key; plaintext DB traffic). | Config rejects a plaintext DB URL in prod (promote the existing warning to an error where required); post-rotation smoke. | Low–Medium — deploy procedure, not code logic. | Deploy env; DNS/secret store. |

*Rationale for P1 (not P0):* latent/deploy-dependent, not live-exploitable defects — but the highest-leverage reductions of the worst-case (AP-09/AP-13) impact, so they lead.

### P2 — Advanced controls & regression coverage
| ID | Cat | Item | Benefit | Regression test | Impl. risk | Deps |
|----|-----|------|---------|-----------------|-----------|------|
| P2-1 | [VULN] | **Fix M-01 `form_post`** — scope a relaxed CSP (`script-src` for the inline submit; `form-action` covering redirect origins) to OP HTML responses only, leaving the strict JSON CSP intact (`cmd/iamd/main.go`). | Restores a standard, more-secure OIDC response mode; stops RPs falling back to code-in-URL. | Boot + complete a `form_post` flow; assert the callback CSP allows submit + form action; JSON CSP unchanged. | Low — HTML responses only. | None. **Highest-confidence open item.** |
| P2-2 | [ARCH] | **Audit-trail integrity** — hash-chain or append-only grant on `audit_events`; **surface `Store.Audit` write failures** instead of swallowing (I-04/MON-02). | Trustworthy trail against a DB-level actor; no silent event loss. | Tamper-detection test; audit-write-failure propagates/alerts. | Medium — schema + write-path change. | Migration (out of this phase). |
| P2-3 | [OPS] | **Monitoring: log shipping + SIEM + alert rules** on existing events (login anomaly, lockout storm, privilege/trust change, token-family reuse, **signing-key change**, API-key abuse) (MON-03). | Turns recorded events into detection; most attack paths currently proceed unnoticed. | Alert-rule tests against synthetic event streams. | Low–Medium — additive. | Monitoring stack. |
| P2-4 | [ARCH] | **Row-Level Security** defense-in-depth + a review/lint gate requiring an owner predicate; **audit cross-tenant refusals** (N19). | Removes the "one missed `WHERE org_id`" latent cross-tenant risk (AP-05). | RLS policy tests; refusal-audit assertion. | Medium–High — schema policy + role work; must not break app-enforced paths. | Least-privilege DB roles (P1-2 adjacent). |
| P2-5 | [TEST] | **Load-test the argon2 pool + rate limiter** (N12/ABUSE-02) in a non-shared env; set `IAM_HASH_SLOTS` to fit `mem_limit`; add a **compose-limit lint** CI step. | Converts availability from "assessed by reading" to measured; proves 503-shed before OOM. | Compose-limit lint; recorded load-harness result. | Medium — needs a dedicated load env (BME today). | Non-shared load env; capacity budget. |
| P2-6 | [ARCH] | **Supply chain: SBOM (CycloneDX/SPDX), image + Action digest pinning, release signing + SLSA provenance (`cosign`)** (SUPPLY-05/06/07). | Closes AP-15 floating-tag exposure; verifiable provenance. | CI emits SBOM + attestation; verify step. | Low–Medium — CI only. | None. |
| P2-7 | [ARCH] | **Emergency signing-key revocation** — drop a key from JWKS now and force re-sign (CRYPTO-05). | Bounds a leaked signing key to minutes, not its full `ExpiresAt`. | Revoke-key removes it from `/keys`; its tokens rejected. | Medium — interacts with the key cache / publish-lead. | P1-1 adjacent. |
| P2-8 | [TEST] | **Live federation round trips + Entra cross-tenant re-test** in controlled non-prod (FED-03). | Moves federation from offline- to live-verified (BME today). | Live round-trip harness; cross-tenant refusal recorded. | Low (test only) — outside the read-only boundary. | Test IdP registrations; non-prod env. |
| P2-9 | [TEST] | **Org-MFA gate test across entry paths** + **recovery-code lockout-parity test** (AUTHN-04/05). | Proves the MFA gate can't be skipped and recovery codes share lockout. | Focused handler tests. | Low. | None. |
| P2-10 | [OPS] | **Encrypted, access-controlled backups + retention** (I-08/DB-05). | A stolen dump no longer yields sealed-secret context + rewritable history. | Restore-from-encrypted-backup rehearsal. | Low–Medium — deploy procedure. | Deploy env; KMS (P1-1). |

### P3 — Operational hardening & defense-in-depth
| ID | Cat | Item | Benefit | Regression test | Impl. risk |
|----|-----|------|---------|-----------------|-----------|
| P3-1 | [VULN] | **L-03** — add `RevokeUserTokens` to `removeTOTP`/`deletePasskey`. | Factor removal actually contains stolen tokens. | Mirror `TestSetPasswordHandlerRevokesOnlyTargetUser`. | Low |
| P3-2 | [VULN] | **L-02** — revoke linked users' tokens in `DeleteIDP`. | IdP removal contains access, not just sessions. | Extend `TestDeleteIDPRevokesLinkedSessions` to tokens. | Low |
| P3-3 | [VULN] | **L-01** — require `id_token_hint` or implement `CanTerminateSessionFromRequest`. | Honest logout semantics. | Hint-less logout → `/userinfo` fails. | Low |
| P3-4 | [VULN] | **L-04** — implement advertised capabilities or stop advertising them. | Discovery honesty; no dead integration paths. | Every advertised `response_type` accepted. | Low |
| P3-5 | [VULN] | **L-05** — accept `X-Session-Token` on all session routes. | Consistent transport; clearer failures. | Header works on POST session routes. | Low |
| P3-6 | [VULN] | **L-06** — `cap_drop` + minimal `cap_add` + `mem_limit` + `shm_size` on the Postgres service. | Reduces DB-container blast radius (AP-13). | `docker compose config` + clean PG boot + `pg_isready`. | Medium (wrong caps break startup). |
| P3-7 | [ARCH] | **Hash auth codes at rest** (N17) and use **HKDF** in `secret.Derive` (CRYPTO-06). | Minor crypto-hygiene hardening. | Code-hash + HKDF round-trip tests. | Low |
| P3-8 | [OPS] | **Complete rate-limit coverage** (`/end_session`, `/keys`, discovery, `/device_authorization`) (I-05); IPv6 /64 keying (N10). | Removes unlimited surfaces. | Limiter-map coverage test. | Low |
| P3-9 | [VULN] | **I-01** renumber the duplicate `0007_` migration; **I-07** add `tmpfs:/tmp`; **I-02** drop dead Google env vars; **I-03** reconcile criterion-12 wording across docs. | Removes latent confusion/foot-guns. | Migration-order test; boot under `read_only`. | Low |
| P3-10 | [OPT] | **Step-up forwarding** (`prompt`/`max_age`) to the IdP (N7), or document "require a local factor after SSO". | True step-up where an RP demands it. | Step-up forwarding test. | Medium (federation flow change). |

### Optional (not scheduled — adopt only on a concrete need)
| ID | Cat | Item | Judgement |
|----|-----|------|-----------|
| OPT-1 | [OPT] | DPoP / mTLS sender-constrained tokens | Consider only if cross-SaaS token blast-radius becomes a real concern; adds client complexity. |
| OPT-2 | [OPT] | Adaptive / risk-based auth (device, geo, impossible-travel) | Okta-class Level-4 control; valuable later, needs a signal pipeline + risk model. High complexity. |
| OPT-3 | [OPT] | CAEP / shared-signals continuous session risk | Multi-app blast-radius control; defer. |
| OPT-4 | [OPT] | Central policy engine / ABAC (OPA/Cedar), UMA authorization services | **Not recommended** for first-party RBAC — unnecessary complexity. |
| OPT-5 | [OPT] | SAML / WS-Fed, SCIM, LDAP/Kerberos user federation | Not needed for first-party OIDC SaaS unless a tenant mandates it. |

---

## 3. Top 20 prioritized improvements

1. **P1-1** [ARCH/OPS] Master key → KMS/HSM envelope; managed secret store (remove `.env.prod`). *(shrinks AP-09)*
2. **P1-2** [OPS] Bootstrap-admin rotation + DB TLS `verify-full` in prod. *(AP-13)*
3. **P2-1** [VULN] Fix M-01 `form_post` CSP scoping. *(highest-confidence open defect)*
4. **P2-2** [ARCH] Audit-trail integrity (hash chain / append-only) + surface audit write failures. *(MON-02)*
5. **P2-3** [OPS] Log shipping + SIEM + alert rules on existing events. *(MON-03)*
6. **P2-4** [ARCH] RLS defense-in-depth + mandatory-owner-predicate gate; audit refusals. *(AP-05)*
7. **P2-7** [ARCH] Emergency signing-key revocation. *(AP-09)*
8. **P2-5** [TEST] Load-test argon2 pool + limiter; compose-limit lint; set `IAM_HASH_SLOTS`. *(N12/AP-14)*
9. **P2-6** [ARCH] SBOM + Action/image digest pinning + signing/SLSA provenance. *(AP-15)*
10. **P2-8** [TEST] Live federation round trips + Entra cross-tenant re-test. *(FED-03)*
11. **P2-10** [OPS] Encrypted, access-controlled backups + retention. *(DB-05)*
12. **P2-9** [TEST] Org-MFA gate test (all entry paths) + recovery-code lockout-parity test. *(AUTHN-04/05)*
13. **P3-1** [VULN] L-03 revoke tokens on factor removal.
14. **P3-2** [VULN] L-02 revoke tokens on IdP delete.
15. **P3-6** [VULN] L-06 harden the Postgres container.
16. **P3-3** [VULN] L-01 honest `end_session` semantics.
17. **P3-8** [OPS] Complete rate-limit coverage + IPv6 /64 keying.
18. **P3-4** [VULN] L-04 discovery honesty.
19. **P3-7** [ARCH] Hash auth codes at rest + HKDF.
20. **P3-5 / P3-9** [VULN] L-05 session-token transport; I-01/I-02/I-03/I-07 housekeeping.

*(The criterion-12 independent external pentest is intentionally excluded from this engineering list: an owner process decision, currently waived, not an implementation task.)*

---

## 4. Recommended target architecture (self-hosted first-party SaaS IAM)

Per component: **why · exists today? · missing part · operational complexity · security benefit · build vs. buy**. Guiding principles: **no unnecessary microservices, no custom cryptography**, keep the lean headless monolith, spend complexity only where blast-radius or detection gaps justify it.

| Component | Why | Exists today? | Missing | Op. complexity | Security benefit | Library / product |
|-----------|-----|---------------|---------|----------------|------------------|-------------------|
| **Go modular monolith** | Small, auditable surface; no inter-service auth to get wrong | **Yes** — keep | — | Low | Smaller attack surface than microservices | stdlib + chi |
| **PostgreSQL authoritative state** | Single source of truth; transactional revocation | **Yes** | RLS, least-priv roles, TLS in prod, encrypted backups | Medium | Tenant-isolation + DB-compromise containment | pgx; native RLS |
| **Redis for bounded ephemeral state / limiting** | Offload hot limiter/ephemeral state from the primary DB | **No** — in Postgres today | Only if load testing shows the shared-DB limiter is a bottleneck | Medium | Availability isolation | redis — **adopt only if P2-5 shows a need; do not add speculatively** |
| **OIDC/OAuth 2.0 OP** | Core function | **Yes** (zitadel/oidc) | Fix `form_post`, logout/discovery honesty; DPoP later | Low | Protocol correctness | zitadel/oidc (keep) |
| **WebAuthn / passkeys** | Phishing-resistant MFA | **Yes** (strong) | Optional attestation policy | Low | At the benchmark bar | go-webauthn (keep) |
| **argon2id** | Memory-hard hashing | **Yes** | Load-validated sizing; per-tenant hash budget | Medium | ATO + DoS resilience | passwap (keep) |
| **Asymmetric token signing** | Verifiable tokens, rotation | **Yes** (RS256) | Emergency revocation; optional ES256 | Low | Token integrity | go-jose (keep) |
| **External KMS/HSM** | Remove the single on-disk root of trust; isolate signing | **No** | Envelope the master key; optionally sign via KMS | Medium–High | **Largest blast-radius reduction (AP-09)** | Cloud KMS / PKCS#11 HSM — **integrate, never custom** |
| **Central authz policy enforcement** | Consistency, auditability | **Partial** — per-handler RBAC (consistent) | A review/lint gate requiring owner predicates is the cheap win; a policy engine is optional | Low (gate) / High (engine) | Prevents a future missed predicate | **Prefer lint/review gate + RLS over a policy engine** |
| **Tenant-aware data isolation** | Multi-tenant safety | **Yes (app-enforced)** | RLS defense-in-depth | Medium | Removes the latent cross-tenant class | native Postgres RLS |
| **Append-only / tamper-evident audit** | Trustworthy forensics | **No** (plain table, swallowed failures) | Hash chain or append-only grant; surface write failures | Medium | Post-incident trust | Postgres grants / in-app hash chain |
| **Centralized monitoring & alerting** | Detection (absent today) | **No** | Log shipping + SIEM + alert rules | Low–Medium | Turns capture into detection across all paths | ship to the org's SIEM — **integrate** |
| **Hardened containers + segmentation** | Reduce host/lateral risk | **Yes (mostly)** | Harden Postgres container; execute deploy follow-ups | Low | Reduced blast radius | compose + distroless (keep) |
| **Automated adversarial testing** | Continuous assurance | **Partial** (internal reviews + optional AI tool) | Continuous internal suite; **independent external pentest (owner-gated)** | Medium | Finds what static review misses | internal harness; external vendor (owner decision) |
| **Signed, reproducible build artifacts** | Supply-chain integrity | **Partial** (reproducible flags, pinned toolchain) | SBOM, signing, provenance, digest pinning | Low | Verifiable provenance (AP-15) | cosign + SLSA tooling — **integrate** |

**Net:** the recommended architecture is **the current one plus five integrations** — KMS/HSM, a monitoring/SIEM pipeline, RLS, audit integrity, supply-chain signing — and **minus nothing**. No microservice split, no custom crypto, no policy engine, no new protocols are recommended. Redis is conditional on a demonstrated limiter bottleneck.

---

## 5. Sequencing and dependencies

```
P1-1 (KMS/secret store) ──┬─▶ P2-7 (emergency key revocation)
                          └─▶ P2-10 (encrypted backups)
P1-2 (bootstrap rotation + DB TLS) ──▶ P2-4 (RLS + least-priv roles)
P2-1 (form_post)   ── independent, do first (highest confidence, lowest risk)
P2-2 (audit integrity) ──▶ P2-3 (monitoring/alerting) ── also consumes existing events
P2-5 (load test)   ──▶ decision on Redis (conditional)
P2-6 (SBOM/signing) ── independent (CI only)
P2-8 (live federation) ── needs non-prod env (BME)
P3-* ── mostly independent, low risk, batchable
```

**Fastest confidence win:** P2-1 (`form_post`) — one confirmed open defect, low risk, immediate.
**Largest risk reduction:** P1-1 (KMS envelope) — shrinks the worst-case (AP-09) blast radius.
**Largest consequence reduction across all paths:** P2-2 + P2-3 (audit integrity + monitoring) — makes every attack path detectable and its aftermath trustworthy.

---

## 6. Status and authorization

Nothing here is implemented; this is a plan. Production readiness remains **NO-GO**; criterion 12 remains **NOT PERFORMED (waived)**; the deploy-time hardening follow-ups (`DEPLOY_HARDENING.md`) remain unexecuted. Implementation of any item requires separate authorization. No application code, CI, infrastructure, branch, or remote state was changed in producing this roadmap; only the five documentation files under `docs/security/` were created. This internal assessment is **not** equivalent to an independent external penetration test.
