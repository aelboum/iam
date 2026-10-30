# IAM — Attack-Path Analysis

**Type:** Internal, evidence-based attack-path analysis (read-only desk analysis; no exploitation against any live system). **Not** an independent penetration test.
**Date:** 2026-10-30. **Code baseline:** `origin/main` `323075c` (== HEAD `c246fe3` code tree).
Companion to `ARCHITECTURE_GAP_ASSESSMENT.md`, `SECURITY_CONTROL_MATRIX.md`, `SECURITY_MATURITY_ASSESSMENT.md`, `SECURITY_REMEDIATION_ROADMAP.md`.

**Method.** Each path is reasoned from source and the in-repository audit evidence (`INTERNAL_SECURITY_AUDIT.md`, `SECURITY.md`). No attack was executed against production, staging, third-party providers or any external system; the prior internal audit ran the few live probes cited, on a disposable local instance only. Line numbers inherited from the audit are as-of `2f78ab6`; items re-read this session on `323075c` are marked **(tip)**.

**Headline:** no path yields a **Critical or High** confirmed compromise on the current code. The highest residual exposures are architectural (key-management blast radius, audit-trail integrity, absence of detection) and availability (noisy-neighbour hashing), not an exploitable authentication or tenant-isolation bypass found in code.

---

## AP-01 — Account takeover (ATO)
- **Initial position:** remote, unauthenticated; knows/guesses a username/email. **Privileges:** none. **Exposed:** password/TOTP login, reset.
- **Conditions:** weak/reused password; no second factor.
- **Existing controls:** argon2id; breached-password denylist on set (`authn/weakpasswords.go` **(tip)**); per-factor lockout via conditional `UPDATE` (`store/users.go`); uniform unknown-user timing (`authn/authn.go`); reset single-use/30 min with unknown-user-looking cooldown (`store/email.go`); optional org-mandated MFA (`orgs.mfa_required` **(tip)**); phishing-resistant passkeys.
- **Impact:** single-account compromise (no tenant-wide effect).
- **Detection:** lockout + login audit events; **no alerting** (MON-03).
- **Residual: Low** (strong controls), detection-blind.

## AP-02 — MFA bypass
- **Initial position:** holds a valid password for an MFA-required account. **Privileges:** first factor. **Exposed:** 2nd-factor enforcement, `amr`, recovery codes.
- **Existing controls:** `amr: fed` is not MFA; federated login counts as MFA only with `trust_mfa` (`authn.go:581`); TOTP step enforced; recovery codes single-use + HMAC-hashed, under the same lockout/rate limits per SECURITY.md (`store/recovery_codes.go` **(tip)**); per-factor lockout.
- **Impact:** full ATO of an MFA-protected account.
- **Detection:** lockout + MFA audit events; no alerting.
- **Residual: Low**, pending explicit tests that the org-MFA gate can't be skipped on any entry path (AUTHN-04) and recovery-code attempts share lockout (AUTHN-05).

## AP-03 — Passkey enrollment abuse
- **Initial position:** holder of a management key, or a session mid-login. **Privileges:** admin key or a valid session. **Exposed:** passkey/TOTP enrollment.
- **Existing controls:** enrollment requires an authenticated key or the user's session; TOTP enroll capped at 5 (N23, migration 0008); RP settings validated at boot; counter CAS + clone-reject on use (`authn/passkeys.go`).
- **Impact:** persistent attacker-controlled factor.
- **Detection:** factor-change audit; **no alert on a new factor**.
- **Residual: Low–Medium** (hinges on management-key custody — see AP-07). Improvement: alert on factor enrollment; step-up to add a factor.

## AP-04 — Password-reset abuse
- **Initial position:** remote/unauthenticated or a login-scope key. **Exposed:** `/v1/password-resets`.
- **Existing controls:** single-use/30-min tokens; unknown-user-looking cooldown; **reset does not bypass lockout** (`password_reset_lockout_test.go`); invalidated on credential/lock change; login-key trust boundary (D3 — login keys may reset for their users).
- **Impact:** recovery hijack **only** via a compromised login key (documented trust, D3).
- **Detection:** reset audit events; no alert.
- **Residual: Low** (Medium where a login key is compromised — by-design trust).

## AP-05 — Tenant escape (cross-tenant access)
- **Initial position:** authenticated holder of Tenant A's admin/org key. **Exposed:** every `/v1` object route; store methods.
- **Existing controls:** per-object ownership (`userForCaller`→404, `projectForOwner`/`projectForReader`→403/404); machine scope one project; **live 13-route cross-tenant probe all 404/403** (audit §9); `store/tenant_isolation_test.go` (413 lines). **Gap:** application-only isolation — **no RLS**.
- **Impact if a predicate is missed in a future method:** cross-tenant read/write — a High-impact class.
- **Detection:** refusals return 403/404 but are **not separately audited** (N19).
- **Residual: Low today (test-gated), Medium latent** — the single most important place a future regression turns serious. Improvement: RLS defense-in-depth + a review/lint gate requiring an owner predicate.

## AP-06 — Privilege escalation (org-admin → instance, or within org)
- **Initial position:** org-admin key. **Exposed:** trust policy, cross-org grant creation, key issuance.
- **Existing controls:** `trust_*` and `createProjectGrant` **instance-admin-only** (`api/orgs.go:290`, feature-tested); child key cannot outlive parent; key cannot self-delete; `updateProjectGrant` confined to the owning project's roles (N20).
- **Impact:** escalation to instance policy — blocked.
- **Residual: Low.** (N16: an org-admin key can revoke its sibling/parent org keys — same-org DoS only.)

## AP-07 — API-key compromise
- **Initial position:** attacker with a leaked API key. **Exposed:** everything the key's scope reaches.
- **Existing controls:** keys hashed at rest (`key_hash`, no plaintext field); scope split (admin/login, org/instance); parent-bounded child expiry (no indefinite self-renewal); `gitleaks` blocks committed keys; invalid-key logging throttled.
- **Impact:** scoped to the key — a login key → resets/logins for its users (D3); an instance-admin key → full control.
- **Detection:** API audit events; **no API-key-abuse anomaly detection**.
- **Residual: Medium for an instance-admin key** (powerful bearer credential; custody is operational). Improvement: short-lived keys, rotation, managed secret store, abuse alerting.

## AP-08 — Refresh-token replay
- **Initial position:** attacker holding a stolen refresh token. **Exposed:** `/oauth/token` refresh grant.
- **Existing controls:** rotation CAS (`UPDATE … WHERE used_at IS NULL`); **reuse detection revokes the whole family + audits** (`oidcop/storage.go:256-284`, `refresh_reuse_test.go`); refresh idle 7 d / absolute 30 d.
- **Impact:** blocked on reuse; a single live unreused stolen token works until first rotation/revocation.
- **Residual: Low.** Improvement: DPoP sender-constraining (optional, P3).

## AP-09 — Signing-key compromise *(highest architectural blast radius)*
- **Initial position:** attacker with host/memory/`.env`/DB access to a running instance. **Privileges:** read of master key (env `IAM_MASTER_KEY`) or process memory. **Exposed:** `secret.Box` master key → all sealed secrets + RSA signing keys (`oidcop/keys.go`, `secret/secret.go`).
- **Conditions:** `.env.prod` on disk (deploy follow-up unexecuted), process-memory read, or DB + key.
- **Existing controls:** keys sealed at rest; master-key rotation supported; `keyFingerprint` never logs the key; distroless read-only nonroot container narrows host access. **Gaps:** **no KMS/HSM**, no signer isolation, **no emergency key revocation** (compromised key valid in JWKS until `ExpiresAt`).
- **Impact:** **forge any token for any tenant** — effectively total compromise.
- **Detection:** signing-key changes recorded but **not alerted**; a passive key read leaves no trace.
- **Residual: Medium now** (bounded by host-access difficulty), **High impact if the host is breached** — the top architectural risk. Improvement: KMS/HSM envelope for the master key, isolate/externalise signing, emergency key revocation (CRYPTO-04/05, P1/P2); managed secret store.

## AP-10 — Federated identity substitution
- **Initial position:** malicious/compromised upstream IdP, or an org admin configuring an IdP. **Exposed:** federation callback, issuer binding, account linking.
- **Existing controls:** identity on `(idp_id, sub)` never email; **preset issuers computed server-side** (org admin cannot repoint "google"/"entra"); Entra pinned to tenant GUID; email linking needs instance `trust_email`+`link_by_email`; untrusted email → `idp-<hash>@idp.invalid` (N13); browser-bound state/intent; SSRF dial guard.
- **Impact:** impersonation — blocked by `(idp_id, sub)` keying + server-side issuers.
- **Detection:** federated-login audit; cross-tenant refusals not separately audited (N19).
- **Residual: Low (offline-verified), unproven live** — **live Entra cross-tenant round trip not re-tested here (BME)**; re-validate in controlled non-prod.

## AP-11 — Session hijacking
- **Initial position:** network/XSS-adjacent attacker targeting a session/access token. **Exposed:** session API; bearer tokens.
- **Existing controls:** 256-bit tokens; TLS + HSTS at the edge; `no-store` on token responses (N22); session tenant-scoped; short access TTL; `X-Session-Token` header (GET/DELETE). **Gap:** session-token transport inconsistent between verbs (L-05 — POST reads body only); **the engine renders no UI**, so classic XSS is the integrator's surface.
- **Impact:** session use until expiry/revocation.
- **Detection:** session audit; no suspicious-session detection.
- **Residual: Low** (UI/XSS is the RP's responsibility). Improvement: consistent header transport (L-05); DPoP (optional).

## AP-12 — Authorization-cache inconsistency
- **Initial position:** a user whose grant was just revoked, acting with a previously valid session/token.
- **Existing controls:** **authorization is never cached — every check hits the DB at request time**; grant removal revokes tokens; revoke by subject/org/app/project.
- **Impact:** stale-privilege use — **NA by construction** (no cache; only the ≤5-min access-token TTL, the standard OAuth trade-off).
- **Residual: Low.**

## AP-13 — Database compromise
- **Initial position:** attacker with DB read/write (stolen creds, on-network with `sslmode=disable`, or backup theft). **Exposed:** all persisted state.
- **Existing controls:** secrets sealed (AES-GCM); token/key hashes not plaintext; Postgres `expose`-only on a private network; parameterised queries. **Gaps:** **no DB TLS** (deploy follow-up; prod plaintext-URL warning **(tip)**); **single app role** (no least privilege); **backup encryption is a placeholder** (I-08); **auth codes stored as ciphertext not hashed** (N17); **audit trail rewritable** (MON-02); sealed secrets are only as safe as the master key (AP-09).
- **Impact:** with the master key → full compromise (AP-09); without it → sealed secrets resist offline attack, but a DB writer can rewrite audit history and redeem a live auth code.
- **Detection:** none at the DB layer; audit tampering undetectable (no hash chain).
- **Residual: Medium** (deploy-dependent; master-key custody dominates). Improvement: DB TLS + least-privilege roles + encrypted backups (P2 deploy); audit integrity (P2); hash codes at rest (P3).

## AP-14 — Denial of service
- **Initial position:** remote/unauthenticated or a single tenant. **Exposed:** argon2 hashing pool; shared DB rate limiter; unlimited endpoints.
- **Existing controls:** per-key/-IP/-client rate limits, local-first, **fallback never fail-open**; `limitOAuthEndpoints`; 413 body cap; sizing guard; **`mem_limit` now set (tip)** so the guard engages and sheds with 503 rather than OOM.
- **Gaps:** **N12 noisy-neighbour** argon2 pool (shared, unmeasured under load); `/end_session`/`/keys`/discovery/`/device_authorization` unlimited (I-05); `/healthz` DB ping (N27); IPv6 full-address keying (N10); limiter shares the primary DB's fate.
- **Impact:** degraded login latency across tenants; one tenant can affect others.
- **Detection:** overload warnings (rate-limited); no DoS alerting.
- **Residual: Medium availability** — the main unproven area. Improvement: load-test the pool (BME — needs a non-shared env); per-tenant ceilings; add the unlimited paths to the limiter.

## AP-15 — CI/CD supply-chain compromise
- **Initial position:** attacker targeting the pipeline or a dependency/action. **Exposed:** GitHub Actions; Go modules; base images.
- **Existing controls:** `permissions: contents: read`, **no `pull_request_target`**; `govulncheck`/`gitleaks`/`gosec`/`staticcheck` gates; **Trivy image + config scan pinned `0.58.1` (tip)**; pinned toolchain + builder; `go.sum`.
- **Gaps:** **Actions pinned by tag not SHA**; **no SBOM**; **no release signing / SLSA provenance**; **no image digest pinning** (floating `caddy`/`postgres`/distroless).
- **Impact:** a compromised action tag or base image could inject into the build or runtime.
- **Detection:** Trivy on image/config; none for an action-tag swap.
- **Residual: Medium** — a realistic exposure given tag pinning. Improvement: pin Actions + images by digest (P2); SBOM (P3); sign + attest (P2/P3).

## AP-16 — Compromise of one SaaS application affecting another
- **Initial position:** attacker who compromised one relying-party app (its client secret or a user session there). **Exposed:** cross-application token/scope boundaries.
- **Existing controls:** **project-scoped introspection**; per-app/per-project revocation; machine scope one `urn:iam:project:<uuid>`; audience/scope enforcement; client secrets hashed, returned once; refresh family per client.
- **Impact:** a compromised RP's tokens are **scoped to that RP/project** — they do not grant another app's resources.
- **Gaps:** opaque **bearer** tokens (no DPoP) → a stolen token works from anywhere until revoked; a shared master key is a common root across all apps (AP-09); no cross-app anomaly correlation (MON-03).
- **Residual: Low–Medium** — scope containment is solid; the shared key-management root and lack of detection are the cross-app weak points. Improvement: DPoP (optional, P3); fix AP-09 / MON-03.

---

## Residual-risk summary (post-controls)

| # | Path | Residual | Dominant factor |
|---|------|----------|-----------------|
| AP-05 | Tenant escape | Low now / **Medium latent** | no RLS; one future missed predicate |
| AP-09 | Signing-key compromise | Medium now / **High impact** | single master-key root, no KMS/HSM, no emergency revocation |
| AP-13 | Database compromise | Medium | DB-TLS/least-priv/backup-encryption deploy gaps + master key |
| AP-14 | Denial of service | Medium (availability) | noisy-neighbour hashing, unmeasured under load |
| AP-15 | CI/CD supply chain | Medium | tag (not SHA) pinning, no SBOM/provenance |
| AP-07 | API-key compromise | Medium (instance key) | operational key custody |
| AP-01..04, 06, 08, 10, 11, 12, 16 | ATO / MFA / reset / privesc / replay / federation / session / cache / cross-app | Low | strong, tested controls; detection-blind |

**Cross-cutting residual (raises the consequence of most paths):** **no detection or alerting** (MON-03) — most attacks would proceed unnoticed even where a control blocks the final step; and **audit-trail integrity** (MON-02) — post-incident reconstruction is untrustworthy against a DB-level actor. Neither is an exploitable code vulnerability; both are enterprise-maturity gaps. See `SECURITY_REMEDIATION_ROADMAP.md`.

*No exploitation was performed against any live system in producing this analysis. This internal analysis is **not** equivalent to an independent external penetration test; criterion 12 remains **NOT PERFORMED**; production readiness remains **NO-GO**.*
