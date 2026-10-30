# IAM — Enterprise Security Architecture Gap Assessment

**Type:** Internal architecture and security-control gap assessment (read-only). **Not** an independent penetration test.
**Date:** 2026-10-30.
**Assessor:** Internal AI-assisted review.
**Status of production readiness:** **NO-GO** (unchanged). Independent-pentest criterion 12 remains **NOT PERFORMED** (waived by owner 2026-10-28, risk accepted; a waiver is not a pass).

This document is one of five deliverables produced together:

1. `ARCHITECTURE_GAP_ASSESSMENT.md` (this file) — architecture review, current vs target, product benchmark.
2. `SECURITY_CONTROL_MATRIX.md` — per-control status, evidence, gaps, framework mapping.
3. `ATTACK_PATH_ANALYSIS.md` — 16 attack paths, controls, residual risk.
4. `SECURITY_MATURITY_ASSESSMENT.md` — maturity scores per domain with evidence.
5. `SECURITY_REMEDIATION_ROADMAP.md` — prioritized P0–P3 program.

---

## 1. Repository baseline

| Item | Value |
|------|-------|
| Remote | `https://github.com/aelboum/iam.git` |
| Local path | `C:\Users\imran\Documents\IAM` |
| Branch at assessment | `chore/housekeeping-audit-roadmap` |
| HEAD SHA | `c246fe3e5ea51b873240f6b9e3d292ba6ff660bc` |
| `origin/main` SHA | `323075c59a0cae7aa5b00b7bceb8a13b166056e8` |
| HEAD vs origin/main | 1 ahead (a docs-only commit), 0 behind. **The code tree at HEAD is byte-identical to `origin/main` 323075c**; the extra commit touches only `docs/` and `.gitignore`. |
| Working tree | Clean (no uncommitted modifications). `strix_runs/` is git-ignored. |
| Module | single Go module `github.com/aelboum/iam`, `go 1.26.10`, `toolchain go1.27.3` |
| Size | 85 Go files, ~15,092 LOC, 50 test files; 11 SQL migrations; 1 CI workflow (4 jobs) |
| Open PRs | none |

**Branch handling.** No branch was created, switched, reset, cleaned or stashed for this assessment; it was written on the branch already checked out. All existing user work and untracked files are preserved. The repository is **not** behind `origin/main`.

### Evidence provenance and a caveat on line numbers

This assessment builds on three primary in-repository evidence sources:

- `docs/security/INTERNAL_SECURITY_AUDIT.md` — a detailed source-first internal audit **against commit `2f78ab6`** (the pre-`origin/main` tip), with file:line evidence and live local probing.
- `docs/SECURITY.md` — the authoritative threat model and residual-risk register (N1–N28, D3, W1).
- `docs/SECURITY_ASSESSMENT_2026-10-29.md` — the assessment that produced PR #13.

Since `2f78ab6`, eight pull requests merged into `origin/main` (deploy hardening, Trivy image/config CI scan, DB-plaintext warning, mandatory PKCE for every interactive client, breached-password denylist, org-level MFA enforcement, MFA recovery codes). Where a control was changed by those PRs, this assessment cites **current-tip** evidence re-read this session, marked **(verified on tip)**. Other citations use **file + symbol** (stable across edits) and inherit line numbers from the audits above, taken at `2f78ab6`; **re-confirm any bare line number before acting on it.** A control is never marked VERIFIED here solely because code exists — see the verification bar in `SECURITY_CONTROL_MATRIX.md`.

### Boundaries honoured

Read-only. No production or staging system contacted; no container started; no database, migration, credential, DNS or IdP change; no dependency upgrade; no application-code, CI or GitHub-settings change; no branch/commit/push/PR/merge/release/deploy; no external pentest; no vendor contact. `vps-ai-pbx` and `zitadel-stack` untouched. No secret printed. No claim that this internal review equals an independent external test.

---

## 2. Current architecture (as built)

IAM is a **headless, API-driven identity engine** — a Go modular monolith. It renders no UI; the calling login UI owns all screens. It is simultaneously an **OpenID Provider (OP)** and a **REST management/login API**, fronted by Caddy, backed by PostgreSQL.

```
                         ┌──────────────────────── Caddy (TLS, HSTS, edge) ────────────────────────┐
   browser / RP  ─────▶  │  :443  →  iamd (chi router)                                              │
   operator backend ──▶  │          ├─ middleware: RequestID, Recoverer, securityHeaders, noStore,  │
                         │          │              cors, limitOAuthEndpoints, forwardedFor          │
                         │          ├─ /v1/*      REST management + login API (requireAPIKey)       │
                         │          │              users, orgs, projects, sessions, api-keys, audit │
                         │          ├─ /authorize, /oauth/token, /introspect, /revoke, /userinfo,   │
                         │          │   /end_session, /keys, /.well-known/..., /device_authorization │
                         │          │              OIDC provider (zitadel/oidc v3 `op`)             │
                         │          └─ /idp/callback  federation (engine as RP to upstream IdP)     │
                         └──────────────────────────────────────────────────────────────────────────┘
                                        │                                   │
                                   PostgreSQL 17                    outbound https (SSRF-guarded)
                              (authoritative identity +              → Google / Entra / generic OIDC
                               authz state; app-enforced
                               tenant isolation; no RLS)
```

**Packages** (`internal/`): `api` (REST handlers, authz middleware), `authn` (password/TOTP/passkey/federation), `oidcop` (OP adapter: storage, keys, provider, models), `store` (pgx persistence), `db` (migrations, advisory-lock migrator), `secret` (AES-GCM box, token/hash/HMAC/const-time), `sizing` (argon2 pool sizing), `ratelimit` (shared PG limiter), `config` (fail-closed config load), `docs` (OpenAPI UI). Entry point `cmd/iamd/main.go`.

**Key libraries:** `go-chi/chi` v5, `zitadel/oidc` v3.51.16 (`op`), `zitadel/passwap` v0.12.1 (argon2id), `go-webauthn/webauthn` v0.18.2, `pquerna/otp`, `go-jose/go-jose` v4, `jackc/pgx` v5. No custom cryptographic primitives.

**Data-plane trust model** (from `docs/SECURITY.md`): login API keys (operator backends, trusted), org admins (configure own org, not instance policy), instance admins (set `trust_email`/`trust_mfa`), external IdPs (untrusted for email/MFA unless an instance admin opts in per IdP), end users (authentication alone grants no authorization).

---

## 3. Current vs target architecture, by domain

Status key (defined fully in the control matrix): **IV** implemented & verified · **IU** implemented but insufficiently verified · **PI** partially implemented · **M** missing · **NA** not applicable.

### A. Authentication security
Target: passkeys/WebAuthn preferred, argon2id with resource limits, TOTP, MFA enrollment/recovery protection, step-up, multi-level throttling, ATO prevention, credential lifecycle, secure recovery, session invalidation after sensitive change, enumeration/stuffing resistance, uniform failure handling.

- **Present & strong:** WebAuthn passkeys with challenge expiry, counter-must-grow CAS, clone-reject, no credential-ID disclosure (`authn/passkeys.go`). argon2id via `passwap`. TOTP with per-factor lockout (`mfa_locked_until`) separate from password lockout (`locked_until`), anti-bypass preserved (`store/users.go`, migration 0007). **Breached/common-password denylist** on new passwords (`authn/weakpasswords.go`, `IAM_WEAK_PASSWORD_FILE`) **(verified on tip)**. **Org-level MFA enforcement** blocking factorless login until enrolment (`orgs.mfa_required`, migration 0009) **(verified on tip)**. **Single-use MFA recovery codes** stored only as HMAC hashes (`store/recovery_codes.go`, migration 0010) **(verified on tip)**. Unknown-user path matches real failure including hashing time (`authn/authn.go`); reset tokens single-use/30 min, cooldown looks like unknown user, invalidated on credential/lock change. Session + token revocation on password change / lock / delete.
- **Gaps:** **step-up is not enforced at the IdP** (N7); removing a factor (TOTP/passkey) does **not** revoke already-issued OAuth tokens (audit L-03); no adaptive/risk-based signals (device, geo, impossible-travel); enumeration/lockout are well tested offline but **unvalidated under live load** (N12).
- **Status:** core **IV**/**IU**; step-up and factor-removal revocation **PI**; adaptive auth **M**.

### B. Authorization architecture
- **Present & strong:** default-deny — `requireAPIKey` router-wide on `/v1`, `requireAdminScope` gates management, every object route re-checks ownership (`userForCaller` → 404 foreign, `projectForOwner`/`projectForReader` → 403/404). Foreign **objects** 404 (no existence oracle), foreign **containers** 403. Login-scope keys reach only the session API. Child key cannot outlive parent; key cannot delete itself. Machine scopes limited to one `urn:iam:project:<uuid>`. Grant removal revokes tokens. **Authorization is not cached** — every check hits the DB at request time, so there is no stale-authz window by construction.
- **Gaps:** authorization is **consistent but decentralised** (per-handler, no single policy engine/language; no OPA/Cedar/Keycloak-authz-services equivalent); **no ABAC**; tenant isolation is **application-enforced only — no Row-Level Security**; one missed `WHERE org_id` in a future store method is a cross-tenant leak and only tests guard it.
- **Status:** enforcement **IV** (cross-tenant probe + tests); central policy engine **M** (by design for this scale); RLS defense-in-depth **M**.

### C. OAuth 2.0 / OIDC (baseline: RFC 9700, OIDC Core)
- **Present & strong:** auth-code flow; **PKCE S256 required for every interactive client, `plain` refused** (`oidcop/storage.go:68-78`, **verified on tip** — strengthened from "public clients only"); issuer pinned via `op.StaticIssuer`; code claimed only after PKCE + client auth; refresh rotation single `UPDATE … WHERE used_at IS NULL` CAS, reuse revokes the family and audits; `no-store` on token/introspect/revoke/userinfo/callback (N22); introspection scoped to caller's project; signing restricted to **RS256**; JWKS with rotation + publish-lead overlap.
- **Deviations / gaps:**
  - **M-01 (Medium, OPEN on tip):** the global CSP (`default-src 'none'; … form-action 'self'`, `cmd/iamd/main.go:388`, applied router-wide at `:192`, provider mounted at `/` `:210`) **breaks `response_mode=form_post`** — inline auto-submit and cross-origin form target both blocked. Fails closed (no token leak) but fully breaks a standard, more-secure response mode. **Verified still present on tip.**
  - **L-01 (Low):** `end_session` without `id_token_hint` revokes nothing (`oidcop/storage.go` `TerminateSession`/`TerminateTokens`); logged-out page while token stays valid. No test.
  - **L-04 (Low):** discovery advertises `response_types` (`id_token`, `id_token token`) and `jwt-bearer` that do not work (stubs).
  - **N14:** reused auth code's issued tokens not revoked (RFC 6749 §4.1.2 SHOULD). **N17:** auth codes stored as ciphertext, not hashed.
  - **Login CSRF / `state`:** by documented design, `state` binding is the **relying party's** responsibility (RFC 6749 §10.12); the OP echoes it — standard and correct, but an integrator responsibility to communicate.
  - **Mix-up:** fixed pinned issuer; federation audience/issuer strict-equality. OP-side mix-up defenses (distinct redirect per IdP, `iss` in authz response) not explicitly implemented — acceptable for a single fixed-issuer OP.
  - **DPoP / mTLS sender-constraining:** **not implemented** (opaque bearer tokens). Defensible for first-party SaaS.
- **Status:** core flow **IV**; `form_post` **PI (broken)**; logout, discovery honesty, token-reuse-revocation **PI**; DPoP/mTLS **M (optional)**.

### D. Federation
- **Present & strong:** state/nonce/PKCE verifier 256-bit random; **state stored hashed and burned on claim; intent burned even on binding mismatch; redemption requires the browser-binding cookie** (`authn/federation.go`). Identity keyed on `(idp_id, sub)`, **never email**. Email linking requires instance-admin `trust_email` **and** `link_by_email`; untrusted emails → `idp-<hash>@idp.invalid` (N13 fixed). **Preset issuers computed server-side**; Entra pinned to a tenant GUID (`authn/providers.go`). Discovery + authorize URL pass `SafeIdPURL`; outbound client dial-guarded, https-only, 1 MiB body cap, ≤3 redirects.
- **Gaps / not verified:** **no live Google/Microsoft/Entra round trip** here; live cross-tenant Entra rejection reported by the project (2026-10-26, local non-prod) but not repeated; **N9** `SafeIdPURL` not re-run in `HandleCallback`; MSA out of scope; deleting an IdP ends sessions but **leaves issued tokens alive** (L-02).
- **Status:** design **IV** (offline) / **IU** (no live round trip); IdP-delete containment **PI**.

### E. Session and token security
- **Present:** 256-bit opaque tokens; refresh family rotation CAS + reuse detection; access ~5 min, refresh 7 d idle / 30 d absolute; revoke by subject/org/app/project; API-key lifecycle with parent-bounded child expiry; `token_hash`/`key_hash`/`state_hash` unique-indexed; session tenant-scoped.
- **Gaps:** **auth codes stored as ciphertext, not hashed** (N17); factor-removal does not revoke tokens (L-03); no sender-constraining; a compromised refresh token is a bearer credential until revoked.
- **Status:** **IV/IU**; code-at-rest hashing + factor-removal revocation **PI**.

### F. Cryptographic architecture and key management *(flagged priority area)*
- **Present:** AES-256-GCM `Box` with random nonce and multi-key open for rotation (`secret/secret.go`); `crypto/rand` tokens; SHA-256 token hashing; HMAC-SHA256; `subtle.ConstantTimeCompare`; argon2id; RSA-2048 **RS256** signing keys generated in-process, **sealed in the DB with the master key**, interval-rotated with publish-lead overlap, cluster-serialised by an advisory lock (`oidcop/keys.go`). Master-key rotation supported (seal-new/open-old, `iamd rotate-keys`, `--check` read-only). `Derive(master, purpose)` purpose-bound sub-keys.
- **Gaps (material for enterprise maturity):** **no external KMS/HSM** — master key is env `IAM_MASTER_KEY`, i.e. **plaintext on disk via `.env.prod`** until `DEPLOY_HARDENING.md` §2; signing private material decrypted into process memory; **no signing-key isolation** (no HSM/KMS signing, no separate signer); **no separation of key-management privilege**; **no emergency signing-key revocation** (compromised key lives in JWKS until time-based `ExpiresAt`); `Derive` is `SHA-256(master||purpose)` not HKDF; RS256-only (no ES256/EdDSA).
- **Status:** primitives **IV** (standard libs, no custom crypto); KMS/HSM, privilege separation, signing-key isolation, emergency revocation **M**. **Largest enterprise-maturity gap.**

### G. Database and tenant isolation
- **Present:** every query parameterised (fixed-identifier concatenation only; no `Sprintf` into SQL); forward-only transactional migrations serialised by a session advisory lock (`db/db.go`); schema uniqueness on the tenant-scoping columns; monotonic CAS for lockout/TOTP/passkey counters; `go test -race` clean; N21/N28 index fixes merged; Postgres not published to host in prod/staging.
- **Gaps:** **no RLS**; **no automatic down-migration** (N2); **DB TLS `sslmode=disable`** on the compose network (deploy follow-up), with a **production plaintext-DB-URL warning now added (verified on tip, PR #16)**; Postgres service **unhardened** vs app containers (L-06); no least-privilege DB role split; backup **encryption is a placeholder** (I-08).
- **Status:** query safety + migration integrity **IV**; RLS, DB-TLS enforced, least-priv role, Postgres hardening, backup encryption **PI/M**.

### H. Abuse prevention and availability
- **Present:** shared Postgres rate limiter, **local-first with fallback on DB error (never fail-open)**, bounded latency; per-key login (1200/min), per-IP, per-key management limits; `limitOAuthEndpoints`; request-size (413) + JSON-trailing-data handling; argon2 **hashing-pool sizing** guard (`sizing.go`) with cgroup-CPU awareness.
- **Gaps:** **M-02 was OPEN at `2f78ab6` but FIXED on tip** (prod/staging compose set `mem_limit: 1g`, **verified on tip**; base `docker-compose.yml` still unlimited, dev only); **N12** noisy-neighbour argon2 pool, unmeasured under load; no per-tenant global quota; no circuit breakers; **Redis not used** (ephemeral state in Postgres — "Redis failure" NA, but limiter shares the primary DB's fate); `/end_session`/`/keys`/discovery/`/device_authorization` not rate-limited (I-05); `/healthz` unauthenticated + DB ping (N27).
- **Status:** rate limiting **IV**; per-tenant DoS isolation + load-validated capacity **PI/M**.

### I. Security monitoring and incident response
- **Present:** central `audit_events` (logins, lockouts, issuer/provider/trust changes, revocations); `GET /v1/audit` (instance-admin only); PII-safe federated-refusal logging; rate-limited overload warnings; documented IR/recovery (`OPERATIONS.md`, `DEPLOYMENT.md`).
- **Gaps (significant):** **audit trail has no integrity protection** — no hash chain, no append-only grant, and `Store.Audit` **swallows write failures** (I-04); a DB-level actor can rewrite history, a transient failure silently drops events. **No anomaly/risk detection, no alerting, no SIEM/log-shipping**; signing-key-change and token-reuse events are recorded but **nothing watches them**; cross-tenant refusals not separately audited (N19). An operator can reconstruct *recorded* events but cannot *trust* them against DB compromise and has *no proactive signal*.
- **Status:** capture **PI**; integrity, detection, alerting **M**. **Second-largest enterprise gap.**

### J. Infrastructure and self-hosted security
- **Present:** Caddy publishes only 80/443; `iam`/`postgres` `expose`-only; `iam`+`caddy` `read_only`, `cap_drop: [ALL]`, `no-new-privileges` (Caddy re-adds `NET_BIND_SERVICE`); distroless nonroot, no shell/package manager; binary healthcheck; Caddy HSTS + `Server` strip + `X-Forwarded-Proto`; engine trusts one proxy hop; dev-mode/docs off in prod/staging; staging pins its own compose project; `config.Load` fails closed on missing/short master key, http issuer outside dev, bad proxy-hop count, non-origin CORS, RP-ID/origin mismatch. **Container memory limits now present (verified on tip).**
- **Gaps:** **no TLS to Postgres**, **no managed secret store** (`.env.prod` on disk), **bootstrap admin key live after first start** — three documented, **unexecuted** deploy follow-ups; Postgres container unhardened (L-06); no `tmpfs:/tmp` under `read_only` (I-07, latent); no monitoring/alerting/log-shipping/backup-schedule in-repo; network segmentation/firewall are deployment assumptions.
- **Status:** container hardening **IV/IU**; secret store, DB TLS, bootstrap rotation, Postgres hardening, monitoring **PI/M** (deploy-time).

### K. Software supply chain
- **Present:** `govulncheck` **0 reachable** (toolchain pinned, builder matched); deps current and pinned in `go.sum`; `gitleaks` clean over full history; CI `permissions: contents: read`, no `pull_request_target`; `security` job gates `govulncheck`/`gitleaks`/`gosec -severity medium`/`staticcheck`; **`image-scan` runs Trivy image + config scan pinned `0.58.1` (verified on tip — closes the audit's "no image scan" gap)**; build `CGO_ENABLED=0 -trimpath -ldflags="-s -w"`, distroless nonroot.
- **Gaps:** **Actions pinned by tag (`@v4`/`@v5`), not SHA**; **no SBOM**; **no release signing / build provenance (SLSA)**; **no image digest pinning** (floating base tags); no gated dependency-update automation.
- **Status:** scanning/secret/vuln gates **IV**; SBOM, provenance/signing, SHA/digest pinning **M**.

### Scope-coverage summary

| Domain | Overall |
|--------|---------|
| A Authentication | strong core; gaps in step-up / factor-removal revocation / adaptive |
| B Authorization | strong enforcement; no central policy engine; no RLS |
| C OAuth/OIDC | solid; `form_post` broken (M-01); logout/discovery honesty; no DPoP |
| D Federation | strong design; no live validation |
| E Session/token | solid; code-at-rest hashing + factor-removal revocation gaps |
| F Crypto/keys | standard primitives; **no KMS/HSM, no emergency revocation — top gap** |
| G DB/tenant | safe queries + migrations; **no RLS**, DB-TLS/least-priv deploy gaps |
| H Abuse/availability | rate limiting good; noisy-neighbour + no load validation |
| I Monitoring/IR | capture only; **no integrity, no detection, no alerting — major gap** |
| J Infrastructure | good container hardening; deploy-time hardening unexecuted |
| K Supply chain | strong scanning; **no SBOM/provenance/SHA-pinning** |

---

## 4. Benchmark comparison — Ping Identity, Okta, Keycloak

Architectural reference points, not products to copy. The comparison distinguishes **product features**, **documented security controls**, **independent assurance**, and **operational responsibility**, and judges each capability's **necessity for an internal, first-party, self-hosted SaaS IAM** and whether adopting it adds **unnecessary complexity**. No "product X is more secure" claim is made from marketing.

### 4.1 Ping Identity
Documented strengths: enterprise federation breadth (SAML 2.0, WS-Fed, OIDC, legacy), identity lifecycle/SCIM, authentication **orchestration** (DaVinci flow engine), enterprise access policy, large-scale ops + formal certifications (SOC 2, ISO 27001, FedRAMP).

| Capability | IAM today | Need for us | Complexity if adopted |
|---|---|---|---|
| OIDC federation | Yes | Core — have it | — |
| SAML / WS-Fed | No | Not needed for first-party OIDC unless a tenant mandates SAML | High — avoid unless required |
| SCIM provisioning | No | Optional | Medium |
| Orchestration engine | No (flows in code) | Not needed at this scale | High — avoid |
| Formal certifications | No | A compliance decision, not architecture | N/A (process) |
| Clustered ops/monitoring | Partial | **Needed** — monitoring/alerting is a real gap (domain I) | Medium |

**Takeaway:** Ping's protocol/orchestration breadth is largely **unnecessary complexity** here. Borrow only its **operational maturity** (monitoring/alerting).

### 4.2 Okta
Documented strengths: **adaptive/risk-based auth**, **Identity Threat Protection** (continuous session risk, shared-signals/CAEP), phishing-resistant MFA (FIDO2/passkeys), device trust, identity governance.

| Capability | IAM today | Need for us | Complexity if adopted |
|---|---|---|---|
| Phishing-resistant MFA (passkeys) | **Yes** (strong) | Core — have it | — |
| Adaptive/risk-based policy | No | Valuable (impossible-travel, new-device step-up); **not a defect to lack** | High (signal pipeline + risk model) |
| Continuous session risk / CAEP | No | Nice-to-have for multi-app blast-radius | High |
| Device trust | No | Optional; first-party apps can enforce | High |
| Governance / access reviews | Partial (grants + audit) | Low for internal use | Medium |

**Takeaway:** IAM already matches Okta's **phishing-resistant MFA** bar. Adaptive auth / continuous-risk is the main *forward-looking* gap — an advanced (maturity Level 4) control, a later P2/P3 target, **not** a P0/P1 and **not** a vulnerability.

### 4.3 Keycloak (closest peer)
Documented strengths: self-hosted realm/client isolation, full OIDC/OAuth, configurable auth flows, **authorization services** (UMA/policy engine), passkeys, session management, federation/brokering (+ LDAP/Kerberos), operational hardening.

| Capability | IAM today | Assessment |
|---|---|---|
| Self-hosted OIDC OP | Yes | On par in protocol core; IAM is leaner (headless) |
| Realm/client isolation | Org/tenant app-enforced | Keycloak also relies on app-level scoping (no DB-per-realm by default); IAM's **lack of RLS** is a *shared* limitation, not a Keycloak advantage |
| Passkeys/WebAuthn | Yes | On par |
| Authorization services (UMA) | No (per-handler RBAC) | Richer in Keycloak; **unnecessary** for first-party RBAC |
| Configurable auth flows | No (fixed in code) | IAM trades flexibility for a smaller auditable surface — defensible |
| User federation (LDAP/Kerberos) | No (IdP brokering only) | Not needed |
| Key management | Realm keys in DB + provider SPI (external-vault capable) | **Keycloak's external-vault/key-provider story is ahead** — IAM has no KMS/HSM path; clearest borrowable pattern |
| Operational hardening | Mature | IAM has container hardening but weaker monitoring/alerting |

**Takeaway:** Keycloak is the right peer; IAM matches it on protocol core + passkeys and is smaller/more auditable. Borrow **external key-vault integration** (F) and **operational monitoring maturity** (I). Its policy engine and user-federation breadth are **unnecessary complexity** here.

### 4.4 Net position
For a ~15k-LOC headless engine, IAM is **architecturally sound and unusually disciplined**: phishing-resistant MFA, correct PKCE/refresh-rotation/reuse-detection, server-pinned federation issuers, parameterised SQL, fail-closed config, enforced CI security gates. Its protocol/authentication core is at or near the benchmarks' documented controls. It is **behind** on three enterprise dimensions the benchmarks treat as table stakes: **(1) key management** (no KMS/HSM, no signing-key isolation/emergency revocation), **(2) security monitoring** (no audit integrity, detection or alerting), **(3) independent assurance** (no external pentest — criterion 12, waived). It deliberately and correctly **omits** SAML/WS-Fed, orchestration engines, UMA/policy engines, SCIM and user federation.

---

## 5. Consolidated gap list (pointers into the other deliverables)

- **Confirmed defects (functional/availability/hardening, none above Medium):** M-01 `form_post` (OPEN on tip), L-01 logout, L-02 IdP-delete token survival, L-03 factor-removal token survival, L-04 discovery honesty, L-05 session-token transport, L-06 Postgres hardening, I-01..I-08. **No Critical, no High.**
- **Architectural gaps (not defects):** no KMS/HSM + no emergency key revocation (F); audit integrity + detection + alerting (I); no RLS (B/G); no SBOM/provenance/SHA-pinning (K); no adaptive auth (A, optional).
- **Insufficiently validated controls:** live federation round trips (D); load behaviour of argon2 pool + rate limiter (H, N12); cross-tenant Entra re-test (D).
- **Missing operational controls (deploy-time):** managed secret store, DB TLS, bootstrap-admin rotation, backup encryption, monitoring/alerting (I/J).
- **Optional enterprise features (not security defects):** SAML, SCIM, orchestration engine, UMA policy engine, device trust, CAEP shared signals.

Per-control status/evidence/framework mapping: `SECURITY_CONTROL_MATRIX.md`. Exploitation reasoning: `ATTACK_PATH_ANALYSIS.md`. Scores: `SECURITY_MATURITY_ASSESSMENT.md`. Program: `SECURITY_REMEDIATION_ROADMAP.md`.

---

*Prepared from source review and in-repository audit evidence. No production or staging system was contacted; no application code, CI, infrastructure, branch or remote state was changed; only the five documentation files under `docs/security/` were created. This internal assessment is explicitly **not** equivalent to an independent external penetration test; criterion 12 remains **NOT PERFORMED**, and production readiness remains **NO-GO**.*
