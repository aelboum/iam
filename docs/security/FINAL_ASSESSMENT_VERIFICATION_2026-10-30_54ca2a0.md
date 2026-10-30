# IAM — Final Assessment Verification

**Type:** Read-only verification of `ASSESSMENT_UPDATE_2026-10-30_54ca2a0.md`. No production code changed; this file is the only artifact created (not committed/pushed).
**Date:** 2026-10-30. **Audited HEAD:** `54ca2a0` (`origin/main` == HEAD, working tree clean apart from the two new assessment docs, 0 open PRs).
**Method:** source + test reading, and inspection of the vendored `github.com/zitadel/oidc/v3@v3.51.16` keys handler. No execution against production, staging or any external system.

**Status vocabulary (used consistently):** IMPLEMENTED AND VERIFIED · IMPLEMENTED BUT INSUFFICIENTLY VERIFIED · PARTIALLY IMPLEMENTED · MISSING · ACCEPTED · NOT PERFORMED.
Each claim is separated into **technical implementation**, **regression test**, **operational validation**, and **independent assurance**.

> Internal AI-assisted verification is **not** an independent external penetration test. Production readiness remains **NO-GO**; criterion 12 remains **NOT PERFORMED** (owner-waived).

---

## Priority 1 — CRYPTO-05 emergency signing-key revocation

### The full chain, answered

1. **What does `iamd revoke-key <id>` do exactly?**
   `main()` dispatches `revoke-key` (`cmd/iamd/main.go:62`) → `revokeSigningKey(id)` (`cmd/iamd/main.go:410`): `config.Load` → `db.Open` → `db.Migrate` → `store.New` → `st.DeleteSigningKey(ctx, id)` → one `slog.Warn`. It is an **operator CLI**, not an API endpoint.

2. **Permanently registered as revoked, or just deleted?**
   **Just deleted.** `DeleteSigningKey` (`internal/store/oidc.go:384`) is `execOne("DELETE FROM signing_keys WHERE id = $1")`. There is **no `revoked_at` tombstone, no revocation record, and no audit event**. Once gone, nothing records that the key ever existed or was revoked. `ErrNotFound` if the id is absent.

3. **How are local key caches / JWKS invalidated?**
   The in-process `keyStore` (`internal/oidcop/keys.go`) caches keys for `keyCacheTTL = 1 minute` (`keys.go:22`). `current()` reloads when `time.Since(loadedAt) > keyCacheTTL`, when empty, or when `needsNewKey`. So a running instance keeps the deleted key **cached — still published in `/keys` and still signing with it — for up to ~1 minute** after the DB row is gone. There is **no push/broadcast invalidation**; it is TTL-based pull.

4. **What cache do external OIDC clients / resource servers use?**
   Their own JWKS cache. **The engine sets no `Cache-Control` on `/keys`:** the library handler `op.Keys` (`pkg/op/keys.go:22`) marshals the JWKS with no cache headers, and the engine's `noStorePaths` (`cmd/iamd/main.go`) does **not** include `/keys`. So the external refresh interval is entirely RS-defined (commonly minutes to hours) and is **not bounded by the engine's 1-minute internal TTL**.

5. **Can already-issued JWTs signed by the revoked key still be accepted?**
   **Yes, for a window the engine does not control.** A resource server validates a JWT against its cached JWKS; until that RS refreshes and drops the key, a still-unexpired JWT signed by the revoked key **verifies and is accepted**. Revocation removes the key from future JWKS responses; it does **not** retroactively invalidate outstanding JWTs at an external verifier. (Opaque/bearer access tokens that the engine introspects itself are a separate path and are not signed by this key.)

6. **What happens to existing refresh tokens and sessions?**
   **Nothing.** `revoke-key` only deletes a signing key. Refresh tokens and sessions are opaque DB state, revoked through `RevokeUserTokens` / `RevokeRefreshFamily` / force-logout — none of which `revoke-key` calls. A leaked *signing key* and a compromised *session* are distinct incidents; this command addresses only the former.

7. **Is the revocation authorized, audited, abuse-resistant?**
   **Authorized** by possession of the database URL + CLI (operator/out-of-band); there is **no network-exposed revocation endpoint**, which is good (no new auth surface). **Not audited:** no audit event is written. **Abuse resistance:** limited to who can run the binary against the DB; a mistaken or malicious run is unlogged and irreversible.

8. **Multiple IAM instances?**
   Each instance reloads independently within its own `keyCacheTTL`, so propagation is **eventually consistent with up to ~1-minute skew** between instances. No coordination/broadcast.

9. **Datastore/cache unavailable?**
   If the DB is down, `revoke-key` **fails** (cannot delete). For a running instance, a reload that cannot reach the DB makes `load()`→`reload()`→`current()` return an error, so `SigningKey`/`KeySet` fail — signing/JWKS **fail closed** (no silent fallback to the revoked key beyond the cache window).

10. **Rollback / recovery?**
    **None.** Hard delete destroys the row (the private key material is sealed only in that row). A mistaken revocation **cannot be undone**; recovery is forward-only — the engine generates a fresh key, and tokens signed by the deleted key stop verifying once caches expire.

### Explicit distinction (as requested)

| Aspect | Status |
|--------|--------|
| Removal from **JWKS** (future responses) | **IMPLEMENTED** — row deleted → absent from `ListSigningKeys` → absent from `KeySet`/`/keys` after reload. |
| **Local** (engine) cache invalidation | **IMPLEMENTED, TTL-bounded** — ≤ `keyCacheTTL` (~1 min), pull-based, per instance. |
| **External verifier** cache invalidation | **NOT CONTROLLED by the engine** — no `Cache-Control` on `/keys`; RS-defined TTL. |
| Invalidation of **already-issued JWTs** | **NOT PROVIDED** — outstanding JWTs remain acceptable at an RS until its JWKS refresh + token `exp`. |
| Revocation of **refresh tokens / sessions** | **NOT PERFORMED by this command** — separate mechanism. |

### Regression evidence for CRYPTO-05

- **Present:** `internal/store/signing_key_revoke_test.go` → `TestDeleteSigningKeyRemovesFromList` — proves a deleted key leaves `ListSigningKeys` (the query that feeds the JWKS) and a sibling survives; unknown id → `ErrNotFound`. **This is store-level only.**
- **Absent:** the end-to-end `oidcop` test that exercised cache reload → `KeySet` exclusion → signer continuity (`TestRevokedKeyLeavesJWKSAndResigns`) was **removed in PR #34** because it was flaky under parallel package execution on the shared test DB. **No automated test on `main` now covers the cache/JWKS/signer chain.**
- **No test** covers: external-cache behavior, already-issued-JWT acceptance window, or that refresh/sessions are untouched.

### Verdict on CRYPTO-05

**Technical implementation:** present and correct for what it does (delete → eventual JWKS removal + signer self-heal).
**Regression test:** store-level only; end-to-end chain untested.
**Operational validation:** none (propagation/acceptance timing not measured).
**Independent assurance:** none.

→ **Correct status: IMPLEMENTED BUT INSUFFICIENTLY VERIFIED** (the `ASSESSMENT_UPDATE` label "IMPLEMENTED AND VERIFIED" overstates it). CRYPTO-05 is **not fully proven**.

**Recommended (not implemented here):** (a) set a short `Cache-Control: max-age` on `/keys` and/or document a required RS JWKS-refresh TTL so the external window is bounded; (b) emit an audit event on revocation and consider a `revoked_at` tombstone instead of hard delete; (c) restore an isolation-safe end-to-end revocation test (own database/schema, not the shared pool); (d) document clearly that `revoke-key` does **not** revoke sessions/refresh tokens, and pair it with `RevokeUserTokens` when a session compromise is suspected.

---

## Priority 2 — other claims

- **L-06 (PostgreSQL hardening):** **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED.** The `cap_drop`/`mem_limit`/`shm_size` directives exist in the prod/staging compose files, but CI's `e2e` job uses a GitHub **service-container** Postgres, not the hardened compose file, so the hardening is **not exercised by an automated test**. Operational validation = manual (`docker compose config` + `pg_isready`) only. (The `ASSESSMENT_UPDATE` already labelled this "IMPLEMENTED", not "+VERIFIED" — consistent, but the config-only nature should be explicit.)
- **SUPPLY-05/06 (SBOM + SHA pinning):** **IMPLEMENTED.** Proven: the CI `image-scan` job emits a CycloneDX SBOM of the runtime image as the `sbom-cyclonedx` artifact; every third-party Action `uses:` is a commit SHA (now v7 line) with `.github/dependabot.yml` keeping them fresh. **What this does NOT prove:** build provenance or artifact authenticity — the SBOM is an inventory, and pinning only fixes *inputs*.
- **SLSA:** **CORRECTION — no SLSA level is demonstrably met.** The `ASSESSMENT_UPDATE` phrase "approaches L1" is too generous. SLSA levels require a **provenance attestation** of the build; the pipeline generates none. SBOM + pinned actions are good supply-chain hygiene but are **not** SLSA evidence. Correct status for provenance/signing: **MISSING**.
- **N14 (reused-code token revocation):** **ACCEPTED — confirmed.** On code reuse, `claimCode`→`ClaimAuthCode` fails atomically and returns `ErrInvalidGrant("authorization code already used")` (`internal/oidcop/storage.go:160`); tokens issued by the first (legitimate) exchange are **not** revoked. RFC basis: **RFC 6749 §4.1.2** ("SHOULD revoke … all tokens previously issued"). Compensating controls: single-use code + PKCE-S256 + client authentication. (Contrast, correctly handled: **refresh-token** reuse triggers `RevokeRefreshFamily` + audit `token.refresh_reuse_detected`, `storage.go:291-295`.)
- **P2-5 (load tests):** **MISSING — confirmed.** No `testing.B` benchmark or capacity/load harness for the argon2 pool or the rate limiter exists; `overload_integration_test.go` and `sizing_config_test.go` are functional/overload-correctness tests, not measured capacity tests. The 503-shed-before-OOM property remains assessed-by-reading, not measured.
- **"Top 20" naming:** the `ASSESSMENT_UPDATE` §8 lists **12** items under the heading "Remaining prioritised work (top items still open)" — it does **not** claim to be a "Top 20", so it is **not** mislabelled. For clarity: it is a 12-item open list, a subset of the original roadmap's full Top 20 (the rest having landed in PRs #21–#34).

---

## Priority 3 — report-quality re-check of every IMPLEMENTED AND VERIFIED claim

| Prior ID | Claimed | Regression test found | Verified verdict |
|----------|---------|-----------------------|------------------|
| M-01 | IV | `cmd/iamd/headers_test.go` `TestFormPostCSP` | **IMPLEMENTED AND VERIFIED** |
| L-01 | IV | `internal/oidcop/endsession_test.go` `TestTerminateSessionFromRequestRequiresHint` (DB) | **IMPLEMENTED AND VERIFIED** |
| L-02 | IV | `internal/store/assessment_test.go` `TestDeleteIDPRevokesLinkedSessions` (asserts access+refresh → `ErrNotFound`) | **IMPLEMENTED AND VERIFIED** |
| L-03 | IV | `internal/api/grant_revocation_test.go` `TestFactorRemovalRevokesTokens` (removeTOTP; deletePasskey shares wiring) | **IMPLEMENTED AND VERIFIED** |
| L-04 | IV | `cmd/iamd/discovery_test.go` `TestHonestDiscovery` | **IMPLEMENTED AND VERIFIED** |
| L-05 | IV | `internal/api/sessions_header_test.go` `TestSessionTokenPrefersHeader` | **IMPLEMENTED AND VERIFIED** |
| I-05 | IV | `cmd/iamd/main_test.go` `TestOAuthLimiterCoversAllProviderEndpoints` | **IMPLEMENTED AND VERIFIED** |
| N10 | IV | `TestLimiterKeyCollapsesIPv6To64`, `TestOAuthLimiterSharesIPv6Slash64Bucket` | **IMPLEMENTED AND VERIFIED** |
| N17 | IV | `internal/oidcop/authcode_hash_test.go` `TestAuthCodeStoredHashedAtRest` (DB) | **IMPLEMENTED AND VERIFIED** |
| **CRYPTO-05** | IV | store-level only; end-to-end test removed (#34) | **DOWNGRADE → IMPLEMENTED BUT INSUFFICIENTLY VERIFIED** |
| L-06 | IMPLEMENTED | config only; not exercised by CI | **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED** (operational validation absent) |
| SUPPLY-05/06 | IMPLEMENTED | CI emits SBOM / pins verified present | **IMPLEMENTED** (hygiene); provenance/SLSA **MISSING** |
| CRYPTO-06 | ACCEPTED | n/a (owner decision) | **ACCEPTED** |
| N14 | ACCEPTED | n/a | **ACCEPTED** |
| criterion 12 | — | n/a | **NOT PERFORMED (waived)** |

All other IV claims hold: each has a named regression test on `main`. The **only status that must change is CRYPTO-05** (IV → IISV); L-06 and the SLSA wording need the clarifications above.

---

## Conclusions

1. **Is CRYPTO-05 fully proven?** **No.** The implementation works for key *deletion* and eventual JWKS removal + signer self-heal, but the end-to-end revocation chain is **not test-verified** on `main` (the only test is store-level deletion; the end-to-end test was removed as flaky in #34), the external-verifier window is **unbounded by the engine** (no `Cache-Control` on `/keys`), already-issued JWTs remain acceptable until each RS refreshes its JWKS, the action is **unaudited and irreversible**, and it does **not** touch sessions/refresh tokens. → **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED.**

2. **Assessment claims to soften/correct:**
   - **CRYPTO-05:** "IMPLEMENTED AND VERIFIED" → **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED**; add the limitation notes (no tombstone/audit, external cache not bounded, JWTs not retroactively invalidated, sessions/refresh untouched, no rollback).
   - **SLSA:** drop "approaches L1"; provenance/signing is **MISSING** and no SLSA level is met. SBOM + pinning = hygiene, not SLSA.
   - **L-06:** keep IMPLEMENTED but mark **operational validation absent** (compose hardening not exercised by CI).
   - Everything else in `ASSESSMENT_UPDATE` is **confirmed accurate** (M-01, L-01…L-05, I-05, N10, N17 are genuinely IMPLEMENTED AND VERIFIED; N14 ACCEPTED; no open confirmed vulnerability).

3. **Remaining production blockers:**
   - Independent external **pentest — NOT PERFORMED** (criterion 12, owner-waived; a waiver, not a pass).
   - **Deploy-time hardening** unexecuted: external **KMS/HSM** for the master/signing key (no on-disk root of trust), bootstrap-admin rotation, **DB TLS `verify-full`**, managed secret store, stable DNS, encrypted backups.
   - **No monitoring/alerting / audit-trail integrity** (detection and post-incident trust gap).
   - Explicit **owner release authorization** not given.
   - (Non-blocking but open: CRYPTO-05 end-to-end test + external-cache bounding; P2-5 load test; RLS defense-in-depth; release provenance/signing.)

4. **PRODUCTION GO/NO-GO:** **NO-GO.** The code has no known open confirmed vulnerability and a disciplined Level-3 core, but independent assurance is absent (waived, not performed), the key-management blast radius is large (no KMS), detection is absent, and the headline new control (CRYPTO-05) is only partially verified with an engine-unbounded external window. Readiness is unchanged: **NO-GO pending owner release authorization + deploy-time hardening + independent testing.**

**Stop.** No remediation implemented; await separate explicit authorization.
