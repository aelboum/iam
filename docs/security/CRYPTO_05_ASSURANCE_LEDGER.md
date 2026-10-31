# CRYPTO-05 Security Assurance Ledger

Evidence ledger for the CRYPTO-05 emergency signing-key revocation implementation. One row per control. A control is only **IMPLEMENTED AND VERIFIED** when a named test actually ran and passed; code inspection alone never earns that status.

- **Baseline:** `main` at `f3dd2a1`.
- **Feature branches / PRs:** `crypto05/phase1-clock-seam` (#36), `crypto05/phase2-durable-revocation` (#37), `crypto05/phase4a-jwks-cache-control` (#38), `crypto05/assurance-and-docs` (this doc). None merged.
- **Evidence commits:** `fa7dd4d` (Phase 1), `774391f` + `dde09be` (Phase 2), Phase 4a head (JWKS).
- **Local verification environment:** go 1.27.3; disposable Postgres 16 (`IAM_TEST_DATABASE_URL` → throwaway container) for DB-gated tests; `go test -race` **not runnable locally** (no cgo toolchain), deferred to CI; httptest for the JWKS middleware.
- **Scans (on the delivered code):** `staticcheck` clean; `gosec -severity medium -confidence medium` clean; `govulncheck ./...` — 0 vulnerabilities in called code (1 pre-existing advisory in a required-but-uncalled module, unrelated to this work); `gitleaks` — only pre-existing hits in gitignored, untracked local files (`.env`, `examples/demo/.demo-state.json`), none in any changed or tracked file.

Statuses used: `IMPLEMENTED AND VERIFIED`, `IMPLEMENTED BUT INSUFFICIENTLY VERIFIED`, `PARTIALLY IMPLEMENTED`, `MISSING`, `BLOCKED BY OWNER DECISION`, `NOT APPLICABLE`.

## Controls

| ID | Security invariant | Implementation | Test | Result | Commit | Residual risk | Status |
|----|--------------------|----------------|------|--------|--------|---------------|--------|
| SEAM-1 | The clock/TTL seam preserves production timing exactly; key selection/rotation is deterministic under an injected clock | `internal/oidcop/keys.go` (`now`/`cacheTTL`/`pubLead`, `needsNewKey`, `signer`) | `TestNeedsNewKeyUsesInjectedClockAndLead`, `TestSignerPrefersNewestSufficientlyPublishedKey`, `TestNewKeyStoreDefaultsPreserveProductionTiming` | PASS (local, no DB) | `fa7dd4d` | `-race` deferred to CI | IMPLEMENTED AND VERIFIED |
| REV-1 | ACTIVE→REVOKED removes the key from `ListSigningKeys`, writes a tombstone, records exactly one audit event, sets state REVOKED | `internal/store/oidc.go` `RevokeSigningKey`, `ListSigningKeys` | `TestRevokeSigningKeyActiveToRevoked` | PASS (Postgres 16) | `774391f` | none | IMPLEMENTED AND VERIFIED |
| REV-2 | RETIRING→REVOKED is suppressed | `RevokeSigningKey`, `ListSigningKeys` | `TestRevokeSigningKeyRetiringToRevoked` | PASS (Postgres 16) | `774391f` | none | IMPLEMENTED AND VERIFIED |
| REV-3 (T-A) | Tombstone overrides row presence: a present, non-REVOKED, unexpired row whose id is tombstoned is never listed (no resurrection) | `ListSigningKeys` (`id NOT IN revoked_signing_keys`) | `TestTombstoneOverridesRowPresence` | PASS (Postgres 16) | `774391f` | none | IMPLEMENTED AND VERIFIED |
| REV-4 (T-C, F-9) | Revocation is idempotent; a re-run after an ambiguous COMMIT creates no duplicate tombstone or audit event | `RevokeSigningKey` (`ON CONFLICT DO NOTHING`, audit gated on tombstone insert) | `TestRevokeSigningKeyIdempotentRerun` | PASS (Postgres 16) | `774391f` | none | IMPLEMENTED AND VERIFIED |
| REV-5 (F-3 atomicity) | Revoking an unknown id writes no tombstone and no audit event and returns ErrNotFound (gated audit rolls back with the tx) | `RevokeSigningKey` | `TestRevokeSigningKeyUnknownIsAtomicNotFound` | PASS (Postgres 16) | `774391f` | Full fault-injection of an audit-INSERT failure (test 16) not exercised | IMPLEMENTED AND VERIFIED |
| AUDIT-1 (F-3/C-3) | The revocation audit insert uses the transaction handle, never the pool-bound `Store.Audit`; success only after durable commit | `RevokeSigningKey` (inline `tx.Exec`) | Covered indirectly by REV-1/REV-4/REV-5 | PASS (indirect) | `774391f` | No test injects an audit-write failure to prove the state change also rolls back | IMPLEMENTED BUT INSUFFICIENTLY VERIFIED |
| NOLEAK-1 | No private key material appears in logs or audit records | `RevokeSigningKey` audit detail `{key_id, reason}`; `cmd/iamd/main.go` logs `key_id` only | Code inspection + `gitleaks` on changed files | PASS (inspection/scan) | `774391f` | No dedicated assertion test | IMPLEMENTED BUT INSUFFICIENTLY VERIFIED |
| PURGE-1 (T-17/AC7) | `PurgeExpired` never removes revocation tombstones | `internal/store/oidc.go` `PurgedTables`/`PurgeExpired` (tombstone table excluded) | `TestPurgeExpiredRetainsTombstone` | PASS (Postgres 16) | `dde09be` | none | IMPLEMENTED AND VERIFIED |
| JWKS-1 (T-15/AC8) | `/keys` carries an explicit, bounded `Cache-Control`, set before the handler writes, and only on GET/HEAD `/keys` | `cmd/iamd/main.go` `jwksCacheControl`, `keysCacheMaxAge` | `TestJWKSCacheControlOnKeysOnly` | PASS (httptest) | Phase 4a head | Bounds compliant caches only; cannot bind a non-compliant RS or recall issued JWTs | IMPLEMENTED AND VERIFIED |
| FAILCLOSED-1 (C-5) | On a failed authoritative reload the key store serves no stale keys (signing halts) | `internal/oidcop/keys.go:68-72` (`current()` returns error, keeps no stale cache) | Existing suite; no new dedicated test this mission | PASS (pre-existing behavior) | baseline | No new targeted test added; relies on existing behavior | IMPLEMENTED BUT INSUFFICIENTLY VERIFIED |
| ENGINE-1 (tests 3,4) | At the engine level a revoked key is not selected to sign and is absent from `KeySet`/JWKS | `keyStore.load`/`signer`/`KeySet` consume `ListSigningKeys` | Store-level REV-1/REV-3; engine-level test intentionally omitted (decrypts all rows → flaky on a shared DB, the #34 lesson; needs a dedicated-DB harness) | PASS at store level only | `774391f` | Engine path proven only transitively; dedicated engine test deferred to a dedicated-DB harness | PARTIALLY IMPLEMENTED |
| RACE-1 (tests 7,8) | Concurrent signing and revocation, and concurrent revocations, are safe under the race detector | — | Not written; `-race` unavailable locally | NOT RUN | — | True concurrency behavior unproven pending CI `-race` tests | MISSING |
| NOTIFY-1 (D2; tests 9,10,11,13) | Sub-TTL cross-instance convergence via LISTEN/NOTIFY, with polling fallback and stale-cache bound | Not implemented; polling (worst-case ≤ `keyCacheTTL`) remains the correctness guarantee in the baseline | — | NOT RUN | — | Sub-minute convergence not implemented; multi-instance tests require a dedicated-DB harness (see note) | MISSING |
| RESTORE-1 (D3; tests 5,6, T-B, T-D, T-E; AC3/AC4/AC5/AC6/AC11) | Restart/backup/PITR/replica-lag reconciliation via a revocation epoch that fails closed on regression | Designed in plan §4.8; not implemented | — | NOT RUN | — | Epoch fail-closed is an irreversible recovery policy requiring owner authorization | BLOCKED BY OWNER DECISION (D3) |
| AUTHZ-1 (D6) | Revocation is a strongly authenticated, attributable administrative action with an approval policy | Unchanged: `iamd revoke-key` relies on host + DB credentials; actor recorded as `system` | — | NOT RUN | — | No approval gate / per-operator identity; changing this is an owner decision | BLOCKED BY OWNER DECISION (D6) |
| SESSION-1 (D4) | Coupling between key revocation and session/refresh revocation | Default retained: orthogonal (no change) | — | — | — | "Eject the subject" still requires calling the existing refresh/session revocation paths | NOT APPLICABLE (no change this phase) |
| TTL-1 (D5) | Access-token TTL as a lever on the external-JWT window | Default retained: 5 minutes (no change) | — | — | — | External already-issued-JWT window unchanged | NOT APPLICABLE (no change this phase) |

## Acceptance-criterion coverage (plan §11, revision 2)

| AC | Covered by | State |
|----|-----------|-------|
| AC1 tombstone overrides row presence | REV-3 | PASS |
| AC2 atomic revoke+tombstone+audit | REV-1, REV-5 (audit-failure injection pending) | PASS (partial on fault injection) |
| AC3 ≤TTL convergence else fail-closed | FAILCLOSED-1 + polling baseline; multi-instance test pending (NOTIFY-1) | INSUFFICIENTLY VERIFIED |
| AC4 post-revocation JWKS verify fails (T-B) | ENGINE-1 (store-level only) | PARTIAL / engine test pending |
| AC5 survive restart + backup | RESTORE-1 | BLOCKED (D3) |
| AC6 replica lag suppressed (T-D) | REV-3 mechanism; dedicated T-D pending | PARTIAL |
| AC7 purge retains tombstone | PURGE-1 | PASS |
| AC8 JWKS cache header | JWKS-1 | PASS |
| AC9 concurrency idempotent incl. re-run | REV-4 (idempotency) PASS; race tests 7/8 pending (RACE-1) | PARTIAL |
| AC10 honest operator/doc wording | operator message + docs (inspection) | VERIFIED by review, no lint test |
| AC11 restore/PITR fail-closed | RESTORE-1 | BLOCKED (D3) |

## Note on deferred multi-instance / NOTIFY tests

`keyStore.load()` decrypts every `signing_keys` row it reads. Tests that build real key stores and exercise `KeySet`/convergence are therefore flaky when packages share one `IAM_TEST_DATABASE_URL` (the failure that led to removing `TestRevokedKeyLeavesJWKSAndResigns` in PR #34). The engine-level, multi-instance, and NOTIFY tests (ENGINE-1, NOTIFY-1, parts of RESTORE-1) require a per-test or per-package dedicated test database (a CI service or an in-test `CREATE DATABASE`). Standing that harness up is itself a test-infrastructure decision and is recommended before those phases are implemented.

## Classification

CRYPTO-05 remains **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED**. It is not upgraded to IMPLEMENTED AND VERIFIED: several acceptance criteria are still blocked by owner decisions (D3) or pending CI race tests and a dedicated-DB harness (AC3–AC6, AC9), and no independent adversarial review of the implementation has been performed. The independent penetration test remains **NOT PERFORMED (waived)**; internal and AI-assisted testing is not an independent pentest. Production readiness remains **NO-GO**.
