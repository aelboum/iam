# CRYPTO-05 — Independent Architecture and Security Review of the Implementation Plan

- **Review type:** Independent adversarial review. Review-only; the design was not implemented.
- **Baseline:** `main` at `f3dd2a1` (= `origin/main`, clean working tree). PR #35 merged.
- **Document under review:** `docs/security/CRYPTO_05_IMPLEMENTATION_PLAN.md`.
- **Reference design:** `docs/security/CRYPTO_05_EMERGENCY_REVOCATION_DESIGN.md`.
- **Files changed by this review:** this file only (`docs/security/CRYPTO_05_INDEPENDENT_PLAN_REVIEW.md`). No application code, migration, configuration, secret, service or infrastructure was changed. `vps-ai-pbx` and `zitadel-stack` were not accessed.

All source line references below were read during this review. Zitadel behavior was verified against the vendored module `github.com/zitadel/oidc/v3@v3.51.16` in the local module cache, not asserted from memory.

---

## 1. Executive verdict

**READY AFTER DOCUMENTED CORRECTIONS.**

The plan is architecturally sound, correctly diagnoses the three real weaknesses of the current CRYPTO-05 implementation (hard delete / no tombstone, no atomic audit, uncontrolled external propagation), and proposes a durable, state-based model that fits the existing Postgres-authoritative, advisory-locked, no-Redis architecture. Its characterization of Zitadel's JWKS behavior is **correct and independently confirmed**: `op.Keys` sets no `Cache-Control` (`pkg/op/keys.go:22`→`pkg/http/marshal.go:11-16`). Its honesty posture — no claim of instantaneous global JWT revocation — is appropriate and must be preserved.

It is not yet ready to implement verbatim because of several accuracy and testability defects, none fatal:

- The "immediate revocation on the revoking engine" trust-boundary claim is **inapplicable to the only trigger that exists** (`iamd revoke-key` is a separate process, not a signing engine). (F-1, High.)
- "Stops signing immediately on this engine" overstates the achievable guarantee; an in-flight signing operation that already selected the key can still mint one token with it. (F-2, Medium.)
- Atomic audit requires a transaction-scoped insert; the existing `Store.Audit` is pool-bound fire-and-forget and cannot provide atomicity as written — the plan names the gap but does not specify the mechanism. (F-3, Medium.)
- `keyCacheTTL`/`publishLead` are compile-time `const`s and the key store calls `time.Now()` directly, so the timing/convergence tests (9, 11, 13) cannot run deterministically or quickly without a clock/TTL-injection refactor the plan does not mention. (F-4, Medium.)
- Three high-value tests are missing, most importantly a direct "tombstone overrides row presence" resurrection test that is the only clean proof of acceptance criterion 1. (F-5, Medium.)
- No startup/DR reconciliation gate: after a restore that predates the tombstone, nothing forces operators to re-apply revocations before signing resumes. (F-6, Medium.)
- Ambiguous `COMMIT` outcome and mistaken-revocation recovery are under-specified. (F-7/F-8, Low–Medium.)

With these corrections folded in (§6) and the revised acceptance criteria (§7), the plan is implementable.

---

## 2. Confirmed strengths

1. **Correct root-cause diagnosis.** Hard delete with no tombstone (`internal/store/oidc.go:384`), no audit on revoke (only `slog.Warn`, `cmd/iamd/main.go:428`), and no `Cache-Control` on `/keys` are all real and correctly cited.
2. **Zitadel JWKS behavior correctly stated.** Confirmed: `op.Keys` (`pkg/op/keys.go:22`) calls `httphelper.MarshalJSON`, which sets only `content-type: application/json` (`pkg/http/marshal.go:16`). The route is mounted bare (`pkg/op/op.go:156`) with no caching layer. IAM therefore genuinely can and must impose its own `Cache-Control` via middleware, and the library will not override it.
3. **Postgres kept authoritative.** The plan adds no new infrastructure for correctness; LISTEN/NOTIFY is explicitly a best-effort latency optimization with polling as the guarantee (plan §4.5, §7). This matches the stack (no Redis; advisory locks already used, `oidc.go:390`, `db.go:67`).
4. **Fail-closed is real and the plan preserves it.** Verified: on reload error `current()` returns `nil,nil,err` and does **not** serve stale keys past the TTL (`internal/oidcop/keys.go:68-72`). So during a database outage after cache expiry, signing halts rather than continuing with a possibly-revoked cached key. This is stronger than the plan states and should be credited (see §6, C-5).
5. **Honest external boundary.** The plan repeatedly refuses to claim recall of already-issued JWTs at third-party resource servers, which is correct: IAM does not re-verify its own JWT access tokens (`internal/oidcop/storage.go:538` returns "jwt profile grant is not supported").
6. **Additive, replay-safe migration shape** consistent with the existing migrator (`internal/db/db.go:67`); next file `0011_*` is correct (latest is `0010_recovery_codes.sql`).

---

## 3. Findings by severity

### High

**F-1 — "Immediate revocation inside IAM" is inapplicable to the actual trigger.**
Plan §3 lists a trust boundary "Immediate revocation inside IAM: achievable at the engine performing the revocation," and §1/§6 say revocation "stops signing immediately on this engine." But the only revocation entry point is `iamd revoke-key <id>`, a **separate short-lived process** (`cmd/iamd/main.go:62-72`, `revokeSigningKey` at `:410`) that opens its own pool, deletes, and exits. It is not one of the running signing engines and holds none of their in-memory `keyStore` caches. Consequently **every signing engine learns of the revocation only on its next poll** (≤ `keyCacheTTL`, `internal/oidcop/keys.go:22`); there is no engine for which revocation is "immediate." The "immediate local / ≤TTL remote" split the plan draws does not exist under the current design. *Correction:* either (a) restate the guarantee as "≤ `keyCacheTTL` on all engines, with no immediate-local case," or (b) add an in-process revocation trigger (admin endpoint or NOTIFY) if a sub-TTL guarantee is actually wanted — and even then NOTIFY is best-effort, so the worst-case bound stays ≤TTL.

### Medium

**F-2 — "Stops signing immediately" overstates the race guarantee.**
`current()` returns a `*signingKey` pointer under the mutex, then the lock is released and the JWT is signed outside the lock (`keys.go:64-74`; signing happens in the Zitadel `op` layer using the returned key). A revocation+reload that occurs after a concurrent request has already obtained the pointer cannot prevent that request from minting one token with the revoked `kid`. The achievable guarantee is: *no new key selection returns a revoked key after the engine's reload observes the revocation; signing operations that already selected the key may complete.* *Correction:* state this precisely in §1, §6 and §7 of the plan.

**F-3 — Atomic audit mechanism unspecified; existing `Store.Audit` cannot provide it.**
Plan §4.4 requires state change + tombstone + audit in one `pgx.BeginFunc` transaction, and §2.9 correctly notes `Store.Audit` "cannot be made atomic in its current form" because it runs its own `s.pool.Exec` and swallows errors (`internal/store/audit.go:24-35`). But §6 then says `Store.RevokeSigningKey` "performs the atomic transaction" without specifying that it must do a **transaction-scoped audit insert** (an insert on the `tx`, not a call to `Store.Audit`). As written, an implementer could wire `Store.Audit` in and silently reintroduce the non-atomic, error-swallowing path. *Correction:* specify a `tx`-bound audit insert inside `RevokeSigningKey`; `Store.Audit` must not be used for this.

**F-4 — Timing/convergence tests are not achievable without a refactor the plan omits.**
`keyCacheTTL = time.Minute` and `publishLead` are `const` (`keys.go:22,26`), and the store reads wall-clock `time.Now()` directly (`keys.go:79,85,122,159`). Tests 9 ("converge within `keyCacheTTL`"), 11 ("polling fallback timing"), and 13 ("stale cache window, clock-injected") therefore either block for real minutes or cannot inject a clock at all. *Correction:* make `keyCacheTTL`/`publishLead` injectable (struct fields or a package var) and introduce a clock seam (`now func() time.Time`) as an explicit prerequisite work-item; otherwise those three tests are untestable and the related acceptance criteria cannot be met.

**F-5 — Missing high-value tests (see §5).** Most importantly the resurrection-core test ("a `signing_keys` row that is present but tombstoned is never loaded/published/signed-with"), which is the only direct proof of acceptance criterion 1 and is cheaply unit/DB-testable.

**F-6 — No reconciliation gate after restore/PITR.**
Plan §8/§12 acknowledge that a restore predating the tombstone resurrects the key, but propose only "backup hygiene + runbook" (D3). Question 2.F asks whether the system must refuse signing until revocation state is reconciled; the plan does not answer it. There is no proposed startup check, no "revocation epoch" counter, and no external revocation list. *Correction:* either accept this as a documented residual (and say so explicitly, with the runbook replaying tombstones from `audit_events`), or add a concrete safeguard (e.g. a monotonic revocation-epoch persisted and cross-checked, or refuse-to-sign-until-operator-ack after a detected restore). Do not leave the question implicit.

### Low

**F-7 — Ambiguous `COMMIT` result unaddressed.** If the connection drops during `COMMIT`, pgx returns an error while the transaction may or may not have committed. The CLI would report failure though revocation may have succeeded. This is benign because the operation is idempotent (re-run via tombstone PK + `WHERE state <> 'REVOKED'`), but the plan should say so and instruct operators to re-run on ambiguous failure.

**F-8 — Mistaken-revocation recovery not stated.** Because `REVOKED` is terminal and the tombstone permanent (by design, for resurrection protection), a mistaken revocation is **unrecoverable for that key**; recovery is "a successor key is promoted/generated automatically" (`keys.go:94-124`), not "un-revoke." The plan implies but never states this. Operators must know that revoke is irreversible exactly like today's hard delete — the durability improvement does not add an undo.

**F-9 — Double audit rows under concurrent revoke.** Two concurrent `RevokeSigningKey` calls for one id: the tombstone PK and state guard make the *state* idempotent, but two `audit_events` inserts can both succeed (`audit_events.id` is `bigserial`, no uniqueness; `0002_hardening.sql:38`). Result is two audit rows for one revocation — cosmetic, not a state inconsistency. Note it; optionally gate the audit insert on the tombstone insert actually affecting a row.

### Informational

**F-10 — `/keys` middleware feasibility is real but unverified end-to-end.** Setting `Cache-Control` on `/keys` from IAM middleware works only if the header is set before the handler writes (Zitadel calls `w.Write`, which flushes `200`). IAM's existing header middleware sets headers before `next.ServeHTTP` (e.g. `securityHeaders`, `cmd/iamd/main.go:432`), so the approach is sound, but the plan should name the exact middleware insertion point and confirm it precedes the `op` handler in the chain.

---

## 4. Incorrect or unsupported assumptions

1. **"Immediate revocation at the revoking engine" (plan §3).** Unsupported: the revoker is the CLI process, not a signing engine (F-1).
2. **"Stops signing immediately on this engine" (plan §1, §6).** Overstated against the lock-release-before-sign race (F-2).
3. **Convergence "within one `keyCacheTTL`" stated without the reachability qualifier.** True only when the database is reachable at the reload instant; otherwise the engine fails closed and signing halts (which is safe, but the bound is then "≤TTL **or** signing stops," not an unconditional time bound). The plan's §7 is close but should carry the qualifier explicitly, consistent with its own instruction "do not claim a hard maximum when availability can prevent it." Verified from `keys.go:68-72`.
4. **Implicit assumption that `Store.Audit` can be made part of the transaction** (F-3). It cannot without a new tx-bound insert.
5. **Implicit assumption that timing tests are writable against the current code** (F-4). The `const` TTL and direct `time.Now()` contradict this.
6. **"Tombstone in any backup taken after revocation" suffices (plan §8).** Necessary but not sufficient for PITR to a pre-tombstone point (F-6).

No invented or contradicted source references were found in the plan; every file:line it cites that this review checked (`oidc.go:384/360/331/321/404/476`, `keys.go:22/26/64/84/94/126/150/177`, `storage.go:414/538`, `models.go:54`, `audit.go:24`, `db.go:67`, `main.go:62/428/658/724/732`, `0001_init.sql:159`, `0008:24`, `0002:38`) is accurate.

---

## 5. Missing test cases

Add to the matrix:

- **T-A — Tombstone overrides row presence (resurrection core).** Insert a `signing_keys` row **and** a `revoked_signing_keys` tombstone for the same id; assert `load()`/`ListSigningKeys` never returns it and `KeySet` omits it. Proves acceptance criterion 1 directly. *Unit/integration (DB), isolation-safe.* Currently only indirectly implied by tests 1/5/6.
- **T-B — Post-revocation JWKS cannot verify a token signed by the revoked key.** Sign a JWT with key K, revoke K, fetch `KeySet`/`/keys`, assert verification of that JWT against the published set fails because K's `kid` is absent. Stronger, IAM-side proof than the external, doc-only test 15. *Integration (DB + crypto).*
- **T-C — Idempotent re-run after ambiguous commit.** Call `RevokeSigningKey` twice for the same id (simulating a retried ambiguous commit); assert second call is a no-op on state, no error, exactly one tombstone row. *Integration (DB).* (Covers F-7; complements test 8.)
- **T-D — Replica-lag / stale-read suppression.** Simulate a read that still shows the key as `ACTIVE` while the tombstone exists; assert the tombstone check wins. Can be realized without true replication by reading the key row and tombstone separately and asserting suppression. *Integration (DB).* (Covers the replication-lag threat distinctly from backup restore.)
- **T-E — Restore-without-tombstone is detected or documented.** If a reconciliation safeguard is adopted (F-6), test that signing refuses until acknowledgment; if not adopted, this becomes a doc/runbook assertion like test 15. Must exist in one form or the other so the PITR gap is not silently unverified.

Testability prerequisites (block tests 9, 11, 13 and T-B timing): implement the clock/TTL seam from F-4 before writing them, or those rows remain aspirational.

Tests that must run under `go test -race`: 7, 8, and T-C/T-D if they exercise concurrency — plan correctly marks these CI-only. Tests needing real Postgres: 1–6, 9–12, 16, 17, T-A–T-D (all `IAM_TEST_DATABASE_URL`-gated). Tests needing multiple engines: 9 (two `keyStore`s on one DB). Tests needing restart/restore simulation: 5, 6, T-E.

---

## 6. Required design corrections

- **C-1 (from F-1).** Rewrite the propagation model: there is no immediate-local revocation with the CLI trigger; state the guarantee as "≤ `keyCacheTTL` across all signing engines, assuming the database is reachable at reload; otherwise those engines fail closed and stop signing." Only add an in-process/NOTIFY trigger if a sub-TTL path is genuinely required, and keep ≤TTL as the worst-case bound regardless.
- **C-2 (from F-2).** State the precise signing-race guarantee (no new revoked-key *selection* after reload; in-flight signs may complete).
- **C-3 (from F-3).** Specify a transaction-scoped audit insert inside `RevokeSigningKey`; prohibit using `Store.Audit` for the revocation record.
- **C-4 (from F-4).** Add a prerequisite work-item: make `keyCacheTTL`/`publishLead` injectable and add a clock seam, so timing tests are deterministic.
- **C-5 (credit from strength 4).** Document the verified fail-closed-on-stale property (`keys.go:68-72`) as part of the security guarantee; it bounds the stale-cache threat to ≤TTL and never to unbounded stale signing.
- **C-6 (from F-6).** Decide and document the restore/PITR posture: either an explicit safeguard (revocation epoch / refuse-to-sign-until-ack) or an explicit accepted residual with a tombstone-replay runbook sourced from `audit_events`.
- **C-7 (from F-7/F-8).** Document ambiguous-commit retry guidance and state plainly that revocation is irreversible for the affected key (recovery = successor key).
- **C-8 (from F-10).** Name the exact middleware position for the `/keys` `Cache-Control` and confirm it precedes the `op` handler.

---

## 7. Revised acceptance criteria

Replace the plan's §11 with criteria that each map to a concrete test:

1. Tombstone overrides row presence: a present-but-tombstoned key is never loaded, published, or signed with → **T-A** (and 5, 6).
2. Revocation + tombstone + audit commit atomically or not at all → **16**.
3. Revoked keys absent from `ListSigningKeys`, `KeySet`, `/keys` on all engines within `keyCacheTTL` when DB reachable, else signing halts → **3, 4, 9, 11** (require C-4 clock seam).
4. A token signed by a revoked key fails verification against the post-revocation JWKS → **T-B**.
5. Revocation survives restart and post-revocation backup restore → **5, 6**.
6. Replica-lag / stale-read cannot expose a revoked key → **T-D**.
7. `PurgeExpired` never reaps tombstones → **17**.
8. `/keys` carries an explicit bounded `Cache-Control` set before the handler writes → **14** (+ C-8).
9. Concurrency safe and idempotent, including ambiguous-commit re-run → **7, 8, T-C** (race, CI).
10. Operator output and docs state the honest guarantee (no immediate global JWT revocation; revoke is irreversible for the key) → **15** + doc review (C-1, C-2, C-7).
11. Restore/PITR posture is enforced or explicitly accepted with a runbook → **T-E**.

Every criterion now has at least one concrete test; criteria 3 and the timing tests are explicitly gated on the C-4 refactor.

---

## 8. Independent threat-model review (residual classification)

| Threat | Residual after plan + corrections | Severity |
|--------|-----------------------------------|----------|
| Compromised signing key (the CRYPTO-05 case) | Bounded: ≤TTL to leave JWKS on all engines; external JWT validity until RS cache refresh + `exp`. Not recallable at third-party RS. | Medium (irreducible external window) |
| Database compromise | Out of scope of CRYPTO-05; an attacker with DB write can insert keys or delete tombstones. Tombstone model does not defend against a compromised authoritative store. | High, accepted/out-of-scope |
| Database outage | Safe: signing fails closed after TTL (`keys.go:68-72`); revocation transaction fails atomically. No false "revoked," no stale signing. | Low |
| Network partition | NOTIFY may be lost; polling still converges when connectivity returns; bound is ≤TTL-after-reconnect. | Low |
| Stale replica / replication lag | Tombstone check suppresses the key once the tombstone row is replayed; window = lag + TTL. | Medium |
| Compromised IAM instance | Can mint tokens with any key it can load until revoked; revocation still bounds it to ≤TTL on *other* instances, but the compromised instance may ignore its own cache logic. Key compromise ⊇ instance compromise here. | High, partially mitigated |
| Malicious or mistaken operator | CLI needs only host + DB creds (no approval gate, D6). Revocation irreversible for the key. Mistaken revoke → forced successor, brief availability dip only. | Medium |
| Concurrent revocation | State idempotent (tombstone PK + guard); possible duplicate audit rows (F-9). | Low |
| Backup rollback / PITR before tombstone | Resurrects key unless a safeguard (C-6) is adopted; otherwise accepted residual with runbook. | Medium |
| Replay of old key material | Equivalent to resurrection; same mitigation (tombstone authority + C-6). | Medium |
| External RS with long JWKS caching | Entirely outside IAM control; bounded only by the RS's cache policy and token `exp`; mitigated by the explicit `Cache-Control` advisory and shorter token TTL (D5). | Medium (external) |

---

## 9. Owner decisions still required

Carried from the plan (§12), still open and now sharpened:
- **D1.** JWKS `Cache-Control max-age` value (plan proposes 300 s).
- **D2.** Ship LISTEN/NOTIFY now or defer (polling meets correctness; NOTIFY only reduces latency).
- **D3 / C-6.** Restore/PITR posture: explicit safeguard vs. accepted residual + tombstone-replay runbook. **This review requires an explicit decision, not silence.**
- **D4.** Couple key revocation to session/refresh revocation or keep orthogonal (`oidc.go:286-315`).
- **D5.** Shorten default access-token TTL (currently 5 min) to shrink the external window.
- **D6.** Approval/authorization model for `revoke-key` (today: host + DB creds only).
- **New D7 (from F-4/C-4).** Approve the clock/TTL-injection refactor as an implementation prerequisite, since three acceptance criteria depend on it.

---

## Implementation-readiness verdict

**READY AFTER DOCUMENTED CORRECTIONS.**

The architecture is correct and implementable within IAM's existing Postgres-authoritative design, and the Zitadel and fail-closed behaviors are verified rather than assumed. Before implementation the plan must absorb corrections C-1 through C-8, add tests T-A through T-E (with the C-4 clock/TTL seam as a prerequisite for the timing tests), adopt the revised acceptance criteria in §7, and record an explicit decision on the restore/PITR posture (D3/C-6) and the clock-seam refactor (D7). None of these are fatal; all are documentation- and test-level corrections plus one small testability refactor.

Production readiness remains **NO-GO**. The independent penetration test remains **NOT PERFORMED (waived)**. CRYPTO-05 remains **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED**. This document reviews a plan; it implements nothing and authorizes nothing. Await explicit owner authorization for the next phase.
