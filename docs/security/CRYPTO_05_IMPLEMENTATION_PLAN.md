# CRYPTO-05 Implementation Plan — Durable Emergency Signing-Key Revocation

- **Status of this document:** Preparation only. No code, migrations, configuration, infrastructure or credentials were changed in producing it.
- **Revision:** 2 (post-independent-review remediation). Revision 1 was reviewed in `docs/security/CRYPTO_05_INDEPENDENT_PLAN_REVIEW.md`; this revision resolves findings F-1…F-9 and corrections C-1…C-8 from that review. The mapping of each finding/correction to the section, resolution, acceptance criterion and test is in `docs/security/CRYPTO_05_REVIEW_REMEDIATION.md`.
- **Repository baseline:** `main` at `f3dd2a1` (synchronized with `origin/main`, clean working tree). PR #35 merged. The design document `docs/security/CRYPTO_05_EMERGENCY_REVOCATION_DESIGN.md` exists and matches the merged version (committed in `c9d3c80`).
- **Current CRYPTO-05 classification:** IMPLEMENTED BUT INSUFFICIENTLY VERIFIED.

Every claim below was verified against current source. Where this plan and the design document disagree, this plan governs because it was checked against the code.

### Revision-2 changelog (what changed from revision 1)

- §1, §3, §6, §7 — removed every claim of "immediate revocation on the revoking engine"; the revocation trigger is a separate process and all signing engines converge within `keyCacheTTL` (or fail closed). (F-1 / C-1)
- §7 — precise signing/revocation race guarantee, including an already-selected key pointer. (F-2 / C-2)
- §4.4 — audit insertion is transaction-scoped on the `tx`, never the pool-bound `Store.Audit`. (F-3 / C-3)
- §4.7 (new) — minimal injectable clock + TTL seam, as a prerequisite work-item (not implemented here). (F-4 / C-4)
- §4.8 (new) — fail-closed behavior after backup restore / PITR via a revocation epoch. (F-6 / C-6)
- §4.9 (new) — idempotency, ambiguous-commit behavior, irreversibility and duplicate-audit prevention. (F-7 / F-8 / F-9 / C-7)
- §4.6 — exact middleware insertion point for the JWKS `Cache-Control`. (C-8)
- §7 — fail-closed-on-stale property credited as a guarantee. (C-5)
- §9 — tests T-A…T-E added; §11 — acceptance criteria rewritten so each maps to at least one test.
- §12 — owner decisions restructured (D1…D7), each with recommendation, alternatives, security and operational implications, and an explicit approval gate; all marked RECOMMENDED DEFAULT — NOT YET APPROVED.

---

## 1. Executive summary

IAM today can revoke a leaked signing key with one primitive: `iamd revoke-key <key-id>`, which hard-deletes the row from `signing_keys`. Because `ListSigningKeys` only returns rows with `expires_at > now()` and feeds the published JWKS, and because every engine reloads its key cache at most `keyCacheTTL` (1 minute) after a change, a deleted key leaves the JWKS and stops signing within roughly one minute across all engines. This is real and works at the store and engine level.

It is **insufficiently verified and structurally fragile** for three reasons, each confirmed by source inspection:

1. **Hard delete with no tombstone.** `DeleteSigningKey` is `DELETE FROM signing_keys WHERE id = $1` (`internal/store/oidc.go:384`). A revoked key leaves no trace. Restoring a database backup taken before revocation, or a replica that has not yet seen the delete, **resurrects** the key — it reappears in `ListSigningKeys` and is republished. There is no mechanism preventing resurrection.
2. **No atomic audit.** Revocation records nothing in `audit_events`; it only emits an `slog.Warn` (`cmd/iamd/main.go:428`). There is no durable, queryable record of who revoked which key, when, or why, and no transaction binding the revocation to such a record.
3. **Propagation is uncontrolled past the engine boundary.** Cross-engine convergence is polling-only (1-minute cache TTL; **no LISTEN/NOTIFY exists in the codebase**). IAM sets **no `Cache-Control` on the JWKS response**, so how long an external resource server keeps trusting a revoked key is governed entirely by that resource server, not by IAM. Already-issued JWT access tokens remain cryptographically verifiable at any resource server until that server refreshes its JWKS cache **and** the token's own `exp` passes.

**Revocation timing model (corrected, F-1/C-1).** The only revocation trigger today — `iamd revoke-key` — is a **separate, short-lived process** (`cmd/iamd/main.go:62`), not one of the running signing engines. It therefore does not and cannot "immediately" change any running engine's in-memory key cache. The guarantee this plan targets is: **once the revocation has durably committed, every running signing engine stops selecting the revoked key within at most one `keyCacheTTL`, provided the database is reachable at that engine's next reload; if the database is unreachable, that engine fails closed and stops signing rather than continuing with a possibly-revoked cached key.** There is no faster "local" case under the current trigger. An optional LISTEN/NOTIFY path (§4.5, D2) can lower the typical latency but never changes the worst-case bound, which stays ≤ `keyCacheTTL`, and never promises anything about already-issued JWTs at external resource servers.

The plan below replaces the hard delete with a durable, state-based revocation model (`ACTIVE`/`RETIRING`/`REVOKED`) recorded together with a tombstone and a **transaction-scoped** audit event in a single transaction, adds resurrection protection that survives backup restore (including a startup fail-closed epoch check), optionally adds LISTEN/NOTIFY to cut cross-engine latency below the cache TTL, and sets an explicit JWKS `Cache-Control` so the external trust window is bounded and stated rather than unknown. It never claims instantaneous global JWT revocation.

This phased approach corresponds to **Strategy E / Architecture 2 (phased)** recommended in the design document, now grounded in exact source references and corrected by the independent review.

---

## 2. Current implementation findings

### 2.1 Storage and schema

- Table `signing_keys` (`internal/db/migrations/0001_init.sql:159`):
  ```sql
  CREATE TABLE signing_keys (
      id               text PRIMARY KEY,
      algorithm        text        NOT NULL,
      private_key_enc  bytea       NOT NULL, -- master-key sealed PKCS#8
      created_at       timestamptz NOT NULL DEFAULT now(),
      rotate_at        timestamptz NOT NULL, -- stop signing with it after this
      expires_at       timestamptz NOT NULL  -- drop from JWKS after this
  );
  ```
  There is **no state column, no revoked_at, no tombstone**. Revocation is expressed only by the row's absence.
- Index `signing_keys_expires_idx ON signing_keys (expires_at)` (`0008_perf_and_enroll_cap.sql:24`).
- Private keys are sealed with the master key (`encryptedColumns`, `internal/store/oidc.go:404`) and are subject to master-key rotation / re-encryption (`Reencrypt`, `oidc.go:476`).

### 2.2 `Store.DeleteSigningKey`

`internal/store/oidc.go:384`:
```go
func (s *Store) DeleteSigningKey(ctx context.Context, id string) error {
    return s.execOne(ctx, `DELETE FROM signing_keys WHERE id = $1`, id)
}
```
- Hard delete. `execOne` (`internal/store/store.go:60`) returns `ErrNotFound` when zero rows match (no-op on unknown id).
- **Not** wrapped in a transaction; writes **no** audit record.
- Irreversible: the sealed private key is gone, so the action cannot be inspected or rolled back afterward.

### 2.3 Key loading and caching

`internal/oidcop/keys.go`:
- `keyStore` holds `keys []*signingKey` (newest first) and `loadedAt` in memory (`keys.go:50`).
- `keyCacheTTL = time.Minute` (`keys.go:22`); `publishLead = 3 * keyCacheTTL` (`keys.go:26`). Both are compile-time `const`; the store reads wall-clock `time.Now()` directly (`keys.go:79,85,122,159`). This matters for testability (§4.7).
- `current()` reloads when `time.Since(loadedAt) > keyCacheTTL`, the cache is empty, or `needsNewKey` (`keys.go:64`). On a reload error it returns `nil,nil,err` and does **not** serve stale keys (`keys.go:68-72`) — a verified fail-closed property (§7, C-5).
- `load()` calls `ListSigningKeys`, then decrypts **every** returned row with `box.Open` (`keys.go:126`). A decrypt/parse failure on any single row fails the whole load and therefore blocks signing (`keys.go:134-144`).

### 2.4 Key selection during signing

- `ListSigningKeys` returns rows with `expires_at > now()`, newest first (`internal/store/oidc.go:360`).
- `signer()` picks the newest key published for at least `publishLead`, else the oldest (`keys.go:84`).
- If the active signer is revoked, the next reload drops it; `signer()` selects the next eligible published key, and if `needsNewKey` holds, `reload()` generates a successor under an advisory lock (`keys.go:94-124`, `generate()` at `keys.go:150`). Signing continues after revoking the active key.

### 2.5 Internal JWT verification

- **IAM does not re-verify its own JWT access tokens.** JWT profile key lookup is unsupported: `GetKeyByIDAndClientID` returns `"jwt profile grant is not supported"` (`internal/oidcop/storage.go:538`).
- Access-token type is per client: `AccessTokenTypeJWT` (default) or `AccessTokenTypeBearer` (opaque) (`internal/oidcop/models.go:54`). Opaque/bearer tokens are introspected **live** against the database. JWT access tokens are self-contained and verified by **external resource servers** using the JWKS.
- Consequence: "no acceptance of revoked keys by internal verification" is largely **not applicable inside IAM** — the verification boundary that matters is external. IAM must never claim it can refuse already-issued JWTs minted before revocation.

### 2.6 JWKS endpoint and HTTP cache headers

- The JWKS handler is zitadel `op`'s `/keys` handler (`pkg/op/keys.go:22`), which calls `httphelper.MarshalJSON` — that sets only `content-type: application/json` (`pkg/http/marshal.go:16`). The route is mounted bare (`pkg/op/op.go:156`). **The library sets no `Cache-Control` and no caching middleware wraps it.**
- `/keys` is rate-limited on a generous `oauth-metadata` budget (`cmd/iamd/main.go:724,732`) — a rate limit, not an HTTP cache directive.
- IAM's only `Cache-Control` is `no-store` on token responses (`cmd/iamd/main.go:658`, RFC 6749 §5.1). Downstream JWKS caching is therefore uncontrolled by IAM today.

### 2.7 Refresh-token and session revocation

- Refresh tokens are opaque (hashed `token_hash`, `family_id`) and **not** signed by a signing key. Revoked by family (`RevokeRefreshFamily`, `oidc.go:286`) and by user/org/app/project scope (`oidc.go:215-315`).
- `revoke-key` does **not** touch refresh tokens or sessions. Key revocation is not session revocation; the two are orthogonal (D4).

### 2.8 PostgreSQL transactions and migrations

- Transaction idiom: `pgx.BeginFunc(ctx, s.pool, func(tx) error { ... })` (e.g. `RevokeRefreshFamily`, `oidc.go:287`).
- Key-generation serialization: `pg_advisory_xact_lock(727274)` in `LockSigningKeys` (`oidc.go:390`).
- Migrations: embedded `internal/db/migrations/*.sql`, lexical order, each in its own transaction, serialized by a session advisory lock (`internal/db/db.go:67`). Latest is `0010_recovery_codes.sql`; next is `0011_*.sql`.

### 2.9 Audit mechanism

- `Store.Audit` (`internal/store/audit.go:24`) is fire-and-forget: it runs its own `s.pool.Exec` and logs write failures without returning them. It **cannot be made atomic** with a caller transaction as written — it holds no `tx`. The remediation does not reuse it (§4.4).
- `audit_events(id bigserial, at, org_id, actor, action, target, ip, detail jsonb)` (`0002_hardening.sql:38`). `id` is `bigserial` with no natural-key uniqueness, so nothing prevents two rows for one logical event (F-9, addressed in §4.9).

### 2.10 Multi-instance behavior

- No leader; every engine runs the same `keyStore`. Convergence is **polling only** at `keyCacheTTL` (1 min). There is **no LISTEN/NOTIFY, no pub/sub, no Redis**. Advisory locks serialize only generation and migrations.

### 2.11 Startup and recovery behavior

- `keyStore` loads lazily on first `current()`; an empty table generates a key under lock.
- **Backup restore / replica lag resurrects revoked keys** with the current hard delete and no tombstone. This is the single most important durability gap.
- `PurgeExpired` deletes `signing_keys WHERE expires_at < now()` (`oidc.go:331`, `PurgedTables` `oidc.go:321`). Any future tombstone must be excluded from this purge or it will be reaped.

### 2.12 Existing signing-key tests and infrastructure

- `internal/store/signing_key_revoke_test.go` — `TestDeleteSigningKeyRemovesFromList` (DB-gated on `IAM_TEST_DATABASE_URL`).
- `go test -race` and DB tests run in CI only. A previous oidcop-level cross-package test (`TestRevokedKeyLeavesJWKSAndResigns`) was removed in PR #34 as flaky by construction (whole-table counts under a shared DB). **Any new engine-level test must be isolation-safe** — scope to keys it inserts, never assert whole-table counts.

---

## 3. Threat model

**Asset:** the RSA private signing key(s) for RS256 JWT access tokens and ID tokens.

**Primary threat (CRYPTO-05):** a signing key is compromised. An attacker who holds the private key can forge tokens that any resource server trusting IAM's JWKS accepts, for the key's full validity window.

**Attacker capabilities considered:** forge JWTs offline; replay issued tokens; re-introduce a revoked key via restored backup or promoted lagging replica (resurrection); race a revocation against in-flight signing.

**Defender goals, in order:** (1) stop signing new tokens with the key on every engine quickly and boundedly; (2) remove it from the JWKS; (3) make revocation durable against restore/replication; (4) produce an immutable attributable audit record; (5) bound and **state** the residual external-JWT window.

**Explicitly not achievable:** instantaneous recall of already-issued self-contained JWTs at third-party resource servers.

**Trust boundaries (corrected, F-1/C-1):**
- *Revocation trigger:* a separate CLI process, **not** a signing engine; it changes no running engine's cache directly.
- *Propagation to signing engines:* each running engine stops selecting the revoked key within ≤ `keyCacheTTL` of the committed revocation **when the database is reachable at its reload**; otherwise it fails closed (stops signing). There is no immediate-local case.
- *External resource servers:* **not controlled by IAM**; bounded by each server's JWKS cache policy plus token `exp`.

---

## 4. Proposed architecture

### 4.1 Durable key states

| State | Meaning | In JWKS? | Signs? |
|-------|---------|----------|--------|
| `ACTIVE` | Normal signer or publishable successor | Yes | Yes (per existing `signer()`) |
| `RETIRING` | No longer signs; still published so its recently issued tokens verify until `expires_at` | Yes | No |
| `REVOKED` | Compromised; must not sign and must not be published | No | No |

`REVOKED` is **terminal** (see §4.9 on irreversibility).

### 4.2 Revocation replaces hard delete

Emergency revocation becomes a state transition (`ACTIVE`/`RETIRING` → `REVOKED`) plus a durable **tombstone**, not a `DELETE`. The sealed private key may be scrubbed to a sentinel while the tombstone row and its audit linkage are retained. `ListSigningKeys` must exclude `REVOKED` and tombstoned rows so they never reach the JWKS or the signer.

### 4.3 Resurrection protection

Keep a durable tombstone of every revoked key id in a table that is **not** subject to `expires_at` purging. On load, the engine subtracts any tombstoned id from the candidate set, so a reappearing `signing_keys` row (restored backup, lagging replica) is never republished or used to sign. **The tombstone is the authority; row presence is not.**

### 4.4 Atomic revocation + transaction-scoped audit (F-3 / C-3)

`Store.RevokeSigningKey(ctx, id, actor, reason)` runs **one** `pgx.BeginFunc` transaction that performs, on the transaction handle `tx`:
1. `UPDATE signing_keys SET state='REVOKED', revoked_at=now(), revoked_reason=$reason WHERE id=$id AND state <> 'REVOKED'`.
2. `INSERT INTO revoked_signing_keys (id, revoked_by, reason) VALUES ($id,$actor,$reason) ON CONFLICT (id) DO NOTHING`.
3. `INSERT INTO audit_events (actor, action, target, detail) VALUES (...)` **executed on `tx`** (`tx.Exec`), gated so it runs only when step 2 inserted a new row (see §4.9). It bumps the revocation epoch (§4.8) in the same transaction.

The audit insert is written inline on `tx`. **`Store.Audit` is not used** — it is pool-bound and swallows errors (`internal/store/audit.go:24`), so it cannot be part of this transaction. Either all three statements commit or none do. The function returns the `BeginFunc`/commit error unchanged, so the CLI reports success only after a durable commit (F-7).

### 4.5 Cross-engine invalidation (phased) (C-1)

- **Phase 1 (baseline, present):** polling at `keyCacheTTL`. Worst-case convergence ≤ `keyCacheTTL` when the database is reachable; otherwise the engine fails closed. No new infrastructure.
- **Phase 2 (optional, D2):** Postgres `LISTEN/NOTIFY` on a `signing_keys` channel; the revoking transaction issues `pg_notify`, each engine forces an immediate `reload()` on receipt. **Polling remains the correctness guarantee**; NOTIFY is a best-effort latency optimization and is allowed to be lost across a reconnect or partition. The worst-case bound stays ≤ `keyCacheTTL` regardless.

### 4.6 JWKS cache policy (C-8)

Add an IAM middleware that sets `Cache-Control: public, max-age=<N>` on `GET /keys`, inserted **before** the zitadel `op` handler in the chain — at the same layer as `securityHeaders` (`cmd/iamd/main.go:432`), which already sets response headers before `next.ServeHTTP`, so the header is present before the handler calls `w.Write` (which flushes `200`). The library sets no competing header (§2.6), so no override conflict exists. `N` is an owner decision (D1; recommended default 300 s). This bounds and **states** the external trust window; it cannot shorten a resource server that ignores the directive.

### 4.7 Minimal clock + TTL seam (prerequisite, F-4 / C-4)

Deterministic timing tests (9, 11, 13, and T-B timing) require a seam. The minimal design, **to be implemented in the implementation phase, not here**:
- Add two fields to `keyStore`, defaulted from the existing consts, so tests can shorten them:
  `cacheTTL time.Duration` (default `keyCacheTTL`), `publishLead time.Duration` (default `publishLead`).
- Add `now func() time.Time` to `keyStore`, defaulting to `time.Now`, and replace the four direct `time.Now()` / `time.Since` reads (`keys.go:79,85,122` and the `current()` comparison at `:68`) with `ks.now()`.
- No behavior change in production (defaults preserve current values); the seam only lets tests inject a fast clock and a short TTL.

This plan documents the seam; **it does not implement it** (authorization boundary §7 of the task). D7 is the owner gate to approve the refactor.

### 4.8 Fail-closed after backup restore / PITR (F-6 / C-6)

Add a monotonically increasing **revocation epoch** persisted in a single-row table, incremented inside every revocation transaction (§4.4 step 3). Each engine records the epoch it last observed. On startup and on each reload:
- If the database epoch is **lower** than the last epoch this engine durably observed (possible only after a restore/PITR to an older state), the engine treats the key state as **unreconciled** and **refuses to sign** (fails closed) until an operator acknowledges the restore and re-applies outstanding revocations (replaying tombstones from `audit_events` / an out-of-band revocation list). JWKS publication of any key whose id is tombstoned remains suppressed regardless.
- If the epoch is equal or higher, normal operation continues.

This converts the silent resurrection window into an explicit fail-closed state. The epoch row and `revoked_signing_keys` must both be part of the backup set (D3); a restore that predates both still requires the operator runbook, but the engine will not silently resurrect — it blocks signing on the epoch regression. Recommended as the default safeguard; the alternative (documented residual only, no epoch) is D3.

### 4.9 Idempotency, ambiguous commit, irreversibility, duplicate audit (F-7 / F-8 / F-9 / C-7)

- **Idempotency / duplicate audit (F-9):** `revoked_signing_keys.id` is the primary key; step 2 uses `ON CONFLICT (id) DO NOTHING`. Step 3 (audit + epoch bump) executes **only if step 2 actually inserted a row** (detected via `RETURNING` / rows-affected on step 2). A second revocation of the same id therefore produces **no second audit row and no epoch bump**, while the `UPDATE` in step 1 is naturally idempotent (`WHERE state <> 'REVOKED'`). Exactly one audit event per logical revocation.
- **Ambiguous COMMIT (F-7):** if the connection drops during `COMMIT`, pgx returns an error although the transaction may have committed. `RevokeSigningKey` returns that error and the CLI reports failure. The operator **re-runs the same command**; because the whole operation is idempotent (above), the re-run is safe whether or not the first attempt committed. This guidance goes in the operator output and the runbook.
- **Irreversibility / mistaken revocation (F-8):** `REVOKED` is terminal and the tombstone is permanent by design (resurrection protection). A mistaken revocation is **unrecoverable for that key** — exactly as irreversible as today's hard delete; the durability improvement adds no undo. Recovery from a mistaken revocation is automatic **successor promotion/generation** (`keys.go:94-124`): a new key is produced and signing continues; the mistakenly revoked key stays dead. Operator output must state this before acting.

---

## 5. Database and migration design

New migration `internal/db/migrations/0011_signing_key_revocation.sql` (illustrative; **proposed, not applied**):

```sql
-- Durable lifecycle state for signing keys (CRYPTO-05).
ALTER TABLE signing_keys
    ADD COLUMN state text NOT NULL DEFAULT 'ACTIVE'
        CHECK (state IN ('ACTIVE', 'RETIRING', 'REVOKED')),
    ADD COLUMN revoked_at timestamptz,
    ADD COLUMN revoked_reason text;

-- Resurrection tombstone: authoritative list of revoked key ids, never purged
-- by expires_at. A restored backup or lagging replica cannot republish a key
-- whose id is present here.
CREATE TABLE revoked_signing_keys (
    id          text PRIMARY KEY,         -- the signing_keys.id that was revoked
    revoked_at  timestamptz NOT NULL DEFAULT now(),
    revoked_by  text NOT NULL,            -- actor, same convention as audit_events.actor
    reason      text NOT NULL DEFAULT ''
);

-- Single-row revocation epoch; bumped inside every revocation transaction so a
-- restore/PITR to an older state is detectable and signing can fail closed (4.8).
CREATE TABLE signing_key_revocation_epoch (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    epoch     bigint  NOT NULL DEFAULT 0
);
INSERT INTO signing_key_revocation_epoch (singleton, epoch) VALUES (true, 0);
```

Accompanying code changes (proposed, not implemented):
- `ListSigningKeys` adds `AND state <> 'REVOKED' AND id NOT IN (SELECT id FROM revoked_signing_keys)` (`internal/store/oidc.go:360`).
- `revoked_signing_keys` and `signing_key_revocation_epoch` are **excluded** from `PurgedTables` (no `expires_at`; `oidc.go:321`).
- `Reencrypt` (`oidc.go:476`) tolerates a scrubbed/sentinel `private_key_enc` on revoked rows, or excludes them from the encrypted scan.
- The audit insert in §4.4 is `tx.Exec` on the revocation transaction, not `Store.Audit`.

Migration safety: additive columns/tables plus one seed row; no destructive change; replay-safe under the advisory-locked migrator (`db.go:67`).

---

## 6. API and operator behavior

- Keep the `iamd revoke-key <key-id>` entry point (`cmd/iamd/main.go:62`); repoint it to `Store.RevokeSigningKey` (§4.4). Require `--reason` (or `IAM_REVOKE_REASON`) so the audit record is never empty; default actor `"system"` unless an operator identity is supplied.
- `DeleteSigningKey` is retained only for test fixtures and genuine hard-deletion needs; it is no longer the revocation path.
- Availability after revoking the active signer is preserved by successor promotion/generation (`keys.go:94-124`).
- Operator output must state the **corrected** guarantee verbatim in substance:
  "Revocation committed. Every running signing engine stops using this key within about one minute (one key-cache interval) when the database is reachable; an engine that cannot reach the database stops signing rather than keep using a cached key. The key leaves the JWKS. Already-issued JWT access tokens remain valid at external resource servers until their JWKS cache refreshes and the token `exp` passes — IAM cannot recall them. This revocation is irreversible for this key; if it was a mistake, a successor key is generated automatically and signing continues, but this key stays revoked. If this command reported an error, re-run it; the operation is idempotent."
  Never "instantly revoked everywhere" and never "immediately on this engine."

---

## 7. Multi-instance consistency model

- **Correctness guarantee (always holds):** after a revocation durably commits, no signing engine **selects** the revoked key for a *new* signing operation more than one `keyCacheTTL` after commit, provided the database is reachable at that engine's reload; if it is not reachable, the engine returns an error from `current()` and **does not sign** (verified fail-closed, `keys.go:68-72`, C-5). Polling alone provides this; it does not depend on NOTIFY.
- **Signing/revocation race, precise (F-2 / C-2):** `current()` returns a `*signingKey` under the mutex, then the lock is released and the token is signed outside the lock. A request that **already obtained** the key pointer immediately before a local reload can still complete and mint **one** token carrying the revoked `kid`. The guarantee is therefore: *no new key selection returns a revoked key after the engine's reload observes the revocation; a signing operation that already selected the key may complete.* This residual single-token window is inherent to any cached-key design and is bounded by the duration of one in-flight sign.
- **Latency optimization (best-effort):** LISTEN/NOTIFY (D2) lowers typical convergence to sub-second but may be lost; polling is the backstop and the worst-case bound stays ≤ `keyCacheTTL`.
- **Write serialization:** concurrent revocations of the same id are idempotent via the tombstone PK and the `state <> 'REVOKED'` guard (§4.9); no generation advisory lock is needed for revocation.

---

## 8. Failure-mode analysis

| Failure | Current behavior | Behavior under this plan |
|---------|------------------|--------------------------|
| Database unavailable during revocation | `DeleteSigningKey` errors; nothing recorded | Transaction fails atomically; nothing applied; operator retries. Fail-closed; no false "revoked". |
| Database unavailable during signing | `current()` errors; signing fails (fail-closed) | Unchanged (fail-closed preserved, `keys.go:68-72`). |
| Backup restored / PITR to pre-revocation state | Key resurrected silently | Epoch regression detected → engine **refuses to sign until reconciled** (§4.8); tombstone (if restored) still suppresses the key. A restore predating both epoch and tombstone still needs the runbook, but signing blocks rather than resurrecting silently. |
| Lagging replica promoted | Key may reappear | Tombstone suppresses on load once replayed; epoch regression blocks signing if the promoted replica is behind. Window bounded by lag + TTL. |
| NOTIFY lost / partition | N/A | Polling converges within `keyCacheTTL`; correctness unaffected. |
| Stale engine cache | ≤1 min window | ≤1 min window, then reload or fail-closed; never unbounded stale signing. |
| Concurrent revocations of same id | Second `DELETE` is `ErrNotFound` | Idempotent; exactly one tombstone, one audit row, one epoch bump (§4.9). |
| Ambiguous COMMIT | N/A | CLI reports error; operator re-runs; idempotent (§4.9). |
| Revoke the only/active key | Successor promoted/generated | Unchanged; availability preserved. |
| Mistaken revocation | Irreversible (hard delete) | Irreversible for that key; successor auto-generated; stated to operator (§4.9). |
| Already-issued JWT at external RS | Valid until RS cache refresh + `exp` | Unchanged and unavoidable; bounded and stated via explicit JWKS `max-age`. |
| Clock behind real time | Windows lengthen | NTP SLA prerequisite; windows are upper bounds (D5 shortens the external window via token TTL). |

---

## 9. Test matrix

Legend per row: **Invariant → setup → expected → failure condition → test type.** All DB-gated tests are isolation-safe (scope to inserted ids; never whole-table counts — §2.12). Race tests are CI-only. Tests 9, 11, 13 and T-B timing require the §4.7 clock/TTL seam first.

1. **ACTIVE → REVOKED removes from list.** Insert active key; revoke; assert absent from `ListSigningKeys`, present in `revoked_signing_keys`. *Unit/integration (DB).*
2. **RETIRING → REVOKED.** Insert retiring key; revoke; assert removed from JWKS candidate set. *Integration (DB).*
3. **Revoked key cannot be selected to sign.** Revoke; force engine reload; assert `signer()` never returns it. *Integration (DB).*
4. **Revoked key absent from `KeySet`/`/keys`.** Revoke; assert absent from published set. *Integration (DB + HTTP).*
5. **Revocation survives restart.** Revoke; recreate engine against same DB; assert suppressed. *Integration (DB).*
6. **Revocation survives backup restore.** Dump after revocation; restore to fresh DB; assert tombstone present and key suppressed. *Integration (DB, scripted).*
7. **Concurrent signing and revocation.** Signer loop + revoke; assert no *new* token is signed with the revoked key after commit (allowing one already-selected in-flight token, §7). *Race (CI).*
8. **Concurrent revocation requests.** Two revocations of same id; assert idempotent, one tombstone row, one audit row, one epoch bump. *Race (CI).*
9. **Multiple engines converge.** Two `keyStore`s on one DB (short injected TTL); revoke via one; assert the other stops selecting it within `cacheTTL`. *Integration (DB; needs §4.7).*
10. **LISTEN/NOTIFY failure falls back to polling.** NOTIFY disabled/error injected; assert convergence still occurs within `cacheTTL`. *Integration (DB).*
11. **Polling fallback timing.** NOTIFY off; assert convergence ≤ `cacheTTL`. *Integration (DB; needs §4.7).*
12. **Database outage during revocation.** Inject mid-transaction failure; assert nothing applied (no tombstone, no state change, no audit, no epoch bump). *Integration (DB).*
13. **Stale cache window.** Injected clock; assert the cache refuses the revoked key no later than `loadedAt + cacheTTL`. *Unit (needs §4.7).*
14. **JWKS cache header.** Assert `/keys` sets `Cache-Control: public, max-age=N` and that it is set before the handler writes. *Unit (HTTP).*
15. **External RS limitation documented.** Assert operator output and docs state non-recall of issued JWTs. *Doc/lint.*
16. **Audit transaction rollback.** Force the audit insert to fail inside the transaction; assert state change, tombstone and epoch bump also roll back. *Integration (DB).*
17. **Tombstone/epoch retention vs purge.** Run `PurgeExpired`; assert `revoked_signing_keys` and `signing_key_revocation_epoch` rows are **not** deleted. *Integration (DB).*
- **T-A — Tombstone overrides row presence.** Insert a `signing_keys` row **and** a `revoked_signing_keys` tombstone for the same id; assert `load()`/`ListSigningKeys` never returns it and `KeySet` omits it. Fail if the key is loaded, published, or signs. *Unit/integration (DB), isolation-safe.* (Direct proof of acceptance criterion 1 / resurrection.)
- **T-B — Post-revocation JWKS verification fails.** Sign a JWT with key K; revoke K; fetch `KeySet`/`/keys`; assert verifying that JWT against the published set fails because K's `kid` is absent. Fail if verification succeeds. *Integration (DB + crypto).*
- **T-C — Idempotent revocation re-run.** Call `RevokeSigningKey` twice for the same id (simulating a retried ambiguous commit); assert second call is a no-op on state, returns no error, and leaves exactly one tombstone row, one audit row, and an unchanged epoch after the first. *Integration (DB).*
- **T-D — Replica lag / stale read suppresses signing.** Present a read where the key row still looks `ACTIVE` while the tombstone exists (read key row and tombstone separately); assert the tombstone wins and the key is neither published nor signed with. Fail if the stale `ACTIVE` view is honored. *Integration (DB).*
- **T-E — Restore without tombstone fails closed.** Simulate an epoch regression (DB epoch < engine's last observed epoch); assert the engine refuses to sign until an operator ack and suppresses any tombstoned id. If the epoch safeguard (§4.8) is **not** adopted (D3 alternative), this degrades to a doc/runbook assertion that the resurrection window is an accepted, documented residual. *Integration (DB) or doc/lint.*

---

## 10. Rollout and rollback strategy

**Rollout (phased):**
1. Migration `0011` (additive columns + `revoked_signing_keys` + `signing_key_revocation_epoch`). No behavior change.
2. Clock/TTL seam (§4.7) — testability prerequisite, no production behavior change (D7).
3. `Store.RevokeSigningKey` (transactional state + tombstone + tx-scoped audit + epoch bump); repoint `revoke-key`; update `ListSigningKeys` predicate and `PurgeExpired` exclusions; add the epoch fail-closed check (§4.8).
4. Explicit JWKS `Cache-Control` middleware (§4.6).
5. (Optional) LISTEN/NOTIFY as a latency optimization, polling remaining the guarantee (D2).

**Rollback:** phases 2–5 are code-only and revert by redeploying the prior binary; the additive phase-1 schema is forward-compatible (old binaries ignore new columns/tables) and need not be dropped. Migrations are forward-only, so rollback is "redeploy old binary," not "drop column." No rollback can un-issue already-minted JWTs.

---

## 11. Acceptance criteria (each maps to ≥1 test)

| # | Criterion | Test(s) |
|---|-----------|---------|
| 1 | Tombstone overrides row presence: a present-but-tombstoned key is never loaded, published, or signed with | **T-A**, 5, 6 |
| 2 | Revocation + tombstone + tx-scoped audit + epoch bump commit atomically or not at all | 16, 12 |
| 3 | Revoked keys absent from `ListSigningKeys`, `KeySet`, `/keys` on all engines within `cacheTTL` when DB reachable, else signing halts | 3, 4, 9, 11 (need §4.7) |
| 4 | A token signed by a revoked key fails verification against the post-revocation JWKS | **T-B** |
| 5 | Revocation survives restart and post-revocation backup restore | 5, 6 |
| 6 | Replica lag / stale read cannot expose a revoked key | **T-D** |
| 7 | `PurgeExpired` never reaps tombstones or the epoch row | 17 |
| 8 | `/keys` carries an explicit bounded `Cache-Control` set before the handler writes | 14 |
| 9 | Concurrency safe and idempotent, including ambiguous-commit re-run; exactly one audit row per revocation | 7, 8, **T-C** (race, CI) |
| 10 | Operator output and docs state the honest guarantee (no immediate global revocation; irreversible for the key; re-run on ambiguous failure) | 15 + doc review |
| 11 | Restore/PITR regression fails closed (or is an explicitly accepted, documented residual) | **T-E** |

Criteria 3 and tests 9/11/13 are gated on the §4.7 clock/TTL seam (D7).

---

## 12. Owner decisions (D1–D7)

Each decision below is a **RECOMMENDED DEFAULT — NOT YET APPROVED**. No owner decision is made here; implementation of any option requires explicit owner approval.

### D1 — JWKS `Cache-Control max-age`
- **Recommendation (default):** `public, max-age=300` (5 minutes).
- **Alternatives:** shorter (e.g. 60 s) for a tighter external window at higher JWKS fetch load; longer (e.g. 3600 s) for less load but a wider window; `no-cache` to force revalidation (highest load).
- **Security implications:** `N` is the stated upper bound on how long a compliant resource server keeps trusting a revoked key after it leaves the JWKS. Non-compliant servers ignore it.
- **Operational implications:** lower `N` increases `/keys` request volume (rate-limited on the metadata budget, `main.go:724`); higher `N` reduces load but lengthens the external window.
- **Approval required:** owner selects `N`.

### D2 — LISTEN/NOTIFY versus polling
- **Recommendation (default):** ship polling only first (meets the correctness bar); add LISTEN/NOTIFY later as a latency optimization if sub-minute convergence is required.
- **Alternatives:** ship NOTIFY immediately; never ship NOTIFY.
- **Security implications:** none to the worst-case bound (stays ≤ `keyCacheTTL`); NOTIFY only reduces typical latency.
- **Operational implications:** NOTIFY adds a dedicated listener connection per engine and reconnect handling; must never become a correctness dependency (a bug that blocks signing on NOTIFY availability would be a self-inflicted outage).
- **Approval required:** owner decides whether/when to add NOTIFY.

### D3 — Tombstone backup and restore policy
- **Recommendation (default):** adopt the revocation-epoch fail-closed safeguard (§4.8) **and** include `revoked_signing_keys` and `signing_key_revocation_epoch` in the backup set; define a runbook that replays tombstones from `audit_events` after any restore predating them.
- **Alternatives:** documented residual only (no epoch safeguard) — accept that a pre-tombstone restore can resurrect a key, mitigated solely by backup hygiene.
- **Security implications:** without the epoch safeguard, a restore/PITR silently resurrects revoked keys; with it, signing fails closed on epoch regression.
- **Operational implications:** the epoch check can block signing after a legitimate restore until an operator acknowledges — a deliberate availability-for-safety trade.
- **Approval required:** owner chooses safeguard vs. documented residual, and confirms backup inclusion.

### D4 — Session and refresh-token coupling
- **Recommendation (default):** keep key revocation orthogonal to session/refresh revocation; document that "eject the subject" requires calling the existing refresh/session revocation paths (`oidc.go:286-315`) as well.
- **Alternatives:** automatically revoke affected subjects' sessions/refresh families on key revocation.
- **Security implications:** coupling ensures a compromised-key incident also ends live sessions; decoupling avoids mass logout on a routine key issue.
- **Operational implications:** coupling can log out large user populations on a single revocation.
- **Approval required:** owner decides coupling.

### D5 — Access-token TTL
- **Recommendation (default):** review and consider shortening the default access-token lifetime (currently 5 minutes) — the only control that shrinks the irreducible external-JWT window.
- **Alternatives:** keep 5 minutes; shorten further (more token/introspection traffic); lengthen (worse exposure).
- **Security implications:** shorter TTL directly shortens how long a forged or pre-revocation JWT is accepted externally.
- **Operational implications:** shorter TTL increases token refresh and issuance load.
- **Approval required:** owner sets the TTL.

### D6 — Authorization / approval gate for revocation
- **Recommendation (default):** keep the CLI trigger but add audited operator identity (actor in the audit record) and consider a two-person confirmation for production.
- **Alternatives:** CLI-only with host+DB creds (status quo); a dedicated authenticated admin endpoint; mandatory two-person approval.
- **Security implications:** today anyone with host access and DB creds can revoke (and the action is irreversible); an approval gate reduces malicious/accidental revocation risk.
- **Operational implications:** an approval gate slows emergency response — the thing most needed in a key-compromise incident; balance carefully.
- **Approval required:** owner decides the authorization model.

### D7 — Clock/TTL injection prerequisite
- **Recommendation (default):** approve the minimal seam in §4.7 as an implementation prerequisite, because acceptance criterion 3 and tests 9/11/13 cannot be met deterministically without it.
- **Alternatives:** no seam (those tests remain slow/flaky or cannot run); a larger time-abstraction refactor (unnecessary scope).
- **Security implications:** none in production (defaults preserve current values).
- **Operational implications:** trivial, internal-only; no config or behavior change.
- **Approval required:** owner approves the refactor as part of the implementation phase (this plan does not implement it).

---

## 13. Control classification summary

| Control | Classification |
|---------|----------------|
| Hard-delete revocation removes key from `ListSigningKeys`/JWKS within ~1 min | **Existing and verified** (`TestDeleteSigningKeyRemovesFromList`) |
| Fail-closed on reload error (no stale-key signing) | **Existing and verified** (`keys.go:68-72`) |
| Active-signer revocation preserves availability | **Existing but insufficiently verified** (no isolation-safe engine test since #34) |
| Durable key state (`ACTIVE`/`RETIRING`/`REVOKED`) | **Proposed** |
| Resurrection tombstone (`revoked_signing_keys`) | **Missing** today → **Proposed** |
| Revocation epoch fail-closed on restore/PITR | **Missing** today → **Proposed / Blocked by D3** |
| Atomic revocation + **tx-scoped** audit + epoch bump | **Missing** today → **Proposed** |
| Idempotency / single audit per revocation | **Missing** today → **Proposed** |
| Explicit JWKS `Cache-Control` | **Missing** today → **Proposed** |
| Clock/TTL seam for deterministic tests | **Missing** today → **Proposed / Blocked by D7** |
| Cross-engine sub-second invalidation (LISTEN/NOTIFY) | **Proposed / Blocked by D2** |
| Honest "no instantaneous global JWT revocation" statement | **Proposed** (enforced in operator output + docs) |
| Session/refresh coupling | **Blocked by D4** |
| Approval/authorization gate for `revoke-key` | **Blocked by D6** |

---

## 14. Confirmation of boundaries

No application code, migration, configuration, secret, signing key, service, DNS/tunnel/infrastructure, staging or production state was created, executed or modified in producing this plan, and the §4.7 clock/TTL seam and all other code changes described are **proposals, not implementations**. No commit, push, PR or merge was made. `vps-ai-pbx` and `zitadel-stack` were not accessed. Production readiness remains **NO-GO**; the independent penetration test remains **NOT PERFORMED (waived)**; CRYPTO-05 remains **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED**. This document is a plan; it implements nothing and authorizes nothing. Await explicit owner authorization for the next phase.
