# CRYPTO-05 — Emergency Signing-Key Revocation — Design

**Type:** Architecture & security design. **DESIGN ONLY — nothing implemented.** This file is the only artifact created (not committed/pushed).
**Date:** 2026-10-30. **Baseline:** `main` @ `54ca2a0` (working tree clean apart from the three new `docs/security/` assessment docs; 0 open PRs).

**Legend for every claim below:**
🟩 **Existing-verified** (read from code/tests on `54ca2a0`) · 🟦 **Proposed** · 🟨 **Assumption** · 🟥 **Unverified / cannot be proven here** · ⚖️ **Owner decision required**.

---

## 1. Executive summary

Emergency signing-key revocation must do one honest thing well: **make a leaked signing key stop being trusted as fast as the architecture can actually enforce, and never let it come back.** Today's `iamd revoke-key` is a hard `DELETE` of a `signing_keys` row — it removes the key from *future* JWKS responses but provides no durable revoked state, no audit record, no cross-instance invalidation faster than a 1-minute cache TTL, and **no control at all over already-issued JWTs at external resource servers**.

This design proposes:

- 🟦 A **persistent key-state model** (`ACTIVE` / `RETIRING` / `REVOKED`) stored in Postgres, replacing hard delete with a **durable, irreversible REVOKED tombstone** so a revoked key can never be resurrected by restart, cache expiry, or a DB restore.
- 🟦 **Revocation + audit in one transaction**, success reported only after commit (never fail-open / never false success).
- 🟦 **Postgres-native cross-instance invalidation** (`LISTEN/NOTIFY` push, with the existing TTL poll as fallback) giving a **measurable internal propagation bound** — no Redis, no new infrastructure.
- 🟦 A short `Cache-Control: max-age` on `/keys` plus a **documented required RS JWKS-refresh TTL**, to *shorten* (never zero) the external window.
- 🟦 A clear, honest guarantee split: IAM can make its **own** verification, introspection, signing and refresh/session state consistent within a bounded internal time; it **cannot** force an external resource server to drop an already-issued JWT before that token's `exp` (default **5 minutes**) — that requires RS cooperation.

**Recommended backbone:** short-lived JWTs (already 5 min) + authoritative refresh/session revocation + durable key-state tombstone + `kid` denylist on IAM's own verification paths + JWKS removal with short cache. This is Strategy **E (hybrid of D + A + C)** below. It is proportionate to a self-hosted IAM serving first-party SaaS: no per-request online introspection mandated for ordinary RS, no microservices, no custom cryptography.

---

## 2. Current implementation and verified limitations

🟩 **Signing-key storage** — `internal/store/oidc.go`: table `signing_keys(id, algorithm, private_key_enc, created_at, rotate_at, expires_at)` (migration `0001_init.sql`). `InsertSigningKey`, `ListSigningKeys` (`WHERE expires_at > now() ORDER BY created_at DESC`), `LockSigningKeys` (advisory-lock serialized generation), and `DeleteSigningKey` (`WHERE id=$1`, hard delete) at `internal/store/oidc.go:384`. **No state/revoked column.**

🟩 **Key store / cache** — `internal/oidcop/keys.go`: `keyStore` caches keys in-process; `keyCacheTTL = 1 * time.Minute`; `publishLead = 3 * keyCacheTTL`. `current()` reloads on TTL expiry / empty / `needsNewKey`; `signer()` picks the newest key published ≥ `publishLead`; `KeySet()` returns every loaded key as a `publicKey`. `generate()` creates RS256 2048-bit keys with `rotate_at = now + rotation`, `expires_at = now + 2*rotation`.

🟩 **JWKS endpoint** — served by the vendored library `op.Keys` (`github.com/zitadel/oidc/v3@v3.51.16/pkg/op/keys.go:22`): marshals the JWKS as JSON **with no `Cache-Control`/`Expires` header**. The engine's `noStorePaths` (`cmd/iamd/main.go`) does **not** include `/keys`, so the engine adds no cache directive either.

🟩 **Token types** — per client: `internal/oidcop/models.go:54` → `AccessTokenType()` returns JWT unless the app is `access_token_type=bearer` (opaque); machine clients are always JWT (`models.go:161`). So **interactive clients default to JWT access tokens** (signed by the signing key, RS256); **bearer** apps get opaque DB tokens that IAM introspects live.

🟩 **Lifetimes (defaults)** — `internal/config/config.go:123-127`: access `5m` ("short, because JWTs cannot be recalled" — the author's own comment), refresh idle `7d`, session max age `30d`, key rotation `30d`.

🟩 **Refresh tokens / sessions** — `refresh_tokens` are opaque (`token_hash`, `family_id`); rotation + reuse detection in `internal/oidcop/storage.go` (`RevokeRefreshFamily` + audit `token.refresh_reuse_detected`, lines ~291-295). `RevokeUserTokens`, `logoutUser`, `TerminateTokens` manage sessions/tokens. **Refresh tokens are not signed by the signing key** — there is no cryptographic association between a signing key and a refresh token.

🟩 **Audit** — `internal/store/audit.go`: `Audit(ctx, AuditEvent{OrgID, Actor, Action, Target, IP, Detail})` inserts into `audit_events`; **write failures are logged, not returned** ("auditing never breaks the operation"). The table is a plain table (no hash-chain / append-only) — audit-trail integrity is the separate open item **P2-2 / MON-02**.

🟩 **Revocation command** — `cmd/iamd/main.go:62` (`revoke-key` dispatch) → `revokeSigningKey` (`main.go:410`) → `DeleteSigningKey`. One `slog.Warn`. **No audit event, no confirmation, no reason, no tombstone, irreversible.**

🟩 **Redis** — **not used** anywhere (no dependency, no code). Postgres is the single authoritative store.

🟩 **Verified limitations (from `FINAL_ASSESSMENT_VERIFICATION_2026-10-30_54ca2a0.md`):** hard delete (no tombstone); no audit; internal cache retains the key ≤ `keyCacheTTL`; no engine-enforced external JWKS cache bound; issued JWTs accepted until RS JWKS refresh + `exp`; refresh/sessions untouched; end-to-end test removed in PR #34; only `store.TestDeleteSigningKeyRemovesFromList` remains (store deletion only). **CRYPTO-05 status: IMPLEMENTED BUT INSUFFICIENTLY VERIFIED.**

---

## 3. Architecture and trust boundaries

```
 Operator (DB creds + binary)            ── trust: full, out-of-band
      │  iamd revoke-key --kid <id> --reason "<ref>" --confirm <id>
      ▼
 Postgres  signing_keys(state,…)         ── AUTHORITATIVE revocation state
      │        audit_events              ── tamper-evident target (P2-2)
      │  (state flip + audit in ONE tx; NOTIFY on commit)
      ├──────────────► IAM instance A  keyStore (filters REVOKED; LISTEN)
      ├──────────────► IAM instance B  keyStore (filters REVOKED; LISTEN)
      ▼
   /keys (JWKS, short max-age)           ── IAM-enforced: shortened, not zero
      ▼
 External Resource Servers               ── trust: cooperative only
   (own JWKS cache + own exp/iss/aud checks)  ◄── IAM CANNOT force early drop
```

**Trust boundaries.** Inside the boundary IAM controls: the authoritative key state (Postgres), its own signing, its own introspection/verification of opaque tokens, and refresh/session state. Outside the boundary (external RS) IAM controls nothing but what it *publishes* (JWKS contents, cache headers, `exp`); enforcement there is cooperative.

---

## 4. Key lifecycle state machine 🟦

Add a `state` column (and `revoked_at`, `revoked_reason`) to `signing_keys`. State is **DB-authoritative**, not time-derived (except RETIRING's deadline).

```
             generate()
                 │
                 ▼
            ┌─────────┐   rotate_at reached (normal)   ┌──────────┐
            │ ACTIVE  │ ─────────────────────────────► │ RETIRING │
            └─────────┘                                 └──────────┘
                 │  emergency revoke                         │  expires_at reached
                 │                                           │  (normal end of life → row may be purged)
                 ▼                                           ▼
            ┌─────────┐ ◄───── emergency revoke ────────  (RETIRING)
            │ REVOKED │   (terminal, durable, irreversible)
            └─────────┘
```

| State | May sign new? | In JWKS? | Accepted by IAM's own verification? | Durable? |
|-------|:---:|:---:|:---:|:---:|
| **ACTIVE** 🟦 | yes (when past `publishLead`) | yes | yes | — |
| **RETIRING** 🟦 | **no** | yes (overlap, until `expires_at`) | yes | — |
| **REVOKED** 🟦 | **never** | **no (removed immediately)** | **never** (kid denylisted) | **yes (tombstone, survives restart/cache/restore)** |

- 🟩 Today ACTIVE/RETIRING are *implicit* (`signer()` age heuristic + `ListSigningKeys` by `expires_at`); **REVOKED does not exist**.
- 🟦 **REVOKED is a tombstone row kept forever** (or until a long retention): `state='revoked'`, `revoked_at`, `revoked_reason`. The private key material (`private_key_enc`) **should be zeroed** on revoke (it is no longer needed and reduces exposure), but the **row and `kid` are retained** so the key can never silently return and so the `kid` is permanently denylisted.
- **JWKS on revoke:** remove **immediately** (do not keep a REVOKED key published). Rationale: a published key invites continued acceptance; a verifier that still holds a cached copy is the external-window problem, which short cache + `exp` bound, not continued publication.
- **kid reuse protection:** 🟩 `kid` = `uuid.NewString()` (collision-safe). 🟦 `generate()` must additionally check the new `kid` is absent from **all** rows including REVOKED tombstones (belt-and-braces; practically impossible to collide, but the tombstone makes reuse provably impossible).

---

## 5. Emergency revocation semantics 🟦

Command: `iamd revoke-key --kid <id> --reason "<ref>" --confirm <id> [--operator <name>] [--revoke-sessions=false]`

1. **Authorization / privileges.** Operator possesses the DB URL and runs the binary out-of-band (no network endpoint — keep it that way; no new auth surface). ⚖️ *Owner decision:* require two-operator approval for revocation (defense against a single malicious/compromised admin)? Proportionate default for first-party internal SaaS: **single operator + mandatory `--reason` + typed `--confirm` echo + audit**; two-operator optional.
2. **Confirmation / fat-finger protection.** 🟦 Refuse unless `--confirm <id>` exactly echoes `--kid <id>` and `--reason` is non-empty. Print the key's current state and `created_at` and require the echo. No bare-id execution.
3. **Persistent revocation state.** 🟦 `UPDATE signing_keys SET state='revoked', revoked_at=now(), revoked_reason=$2, private_key_enc = '' WHERE id=$1 AND state <> 'revoked'` — **not** `DELETE`.
4. **Audit event.** 🟦 Insert `audit_events(action='signing_key.revoked', target=<kid>, actor=<operator>, detail={reason, correlation_id, prev_state})` — **non-secret metadata only** (never the key).
5. **Atomicity.** 🟦 Steps 3 + 4 run in **one transaction**. Unlike today's fire-and-forget `Audit`, this path must **fail the command if the audit insert fails** — commit both or neither. Success is printed **only after COMMIT**.
6. **Cross-instance invalidation.** 🟦 On commit, `pg_notify('signing_keys','revoked:'||kid)`; each instance `LISTEN`s and drops/reloads on notice. Fallback: the existing TTL poll (`keyCacheTTL`) still converges if NOTIFY is missed. 🟩 Postgres-native — no Redis.
7. **DB / Redis outage.** DB down → the UPDATE cannot commit → command **fails loudly, reports no success** (never fail-open). Redis: N/A (not in the stack). 🟥 A running instance that cannot reach the DB keeps its last cache; a key revoked *during* its outage is not seen until reconnect — residual window documented in §10.
8. **Partial failure.** The single transaction removes partial states. If `NOTIFY` is lost post-commit, the TTL poll still applies the revocation within `keyCacheTTL`.
9. **Idempotency.** 🟦 Re-revoking a REVOKED key → `state <> 'revoked'` matches nothing → report **success (already revoked)**, not an error.
10. **Concurrent revocation & rotation.** 🟦 Take `LockSigningKeys` (existing advisory lock) around revoke and around `generate()`; `signer()`/`KeySet()` filter `state IN ('active','retiring')` and never select a REVOKED key, so a rotation racing a revoke cannot pick the revoked key.
11. **Recovery / DR.** Accidental revoke is **irreversible by design** (safety over convenience); recovery = `generate()` a fresh key and re-sign forward; tokens signed by the revoked key die at `exp`. Real compromise = same, plus (if key sealing is suspect) master-key rotation, plus scoped session/refresh revocation.
12. **Unknown kid.** 🟦 Report "unknown signing key `<id>`", non-zero exit, create no tombstone (default). ⚖️ *Owner decision:* optionally allow `--force-denylist <kid>` to tombstone a `kid` that was never stored (defends against a key minted from stolen material outside the DB) — niche; default off.

**Hard rule:** 🟦 the command must never print success before the durable REVOKED state is committed, and must never silently fall back to a path that leaves the key usable.

---

## 6. Existing JWTs and external resource servers — the central question

**Honest baseline (🟩/🟥):** JWKS removal + cache headers affect only *future* key lookups. An already-issued JWT at an external RS remains valid there until (a) the RS refreshes its JWKS and drops the `kid`, **and** (b) the token's own `exp`. IAM controls (a)'s *input* (what it publishes and the cache header) but not the RS's behavior; IAM controls (b) by issuing **short-lived** tokens. **JWKS removal alone does not immediately invalidate issued JWTs.**

### Strategy comparison

| | Security | Op cost | Availability | Latency | Multi-instance | Ordinary-RS compatible | Behavior when IAM down |
|---|---|---|---|---|---|---|---|
| **A. JWKS removal + short `/keys` cache** | Shortens external window to ~cache TTL + `exp`; never zero | Low | High | None | Fine (DB-authoritative) | **Yes** | RS keeps using cached JWKS (fails safe-ish; no new keys) |
| **B. Online introspection / revocation check per request** | Strong, near-immediate | High | **Couples RS availability to IAM** | +1 network hop per call | Fine | **No** (ordinary stateless RS do not introspect) | RS calls fail → outage or fail-open risk |
| **C. `kid`/token denylist** | Strong for IAM's own verification; for external RS only if they consult it | Medium | Medium | Low (cached denylist) | Needs distribution | Partial (non-standard for third parties) | Denylist stale |
| **D. Short-lived access tokens + refresh/session revocation** | Bounds JWT exposure to `exp` (5 min); refresh/session cut immediately in DB | Low | High | None | Fine | **Yes** | New tokens stop; issued ones expire |
| **E. Hybrid D + A + C** | Best realistic: `exp`-bounded external window, shortened further by cache, immediate for IAM's own paths | Low–Medium | High | None for RS | Fine | **Yes** | Fails safe; `exp` still bounds |

### Recommendation: **E (hybrid)** 🟦

- **D is the backbone.** With a 5-minute access `exp`, the *maximum* an external RS can honor a revoked-key JWT is **≤ RS JWKS cache TTL + 5 min**; with D we accept the 5-min `exp` as the enforceable outer bound and focus emergency effort on **refresh/session** (the long-lived state) via existing DB revocation.
- **A shortens the external window** by setting a short `Cache-Control: max-age` on `/keys` (e.g. 60–300 s) and **documenting the required RS behavior** (honor cache headers; re-fetch on unknown `kid`).
- **C hardens IAM's own paths:** IAM's introspection/verification treats a REVOKED `kid` as invalid immediately (opaque bearer tokens die at once; any IAM-side JWT check rejects the `kid`).
- **B is not mandated** — it breaks ordinary OIDC RS compatibility and couples their availability to IAM. Offer it only as an *option* for a high-value internal RS that is willing to introspect.

### Guarantee split (state explicitly) 🟩/🟦/🟥

| IAM can enforce itself | Requires external RS cooperation |
|---|---|
| Stop **signing** with the key: immediate in DB; ≤ sub-second (NOTIFY) to ≤ `keyCacheTTL` (cache) across instances 🟦 | Dropping an **already-issued JWT** before its `exp` 🟥 |
| Reject the revoked `kid` on **IAM's own** verification/introspection: immediate 🟦 | Honoring `/keys` `Cache-Control` / re-fetching on unknown `kid` 🟦(published) / 🟥(enforced) |
| Kill **opaque bearer** access tokens (DB introspection): immediate 🟦 | — |
| Revoke **refresh tokens / sessions** (DB): immediate, cross-instance 🟩 | — |
| Bound JWT exposure to **`exp` (5 min default)** 🟩 | — |

---

## 7. Refresh-token and session impact 🟦

- 🟩 **Refresh tokens are not associated with a signing key** (opaque rows). A key revocation therefore has **no intrinsic refresh-token target**. You cannot "find the refresh tokens signed by this key" — there are none.
- ⚖️ **Should a key revocation revoke sessions/refresh?** **Not by default.** Revoking a signing key because *the key leaked* does not imply user tokens leaked; force-logging every user out of every app (blast radius: all sessions, all tenants) is disproportionate and a self-inflicted outage.
- 🟦 Provide a **separate, scoped, explicit** operator action for the incident where tokens are also suspect: `--revoke-sessions` (default **false**), and prefer **targeted** `RevokeUserTokens` / `RevokeRefreshFamily` over a global wipe. Analyze blast radius before any global revoke.
- 🟩 Refresh-token **replay** is already handled (family revoke + audit). 🟩 Concurrent refresh requests are serialized by rotation/consume semantics. Cross-instance logout is DB-authoritative; for JWT sessions the ≤5-min `exp` bounds staleness.

---

## 8. Cache and distributed-system design 🟦

- 🟩 **Authoritative source:** Postgres `signing_keys.state`. Caches are advisory.
- 🟩 Today: per-instance `keyStore`, `keyCacheTTL = 60 s`, pull-based reload; no cross-instance signalling.
- 🟦 **Add:** `keyStore.current()` filters `state IN ('active','retiring')` and refuses REVOKED; **`LISTEN signing_keys`** for push invalidation on revoke/rotate; keep the TTL poll as fallback.
- 🟦 **Measurable internal propagation target:** **≤ ~2 s typical** (NOTIFY delivery) and **≤ `keyCacheTTL` (60 s) worst case** (fallback poll). This is an **internal, IAM-enforced** bound.
- 🟥 **No bounded external propagation** is promised — the architecture cannot enforce it.
- **Startup/restart:** `load()` reads state from DB → REVOKED keys are never loaded → **no resurrection** across restart.
- **Clock skew:** REVOKED is state-based, not time-based → skew-immune. Only RETIRING deadlines use time.
- **Network partition:** a partitioned instance serves its last cache; ⚖️ *owner decision:* add a **fail-closed-on-stale** option (refuse to sign if key state is older than N) — availability vs. safety tradeoff.
- **Stale reads / races:** the revoke transaction + `LockSigningKeys` serialize revoke vs. generate; membership filtering makes a race unable to select a REVOKED key.
- **Redis:** 🟩 not present; 🟦 **do not add it** for this — `LISTEN/NOTIFY` covers push invalidation natively. Adding Redis would be unjustified new infrastructure.

---

## 9. Audit and incident response 🟦

- **Audit record** (`audit_events`): `action='signing_key.revoked'`, `target=<kid>`, `actor=<operator>`, `at`, `detail={reason, correlation_id, prev_state, result}`. **Never** log private keys, sealed material, access or refresh tokens.
- 🟦 Written **in the revoke transaction** (atomic; fail the command if it fails — stricter than the current fire-and-forget `Audit`).
- ⚖️ Tamper-evidence ties to **P2-2** (audit hash-chain / append-only). Until P2-2 lands, the record is a plain row — note the limitation.
- **Alerting:** `signing_key.revoked` and `signing_key.generated` must page (a key-state change is always security-relevant — this is exactly a **P2-3 / MON-03** alert rule).
- **IR steps:** (1) revoke; (2) confirm a healthy successor key signs (generate if needed); (3) note the external window (RS JWKS TTL + `exp`) and, if warranted, notify RS operators to refresh; (4) if token compromise is suspected, scoped `RevokeUserTokens`/force-logout; (5) if key *sealing* is suspect, rotate the master key.
- **Recovery after accidental revocation:** forward-only (generate new key); the revoked key stays dead. **Recovery after real compromise:** as IR, plus master-key rotation.
- **Backup/restore implication (critical):** 🟥 a restore from a snapshot **predating** the revocation would bring the key back as ACTIVE. Mitigations: keep tombstones in-band (restores carry them if taken after revoke), and/or maintain an out-of-band `kid` denylist consulted at `load()`. Residual risk documented in §10.

---

## 10. Threat model and failure scenarios

| Scenario | Expected behavior (🟦 proposed) | Residual risk |
|---|---|---|
| **Signing-key theft** | Revoke → durable REVOKED, dropped from JWKS, IAM stops signing/accepting; issued JWTs bounded by `exp` + RS cache | External RS honoring a cached JWT until `exp`/refresh 🟥 |
| **Unauthorized emergency revocation** | Requires DB creds + binary; audited; (optional two-operator) | A compromised operator can DoS signing; mitigated by audit/alerting |
| **Malicious administrator** | Audit + alert on every revoke; optional two-operator approval | Insider with DB access can still act; blast radius = signing DoS, not key exfiltration |
| **Accidental revocation** | `--confirm` echo + `--reason`; irreversible; recover by generating a new key | Short self-inflicted signing disruption; no data loss |
| **Database outage** | Revoke fails loudly (no false success); running instances serve last cache | Revocation delayed until DB returns 🟥 |
| **Redis outage** | N/A (no Redis) | — |
| **Network partition** | Partitioned instance serves stale cache; optional fail-closed-on-stale | Stale signing until reconnect 🟥 |
| **Stale internal cache** | ≤ `keyCacheTTL` (poll) or ≤ ~2 s (NOTIFY) | Bounded internally |
| **Stale external JWKS cache** | Shortened by `/keys` max-age + `exp`; not enforceable | Bounded only by RS cooperation 🟥 |
| **Concurrent key rotation** | `LockSigningKeys` + state filter serialize | None material |
| **Multiple IAM instances** | NOTIFY + poll converge; DB authoritative | ≤ propagation bound skew |
| **Backup restore predating revocation** | Tombstone resurrection risk | 🟥 **Documented residual** — needs restore runbook + denylist |
| **Revocation registry corruption** | DB integrity + backups; `load()` fails closed on unreadable state | Depends on DB durability |

---

## 11. Test strategy 🟦 (design before implementation)

**Determinism fix for the removed flaky test:** the old `oidcop.TestRevokedKeyLeavesJWKSAndResigns` was flaky because `go test ./...` runs packages in parallel against one shared `IAM_TEST_DATABASE_URL`, and `keyStore.load()` decrypts **every** `signing_keys` row — so it collided with `internal/store` tests inserting placeholder keys and asserting global counts. **Make the replacement isolated, not reintroduced as-is:**

- Give signing-key end-to-end tests their **own database** (create/drop a uniquely-named DB per run) or their **own schema**, so no other package shares the `signing_keys` table. This removes the cross-package coupling entirely.
- Keep assertions **membership-only on the test's own `kid`s** (never global counts, never decrypt-all) as a second line of defense.

**Test matrix:**

1. **Lifecycle unit tests** — pure state-machine transitions (ACTIVE→RETIRING→REVOKED; illegal transitions rejected); no DB.
2. **Store tombstone tests** — revoke flips state (not delete), `revoked_at`/`reason` set, `private_key_enc` zeroed, row retained; idempotent re-revoke; unknown id → error.
3. **JWKS behavior** — REVOKED `kid` absent from `KeySet`/`/keys`; RETIRING present; `/keys` carries the short `Cache-Control`.
4. **Internal cache invalidation** — after revoke + reload (own-DB), the `kid` is gone and a signer still exists; signer is never a REVOKED key.
5. **Multi-instance propagation** — two `keyStore`s on the same (isolated) DB; NOTIFY/poll drops the `kid` within the target bound.
6. **Restart/recovery** — a fresh `keyStore` over a DB with a REVOKED row never loads it (no resurrection).
7. **Concurrent rotation/revocation** — under `LockSigningKeys`, revoke+generate interleavings never select the revoked key.
8. **Existing-JWT verification after revocation** — a JWT with a REVOKED `kid` is rejected by IAM's own verification; (documented) external RS behavior is out of test scope.
9. **Refresh/session** — key revocation alone does **not** revoke sessions; `--revoke-sessions` scoped path does; refresh reuse still family-revokes.
10. **DB failure** — revoke against a closed pool fails and reports no success; running instance fails closed on signing when state is unreadable.
11. **Audit** — revoke writes exactly one `signing_key.revoked` event with non-secret metadata, in-tx; audit-insert failure aborts the revoke.
12. **Idempotency** — re-revoke returns success/no-op; no duplicate audit.
13. **Rotation regression** — ordinary 30-day rotation + `publishLead` overlap still works unchanged.

---

## 12. Alternatives and trade-offs

**Architecture 1 — Minimal durable revocation** 🟦
State column + tombstone + audit-in-tx + short `/keys` cache; rely on the existing TTL poll (shorten it for revocation).
- Security: large improvement over hard delete (durable, audited, no resurrection). Complexity: low. Schema: 1 migration (add 3 columns + a partial index). Runtime deps: none. Op burden: low. Migration risk: low (additive, default ACTIVE). Compatibility: full.
- Internal propagation: ≤ poll TTL.

**Architecture 2 — Durable revocation + push invalidation (+ optional scoped session revoke)** 🟦
Architecture 1 **plus** `LISTEN/NOTIFY` push and an optional `--revoke-sessions` integration.
- Security: same durability + near-instant internal propagation + incident-scoped session control. Complexity: medium. Schema: same migration. Runtime deps: none new (pg NOTIFY). Op burden: medium. Migration risk: low. Compatibility: full.
- Internal propagation: ≤ ~2 s typical.

**Recommendation:** 🟦 **Architecture 2, delivered in phases** (ship Architecture 1 first, add NOTIFY + scoped session revoke as a bounded enhancement). It is proportionate, Postgres-native, adds **no microservices, no custom crypto, no new infrastructure**, and turns CRYPTO-05 from "delete + hope" into a durable, audited, bounded-internally control with an honestly-stated external limit.

---

## 13. Recommended architecture (summary)

1. 🟦 `signing_keys` gains `state` (`active`/`retiring`/`revoked`, default `active`), `revoked_at`, `revoked_reason`; hard delete replaced by state flip; `private_key_enc` zeroed on revoke; row retained as a permanent tombstone.
2. 🟦 `keyStore`/`ListSigningKeys` filter `state IN ('active','retiring')`; `signer()` only ACTIVE past `publishLead`; REVOKED never signs/serves.
3. 🟦 `iamd revoke-key` → transactional state flip **+** `audit_events` insert; success only after COMMIT; `--reason` + `--confirm` echo; idempotent; unknown-id safe.
4. 🟦 `LISTEN/NOTIFY` push invalidation + TTL poll fallback → internal propagation ≤ ~2 s / ≤ 60 s.
5. 🟦 Short `Cache-Control: max-age` on `/keys` + documented RS JWKS-refresh expectation.
6. 🟦 Keep short JWT `exp` (5 min) as the enforceable outer bound for issued JWTs; refresh/session revocation stays a **separate, scoped** operator action.
7. 🟦 Alerting on `signing_key.revoked`/`generated` (feeds P2-3); audit tamper-evidence deferred to P2-2.
8. 🟦 Isolated-DB end-to-end tests (deterministic replacement for the removed flaky test).

---

## 14. Phased implementation plan 🟦 (for a later, separately-authorized phase)

- **Phase 0 — this document + owner approval** of the §15 open decisions.
- **Phase 1 — durable revocation (Architecture 1):** migration (add columns + index), state-aware `keyStore`/`ListSigningKeys`, transactional revoke+audit, CLI confirmation/reason/idempotency, isolated deterministic tests. Closes the "hard-delete / no-tombstone / no-audit" gaps.
- **Phase 2 — external-window shortening:** `/keys` `Cache-Control` + DEPLOYMENT/OPERATIONS docs on required RS JWKS TTL and the honest guarantee split.
- **Phase 3 — push invalidation (Architecture 2):** `LISTEN/NOTIFY` + measured propagation test.
- **Phase 4 — optional incident scope:** `--revoke-sessions` scoped integration; per-RS introspection guidance for high-value internal RS.
- **Phase 5 — assurance:** fold into P2-2 (audit integrity), P2-3 (alerting), and an independent review.

Each phase is independently shippable, test-gated, and leaves production **NO-GO** until the separate release gates are met.

---

## 15. Explicit unresolved decisions and risks ⚖️🟥

1. ⚖️ **Two-operator approval** for revocation? (insider-threat defense vs. operational friction). Default proposed: single operator + reason + confirm + audit.
2. ⚖️ **Fail-closed-on-stale signing** during a DB/network partition? (safety vs. availability). Default proposed: fail closed on unreadable state at reload; serve last cache during a brief partition.
3. ⚖️ **`/keys` `max-age` value** (60 s vs 300 s) — balances external-window length against JWKS fetch load.
4. ⚖️ **Couple session/refresh revocation** to key revocation, or keep fully separate? Proposed: separate, opt-in, targeted.
5. ⚖️ **Tombstone retention** — keep REVOKED rows forever, or a long retention; interaction with `PurgeExpired` (must **exclude** REVOKED from purge).
6. 🟥 **Backup/restore predating revocation** — needs a restore runbook and/or out-of-band denylist; cannot be fully solved in-DB alone.
7. 🟥 **External RS behavior** — unverifiable from IAM; the external window is cooperative, bounded only by `exp` + RS cache policy.
8. ⚖️ **Audit tamper-evidence** — depends on P2-2; until then the revocation audit is a plain row.

---

## 16. Final report

- **Audited branch / HEAD:** `main` @ `54ca2a0` (`origin/main` identical).
- **Working tree initially clean?** Yes for tracked files; the only untracked items are the three new `docs/security/` assessment docs from this and the prior turns (preserved, not modified).
- **Files inspected:** `internal/store/oidc.go`, `internal/store/audit.go`, `cmd/iamd/main.go`, `internal/oidcop/keys.go`, `internal/oidcop/storage.go`, `internal/oidcop/models.go`, `internal/config/config.go`, `internal/db/migrations/0001_init.sql` (+ migration list `0001…0010`), vendored `github.com/zitadel/oidc/v3@v3.51.16/pkg/op/keys.go`; prior deliverables under `docs/security/`.
- **New document created:** `docs/security/CRYPTO_05_EMERGENCY_REVOCATION_DESIGN.md` (this file).
- **Key recommendation:** durable Postgres key-state model (ACTIVE/RETIRING/REVOKED) + transactional revoke-with-audit + `LISTEN/NOTIFY` invalidation + short `/keys` cache + short-JWT/`exp` backbone (Strategy E, Architecture 2, phased). No Redis, no microservices, no custom crypto.
- **Expected guarantees:** internal revocation propagation ≤ ~2 s (NOTIFY) / ≤ 60 s (poll); IAM's own signing/verification/introspection and refresh/session state consistent within that bound; **external already-issued JWTs bounded only by `exp` (5 min) + RS JWKS cache — not engine-enforceable.**
- **Main unresolved decisions:** two-operator approval; fail-closed-on-stale; `/keys` max-age; session-revocation coupling; tombstone retention; backup-restore resurrection; audit tamper-evidence (§15).
- **Tests run:** none in this design phase. (The existing `store.TestDeleteSigningKeyRemovesFromList` and the removed end-to-end test were reviewed in the prior verification turn; no tests were executed now.)
- **No code, migration, configuration, or infrastructure changed.** No new/modified migrations. Existing assessment documents untouched.
- **Nothing committed or pushed.** No PR/merge/release/deploy. `vps-ai-pbx` and `zitadel-stack` untouched. No secrets printed.

**Production remains NO-GO. CRYPTO-05 remains IMPLEMENTED BUT INSUFFICIENTLY VERIFIED** until a separately-authorized implementation and verification phase completes. **Stop** — awaiting explicit owner authorization before any implementation.
