# CRYPTO-05 — Review Remediation Mapping

- **Purpose:** map every finding (F-1…F-9) and correction (C-1…C-8) from `docs/security/CRYPTO_05_INDEPENDENT_PLAN_REVIEW.md` to its resolution in `docs/security/CRYPTO_05_IMPLEMENTATION_PLAN.md` (revision 2).
- **Baseline:** `main` at `f3dd2a1`, clean working tree. Documentation-only remediation; no code, migration or infrastructure changed.
- **Unchanged evidence:** the independent review document is left as-is as historical record.
- **Status:** the plan now contains a concrete technical resolution and a mapped acceptance criterion/test for every finding; nothing is marked resolved on mention alone.

Plan section numbers (`§`), acceptance-criterion numbers (`AC#`) and test identifiers refer to `CRYPTO_05_IMPLEMENTATION_PLAN.md` revision 2.

---

## 1. Findings F-1 … F-9

| Finding | Plan section | Technical resolution | AC# | Test(s) | Remaining risk / owner decision |
|---------|--------------|----------------------|-----|---------|---------------------------------|
| **F-1** Immediate-local revocation claim invalid (CLI is a separate process) | §1 (timing model), §3 (trust boundaries), §6, §7 | All "immediate on this engine" wording removed. Guarantee restated: every running engine stops **selecting** the revoked key within ≤ `keyCacheTTL` of commit when DB reachable, else fails closed. No immediate-local case under the CLI trigger. | AC3 | 3, 4, 9, 11 | Worst case stays ≤ `keyCacheTTL`; sub-minute needs NOTIFY → **D2**. Timing tests need seam → **D7**. |
| **F-2** "Stops signing immediately" overstated vs. already-selected key pointer | §7 (signing/revocation race) | Precise guarantee: no **new** selection returns a revoked key after reload observes revocation; an operation that already holds the pointer may complete and mint one token. Single-token residual window documented. | AC9 | 7 (race, CI) | Residual single in-flight token is inherent to cached-key designs; no owner decision. |
| **F-3** Atomic audit cannot reuse pool-bound `Store.Audit` | §4.4, §4.9, §2.9, §5 | `Store.RevokeSigningKey` runs one `pgx.BeginFunc`; the audit row is inserted on the `tx` (`tx.Exec`), not via `Store.Audit`. State change + tombstone + audit + epoch bump commit together or not at all. | AC2 | 16, 12 | None; `Store.Audit` explicitly prohibited for this path. |
| **F-4** Timing tests impossible with `const` TTL + direct `time.Now()` | §4.7, §2.3 | Minimal seam specified: `cacheTTL`/`publishLead` as `keyStore` fields defaulted from the consts, plus `now func() time.Time` defaulting to `time.Now`. Documented as a prerequisite; **not implemented** here. | AC3 | 9, 11, 13, T-B timing | Refactor approval → **D7**. |
| **F-5** Missing tests T-A…T-E | §9 | All five added with full specs (setup/expected/failure/type). | AC1,4,6,9,11 | T-A, T-B, T-C, T-D, T-E | T-B and timing tests gated on **D7** seam. |
| **F-6** No reconciliation gate after restore/PITR | §4.8, §8 | Revocation-epoch single-row table bumped in every revocation tx; engine refuses to sign on epoch regression (restore/PITR to older state) until operator ack; tombstoned ids stay suppressed. | AC11 | T-E | Pre-tombstone-and-pre-epoch restore still needs runbook → **D3** (safeguard vs. documented residual). |
| **F-7** Ambiguous COMMIT outcome | §4.9, §6, §8 | `RevokeSigningKey` returns the commit error unchanged (CLI reports failure only if commit not confirmed). Whole op idempotent, so operator re-runs safely; guidance in operator output + runbook. | AC9 | T-C | None; re-run safe by construction. |
| **F-8** Mistaken-revocation recovery unstated / irreversibility | §4.9, §6 | Stated plainly: `REVOKED` is terminal and tombstone permanent → irreversible for that key (same as today's hard delete). Recovery = automatic successor promotion/generation (`keys.go:94-124`); the key stays dead. Operator output warns before acting. | AC10 | 15 + doc review | Approval-gate to reduce accidental revocation → **D6**. |
| **F-9** Duplicate audit rows under concurrent revoke | §4.9, §2.9 | Tombstone `ON CONFLICT (id) DO NOTHING`; audit insert + epoch bump run **only** when the tombstone insert affected a row. Exactly one audit event and one epoch bump per logical revocation. | AC9 | 8, T-C (race, CI) | None. |

---

## 2. Corrections C-1 … C-8

| Correction | Plan section | Technical resolution | AC# | Test(s) | Remaining risk / owner decision |
|------------|--------------|----------------------|-----|---------|---------------------------------|
| **C-1** Rewrite propagation model (no immediate-local; ≤TTL-or-fail-closed) | §1, §3, §4.5, §7 | Done; worst-case ≤ `keyCacheTTL` with DB-reachable qualifier; NOTIFY best-effort only. | AC3 | 3, 4, 9, 11 | **D2** for sub-minute path. |
| **C-2** Precise signing-race guarantee | §7 | Done (see F-2). | AC9 | 7 | None. |
| **C-3** Transaction-scoped audit insert | §4.4, §5 | Done (see F-3). | AC2 | 16 | None. |
| **C-4** Clock/TTL seam prerequisite | §4.7 | Minimal seam specified; not implemented. | AC3 | 9, 11, 13 | **D7**. |
| **C-5** Credit fail-closed-on-stale property | §2.3, §7, §13 | Documented as a verified guarantee (`keys.go:68-72`): never serves stale keys past TTL; outage halts signing rather than using a cached (possibly revoked) key. | AC3 | 3, 13 | None. |
| **C-6** Restore/PITR posture decided, not implicit | §4.8, §12 D3 | Epoch fail-closed is the recommended default; documented-residual is the stated alternative. Decision forced to **D3** (not silent). | AC11 | T-E | **D3**. |
| **C-7** Ambiguous-commit guidance + irreversibility stated | §4.9, §6 | Done (see F-7, F-8). | AC10 | T-C, 15 | None. |
| **C-8** Name exact `/keys` middleware position | §4.6 | Middleware inserted before the zitadel `op` handler, same layer as `securityHeaders` (`cmd/iamd/main.go:432`), which sets headers before `next.ServeHTTP`; library sets no competing header (`pkg/op/keys.go:22` → `pkg/http/marshal.go:16`). | AC8 | 14 | **D1** for the `max-age` value. |

---

## 3. Owner decisions D1 … D7

All are **RECOMMENDED DEFAULT — NOT YET APPROVED** (plan §12). None is presented as final.

| Decision | Recommended default | Open? | Linked findings |
|----------|---------------------|-------|-----------------|
| **D1** JWKS `max-age` | `public, max-age=300` | Yes | C-8 / F-10 |
| **D2** LISTEN/NOTIFY vs polling | Polling first; NOTIFY later if sub-minute needed | Yes | F-1 / C-1 |
| **D3** Tombstone backup & restore policy | Epoch fail-closed + backups include tombstone/epoch + replay runbook | Yes | F-6 / C-6 |
| **D4** Session/refresh coupling | Keep orthogonal; document combined call | Yes | §2.7 |
| **D5** Access-token TTL | Review/shorten from 5 min | Yes | external-window residual |
| **D6** Authorization/approval gate | Audited operator identity; consider two-person for prod | Yes | F-8 |
| **D7** Clock/TTL injection prerequisite | Approve the minimal seam | Yes | F-4 / C-4 |

---

## 4. Test-matrix completeness

- Tests 1–17 retained; T-A…T-E added (plan §9).
- Every acceptance criterion AC1–AC11 maps to at least one test (plan §11 table):
  AC1→T-A/5/6 · AC2→16/12 · AC3→3/4/9/11 · AC4→T-B · AC5→5/6 · AC6→T-D · AC7→17 · AC8→14 · AC9→7/8/T-C · AC10→15+doc · AC11→T-E.
- Prerequisite: AC3 and tests 9/11/13 (and T-B timing) depend on the §4.7 clock/TTL seam (**D7**).
- Test-infrastructure tags preserved: race/CI (7, 8, T-C/T-D if concurrent); real Postgres (1–6, 9–12, 16, 17, T-A–T-D); multiple engines (9); restart/restore simulation (5, 6, T-E); all isolation-safe.

---

## 5. Validation (documentation consistency checks)

- **No contradictory timing guarantees:** the plan states a single worst-case bound (≤ `keyCacheTTL`, DB-reachable, else fail-closed) in §1, §3, §4.5 and §7; no section claims a different hard maximum.
- **No unsupported claim of immediate global revocation:** removed everywhere (F-1/C-1); operator output (§6) forbids "instantly revoked everywhere" and "immediately on this engine."
- **No claim that external JWTs can be instantly invalidated:** §1, §2.5, §3, §6, §8 all state issued JWTs remain valid externally until RS cache refresh + `exp`.
- **No stale-key fail-open behavior:** §2.3/§7 document fail-closed-on-stale (`keys.go:68-72`); no path serves a stale key past TTL.
- **No audit success before durable commit:** audit is on the `tx` and `RevokeSigningKey` returns the commit error (§4.4, §4.9); the CLI cannot report success before COMMIT.
- **No tombstone deletion or resurrection path:** tombstone/epoch excluded from `PurgeExpired` (§5, AC7/test 17); tombstone authority overrides row presence (§4.3, T-A); epoch regression fails closed (§4.8, T-E).
- **No unapproved owner decision presented as final:** all of §12 is labelled RECOMMENDED DEFAULT — NOT YET APPROVED.

---

## 6. Files changed by this remediation

- Updated: `docs/security/CRYPTO_05_IMPLEMENTATION_PLAN.md` (revision 2).
- Created: `docs/security/CRYPTO_05_REVIEW_REMEDIATION.md` (this file).
- Unchanged: `docs/security/CRYPTO_05_INDEPENDENT_PLAN_REVIEW.md`, `docs/security/CRYPTO_05_EMERGENCY_REVOCATION_DESIGN.md`.

No application code, migration, configuration, secret, key, service or infrastructure was modified. No commit, push, PR or merge. `vps-ai-pbx` and `zitadel-stack` were not accessed. CRYPTO-05 remains **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED**; production readiness remains **NO-GO**; independent penetration test remains **NOT PERFORMED (waived)**. Await explicit owner authorization for the implementation phase.
