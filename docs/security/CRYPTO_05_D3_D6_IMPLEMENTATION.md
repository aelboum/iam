# CRYPTO-05 — D3 / D6 Implementation, Threat Model, Runbooks and Assurance

Status of this document: implementation and in-repository evidence for the two
owner-approved CRYPTO-05 policy decisions **D3** (restore/PITR revocation
protection) and **D6** (signing-key revocation authorization). It complements,
and does not replace, the D1–D7 owner-decision section of
`CRYPTO_05_IMPLEMENTATION_PLAN.md`; those two items are now **APPROVED** and
implemented as described here.

Baseline `main`: `f3dd2a1`. Implementation commit: `a59af3d` (on branch
`crypto05/full-stack-ci-integration`, draft PR #40). Production remains
**NO-GO**; independent external pentest remains **NOT PERFORMED (WAIVED)**;
CRYPTO-05 overall remains **IMPLEMENTED BUT INSUFFICIENTLY VERIFIED** until the
operational prerequisites below are satisfied.

---

## 1. D3 — restore/PITR revocation protection

### 1.1 Security invariant

A PostgreSQL restore or point-in-time recovery to any point **before** a
signing-key revocation must never silently restore the ability to sign with the
revoked key.

PostgreSQL cannot be the sole authority, because restoring it also restores its
own pre-revocation rows and tombstones. The authority for "has this key been
revoked?" must therefore live **outside** the IAM database's backup/restore
lifecycle.

### 1.2 Architecture

- `internal/revepoch` defines an `Authority`: a durable, monotonically
  increasing revocation **epoch** plus the set of revoked key ids. Guarantees
  required of any implementation: monotonic (never decreases), idempotent
  `Record`, authenticated reads/writes, independence from IAM PostgreSQL
  restore/PITR, and a detectable rollback.
  - `MemAuthority` — in-memory **test** adapter (also simulates outage and
    rollback). Never a production authority.
  - `PGAuthority` — **reference** adapter backed by a PostgreSQL database that is
    operationally separate from IAM (its own server, credentials and backups),
    selected by `IAM_REVOCATION_AUTHORITY_URL`. Append-only log keyed by key id
    with a `bigint GENERATED ALWAYS AS IDENTITY` epoch.
- `internal/revocation` provides `Reconcile` and a fail-closed `Gate` + `Runner`.
- Migration `0012` adds the local, forward-only reconciliation marker
  `revocation_reconciliation(reconciled_epoch)`.
- The gate is installed via `Storage.SetSigningGate` and enforced inside
  `keyStore.current` — the single boundary behind both `SigningKey` (signing)
  and `KeySet` (JWKS publication).

### 1.3 Revocation ordering and failure semantics

`iamd revoke-key` performs, in order:

1. **Authorize** the operator (D6, below).
2. **Record** the revocation in the independent authority (durable) — *before*
   the local commit.
3. **Commit locally**: mark `REVOKED`, write the tombstone and one audit event in
   one transaction (`RevokeSigningKeyWithDetail`).
4. **Reconcile** the local marker up to the authority's epoch.

Why authority-first: if the process dies between (2) and (3), the authority stays
ahead of the local reconciled epoch, so the startup gate re-applies the
revocation and refuses to sign until it has. A key can never resume signing
merely because the local transaction did not complete. The only cost of a
mistaken id is a harmless authority entry; the direction of failure is always
"revoke", never "resurrect".

### 1.4 Startup / recovery gate

On startup (and every minute thereafter) the engine reconciles:

- authority ahead of local (e.g. after a restore): re-apply the missing
  revocations (idempotent tombstones), then advance the marker; gate opens only
  when `reconciled_epoch >= authority epoch`;
- authority **behind** the local marker (rollback): `ErrRollback`, gate closes,
  operator action required — the authority is never lowered and no key is
  reactivated;
- authority **unavailable** at startup: gate stays **closed** (fail closed);
- authority unavailable after a successful reconcile: the gate stays open on
  last-known-good state (a brief authority outage does not take signing down),
  since in steady state ordinary revocations also suppress via the shared
  database within one key-cache interval.

The gate is enforced at the key-access boundary, so a warm cache cannot bypass a
closed gate.

### 1.5 Restore / PITR operator runbook

1. **Identify** the restore/PITR event (you restored IAM PostgreSQL, or promoted
   an older snapshot/replica).
2. On start, the engine reconciles automatically against the authority
   (`IAM_REVOCATION_AUTHORITY_URL`). While `reconciled_epoch` is behind the
   authority, **signing and JWKS publication are refused** (503-class failures) —
   this is expected and correct.
3. Confirm reconciliation completed: logs show "signing gate open"; the
   `revocation_reconciliation.reconciled_epoch` equals the authority's current
   epoch.
4. If the authority is unreachable, signing stays disabled until it is restored;
   **do not** work around this by clearing tombstones or lowering the epoch.
5. Signing resumes **only** after a successful reconcile. Previously revoked keys
   remain revoked; the engine promotes a successor or generates a new key.

Never lower the authority epoch to match a restored database. Never reactivate a
revoked key or delete a tombstone to recover service.

---

## 2. D6 — signing-key revocation authorization

### 2.1 Security invariant

Possession of database credentials or the ability to run `iamd` must not by
itself grant signing-key revocation authority. Only an explicitly authorized
operator may revoke.

### 2.2 Mechanism

- Migration `0013` adds a dedicated, **safe-by-default** capability
  `api_keys.can_revoke_keys` (default `false`), independent of API-key scope and
  of tenant/project ownership. It also adds `break_glass_keys` (hashed
  credentials only).
- `iamd revoke-key` requires `IAM_OPERATOR_API_KEY` — an API key that has been
  granted the capability. The key is authenticated by hash (`secret.Hash`), and
  the authorized identity (`api_key:<id>`) is derived from the verified
  credential, never from a caller-supplied string.
- The identity, role, break-glass flag and revocation epoch are written into
  `revoked_by` and the audit event **in the same atomic transaction** as the
  tombstone (`RevokeSigningKeyWithDetail`). An audit-write failure rolls the whole
  revocation back (CRYPTO-05 C1).
- Every authorization **denial** is recorded as `signing_key.revoke.denied` with
  the attempted actor and reason.

### 2.3 Break-glass

`iamd revoke-key --break-glass` uses a distinct, pre-provisioned high-value
credential (`IAM_BREAKGLASS_KEY`, stored only as a hash in `break_glass_keys`),
requires an explicit operator identity (`IAM_OPERATOR_ID`) and a mandatory
reason, and is fully audited with break-glass context (`break_glass: true`). It
bypasses the per-key capability check (its purpose) but never the audit trail,
and it is not anonymous. Every use requires mandatory post-event review.

### 2.4 Provisioning (deployment-time admin actions)

- `iamd grant-revoker <api-key-id>` grants the capability.
- `iamd add-break-glass <label>` registers `IAM_BREAKGLASS_KEY`.

These require database and master-key access. **Threat-model note:** raw database
or master-key access is root-equivalent and is outside the D6 runtime threat
model — such an actor can tamper with any table directly. D6 closes the
*supported runtime path*: a compromised ordinary operator or service account (no
capability) cannot revoke, and identity cannot be spoofed by a string. Separating
the runtime operator credential from deployment provisioning is the control.

### 2.5 Recovery from accidental revocation

Revocation is irreversible by design. To recover service after a mistaken
revocation, **do not** reactivate the key or delete its tombstone. Instead let
the engine promote a published successor or generate a new key (automatic on the
next reload / rotation), and rotate relying parties onto the new JWKS as usual.

---

## 3. Assurance ledger — D3 / D6

Environment for VERIFIED items: local, disposable PostgreSQL 16; Go 1.27.3;
commit `a59af3d` (plus the follow-up test commit on PR #40). `-race` runs in CI
(no cgo locally). "Exact test" names are in the referenced packages.

| Control | Status | Evidence |
|---|---|---|
| D3 authority interface + fail-closed boundary | VERIFIED | `internal/revepoch` `TestMemAuthority*`; interface enforces monotonic/idempotent/outage |
| D3 reference PG adapter (SQL semantics) | VERIFIED (adapter) | `TestPGAuthorityMonotonicIdempotentDurable` against disposable PG |
| D3 reconcile re-applies after restore/PITR | VERIFIED | `TestReconcileReappliesRevocationAfterRestore` |
| D3 authority-first crash recovery | VERIFIED | `TestReconcileRecoversRecordWithoutLocalCommit` |
| D3 fail-closed signing gate | VERIFIED | `TestRunnerGatePolicy`, `TestSigningGateBlocksAtKeyBoundary` |
| D3 rollback fails closed, marker never lowered | VERIFIED | `TestReconcileRollbackFailsClosed` |
| D3 idempotent retries | VERIFIED | `TestReconcileIdempotentRetries` |
| D3 multi-instance safety | VERIFIED (shared-DB) | `TestReconcileConcurrentInstancesSafe`; live multi-process timing PARTIAL |
| D3 production external authority deployed on independent infra | BLOCKED — OPERATIONAL REQUIREMENT | no production-separated authority provisioned; reference adapter + mock only |
| D6 dedicated capability, safe-by-default | VERIFIED | `TestAuthorizeKeyRevokerDeniesWithoutCapability` (admin & login scope denied) |
| D6 unknown credential denied + audited | VERIFIED | `TestAuthorizeKeyRevokerDeniesUnknownCredential` |
| D6 operator identity in `revoked_by` + audit, spoof-resistant | VERIFIED | `TestAuthorizedRevokeRecordsOperatorIdentity` |
| D6 break-glass requires credential, attributed, audited | VERIFIED | `TestBreakGlassAuthorization` |
| D6 audit-write failure rolls revocation back | VERIFIED | C1 `TestRevokeSigningKeyAuditFailureRollsBack` |
| D6 CLI preconditions (id, mandatory reason) | VERIFIED | `TestRevokeKeyRequiresKeyID`, `TestRevokeKeyRequiresReason` |
| D6 full CLI end-to-end (exec against real authority) | INSUFFICIENTLY VERIFIED | layers tested; no process-level e2e of the revoke CLI |

---

## 4. Residual risks and operational prerequisites

- **Production authority (BLOCKER).** The restore/PITR protection is only real
  once `IAM_REVOCATION_AUTHORITY_URL` points at a durable authority deployed on
  infrastructure **independent** of IAM PostgreSQL's backup lifecycle, with its
  own backups and rollback protection. Until then the engine logs that D3 is
  disabled and signs without restore protection. This is the main reason
  CRYPTO-05 stays NO-GO.
- **Availability trade-off.** With D3 enabled, a permanently unreachable
  authority at startup means signing stays disabled (fail closed). Operators must
  run the authority with appropriate availability.
- **In-flight and external JWTs.** Unchanged from the base design: already-issued
  JWTs remain valid at relying parties until their JWKS cache refreshes and the
  token `exp` passes; IAM cannot recall them.
- **Operator identity strength.** D6 identity rests on API-key possession
  (hashed at rest). A stronger IdP/MFA-backed administrative identity is possible
  future hardening, not required by the approved policy.
- **Root-equivalent access** (raw DB / master key) is out of scope for D6, as
  documented in §2.4.
- **Independent external pentest:** NOT PERFORMED (WAIVED).
