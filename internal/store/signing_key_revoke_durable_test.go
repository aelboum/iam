package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests cover the durable CRYPTO-05 revocation primitive RevokeSigningKey
// and the tombstone-suppressing ListSigningKeys. They are isolation-safe: every
// assertion is scoped to ids this test inserted, so they are robust to other
// packages sharing one IAM_TEST_DATABASE_URL (the mistake that made the removed
// TestRevokedKeyLeavesJWKSAndResigns flaky). Needs IAM_TEST_DATABASE_URL.
func openRevokeTestStore(t *testing.T) (*Store, *pgxpool.Pool, context.Context) {
	t.Helper()
	url := os.Getenv("IAM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set IAM_TEST_DATABASE_URL to a disposable database to run this test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("migrate: %v", err)
	}
	return New(pool), pool, ctx
}

func insertTestKey(t *testing.T, st *Store, ctx context.Context) string {
	t.Helper()
	id := uuid.NewString()
	now := time.Now()
	if err := st.InsertSigningKey(ctx, &SigningKey{
		ID: id, Algorithm: "RS256", PrivateKeyEnc: []byte("enc-" + id),
		RotateAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("insert signing key: %v", err)
	}
	return id
}

func isListed(t *testing.T, st *Store, ctx context.Context, id string) bool {
	t.Helper()
	keys, err := st.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("list signing keys: %v", err)
	}
	for _, k := range keys {
		if k.ID == id {
			return true
		}
	}
	return false
}

func auditCount(t *testing.T, pool *pgxpool.Pool, ctx context.Context, id string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action='signing_key.revoke' AND target=$1`, id,
	).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

func tombstoned(t *testing.T, pool *pgxpool.Pool, ctx context.Context, id string) bool {
	t.Helper()
	var ok bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM revoked_signing_keys WHERE id=$1)`, id,
	).Scan(&ok); err != nil {
		t.Fatalf("check tombstone: %v", err)
	}
	return ok
}

// Test 1: ACTIVE -> REVOKED removes from the list, writes a tombstone and
// exactly one audit event.
func TestRevokeSigningKeyActiveToRevoked(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	id := insertTestKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)

	if !isListed(t, st, ctx, id) {
		t.Fatal("key must be listed before revocation")
	}
	if err := st.RevokeSigningKey(ctx, id, "user:tester", "leak"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if isListed(t, st, ctx, id) {
		t.Error("revoked key is still listed")
	}
	if !tombstoned(t, pool, ctx, id) {
		t.Error("revoked key has no tombstone")
	}
	if n := auditCount(t, pool, ctx, id); n != 1 {
		t.Errorf("audit events for revocation = %d, want 1", n)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM signing_keys WHERE id=$1`, id).Scan(&state); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state != "REVOKED" {
		t.Errorf("state = %q, want REVOKED", state)
	}
}

// Test 2: RETIRING -> REVOKED is also suppressed.
func TestRevokeSigningKeyRetiringToRevoked(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	id := insertTestKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)

	if _, err := pool.Exec(ctx, `UPDATE signing_keys SET state='RETIRING' WHERE id=$1`, id); err != nil {
		t.Fatalf("set retiring: %v", err)
	}
	if err := st.RevokeSigningKey(ctx, id, "system", "retire-then-revoke"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if isListed(t, st, ctx, id) {
		t.Error("revoked (formerly retiring) key is still listed")
	}
}

// T-A: the tombstone overrides row presence. A signing_keys row that reappears
// (restored backup / lagging replica) but whose id is tombstoned is never listed.
func TestTombstoneOverridesRowPresence(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	id := insertTestKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)

	// Simulate resurrection: a fully present, non-REVOKED, unexpired row whose id
	// is independently tombstoned.
	if _, err := pool.Exec(ctx,
		`INSERT INTO revoked_signing_keys (id, revoked_by, reason) VALUES ($1,'system','prior-revocation')`, id,
	); err != nil {
		t.Fatalf("insert tombstone: %v", err)
	}
	if isListed(t, st, ctx, id) {
		t.Error("a present row whose id is tombstoned must not be listed")
	}
}

// T-C: idempotent re-run (e.g. operator retries after an ambiguous COMMIT). A
// second revocation is a no-op: one tombstone, exactly one audit event, no error.
func TestRevokeSigningKeyIdempotentRerun(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	id := insertTestKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)

	if err := st.RevokeSigningKey(ctx, id, "system", "first"); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := st.RevokeSigningKey(ctx, id, "system", "retry"); err != nil {
		t.Fatalf("second revoke must be a no-op, got: %v", err)
	}
	if n := auditCount(t, pool, ctx, id); n != 1 {
		t.Errorf("audit events after re-run = %d, want exactly 1 (no duplicate)", n)
	}
	var tombs int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM revoked_signing_keys WHERE id=$1`, id).Scan(&tombs); err != nil {
		t.Fatalf("count tombstones: %v", err)
	}
	if tombs != 1 {
		t.Errorf("tombstones = %d, want 1", tombs)
	}
}

// Test 16 (atomicity): revoking an id that was never a key writes no tombstone
// and no audit event, and reports ErrNotFound — the gated audit rolls back with
// the transaction.
func TestRevokeSigningKeyUnknownIsAtomicNotFound(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	id := uuid.NewString()
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)

	if err := st.RevokeSigningKey(ctx, id, "system", "nope"); err != ErrNotFound {
		t.Fatalf("revoke unknown id = %v, want ErrNotFound", err)
	}
	if tombstoned(t, pool, ctx, id) {
		t.Error("unknown-id revocation must not leave a tombstone")
	}
	if n := auditCount(t, pool, ctx, id); n != 0 {
		t.Errorf("unknown-id revocation wrote %d audit events, want 0", n)
	}
}

// Test 17: PurgeExpired must never remove revocation evidence. The tombstone
// table has no expires_at and is not in PurgedTables, so resurrection protection
// is durable: a tombstone survives routine purging indefinitely.
func TestPurgeExpiredRetainsTombstone(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	id := uuid.NewString()
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)

	if _, err := pool.Exec(ctx,
		`INSERT INTO revoked_signing_keys (id, revoked_by, reason) VALUES ($1,'system','retention-test')`, id,
	); err != nil {
		t.Fatalf("insert tombstone: %v", err)
	}
	if err := st.PurgeExpired(ctx); err != nil {
		t.Fatalf("purge expired: %v", err)
	}
	if !tombstoned(t, pool, ctx, id) {
		t.Error("PurgeExpired removed a revocation tombstone")
	}
}

// C1 (audit-failure injection): if the in-transaction audit INSERT fails, the
// whole revocation must roll back — no tombstone, the key stays ACTIVE and
// listed, and no partial audit evidence survives. A plpgsql BEFORE INSERT
// trigger scoped to action='signing_key.revoke' forces the audit write (and
// only that write) to fail deterministically, so this is isolation-safe even on
// a shared test database. It proves RevokeSigningKey reports success only after
// a durable commit and never leaves a key half-revoked.
func TestRevokeSigningKeyAuditFailureRollsBack(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	id := insertTestKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)

	// Force only the signing_key.revoke audit INSERT to fail.
	if _, err := pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION iam_test_fail_audit() RETURNS trigger AS $$
		BEGIN RAISE EXCEPTION 'injected audit failure'; END;
		$$ LANGUAGE plpgsql`); err != nil {
		t.Fatalf("create trigger fn: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE TRIGGER iam_test_fail_audit_trg BEFORE INSERT ON audit_events
		FOR EACH ROW WHEN (NEW.action = 'signing_key.revoke')
		EXECUTE FUNCTION iam_test_fail_audit()`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	defer pool.Exec(ctx, `DROP TRIGGER IF EXISTS iam_test_fail_audit_trg ON audit_events`)
	defer pool.Exec(ctx, `DROP FUNCTION IF EXISTS iam_test_fail_audit()`)

	if err := st.RevokeSigningKey(ctx, id, "system", "audit-fail"); err == nil {
		t.Fatal("revoke must fail when the in-transaction audit write fails")
	}

	// Everything rolled back: no tombstone, key still ACTIVE and listed, no audit.
	if tombstoned(t, pool, ctx, id) {
		t.Error("tombstone persisted despite audit failure: revocation is not atomic")
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM signing_keys WHERE id=$1`, id).Scan(&state); err != nil {
		t.Fatalf("read state: %v", err)
	}
	if state != "ACTIVE" {
		t.Errorf("state = %q, want ACTIVE (must roll back on audit failure)", state)
	}
	if !isListed(t, st, ctx, id) {
		t.Error("key is not listed after rollback: a failed revocation must not suppress the key")
	}
	if n := auditCount(t, pool, ctx, id); n != 0 {
		t.Errorf("audit events = %d, want 0 after rollback", n)
	}
}

// C2 (cross-instance convergence): the database is the single authority, so a
// key revoked through one Store is suppressed for an entirely independent Store
// (separate connection pool, same database) the moment that instance re-reads
// ListSigningKeys. This is the real multi-instance mechanism — each engine's
// keyStore re-reads the authoritative list on cache expiry (bounded by
// keyCacheTTL); there is no LISTEN/NOTIFY and none is needed for correctness.
// This test proves the shared-authority half; the per-instance cache-expiry half
// is covered by the oidcop seam and fail-closed tests. Live two-process timing
// convergence still needs a dedicated multi-process engine harness.
func TestRevocationVisibleAcrossIndependentStores(t *testing.T) {
	stA, poolA, ctx := openRevokeTestStore(t)
	defer poolA.Close()
	id := insertTestKey(t, stA, ctx)
	defer poolA.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer poolA.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer poolA.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)

	// A second, fully independent instance against the same database.
	poolB, err := pgxpool.New(ctx, os.Getenv("IAM_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("open instance B: %v", err)
	}
	defer poolB.Close()
	stB := New(poolB)

	if !isListed(t, stB, ctx, id) {
		t.Fatal("instance B must list the key before revocation")
	}
	if err := stA.RevokeSigningKey(ctx, id, "system", "cross-instance"); err != nil {
		t.Fatalf("revoke on instance A: %v", err)
	}
	// Instance B re-reads the authoritative store and no longer sees the key.
	if isListed(t, stB, ctx, id) {
		t.Error("revocation on instance A is not visible to independent instance B")
	}
}
