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
