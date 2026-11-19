package revocation

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/aelboum/iam/internal/revepoch"
	"github.com/aelboum/iam/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests exercise CRYPTO-05 D3 reconciliation and the fail-closed signing
// gate against a disposable IAM PostgreSQL and the in-memory test authority
// (revepoch.MemAuthority). The in-memory authority stands in for the independent
// authority: because it is not part of the IAM database, deleting tombstones and
// resetting the reconciliation marker (which models an IAM PostgreSQL
// restore/PITR) does not affect it — exactly the independence the design relies
// on. They are not evidence about a production authority deployment.

func openStore(t *testing.T) (*store.Store, *pgxpool.Pool, context.Context) {
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
	return store.New(pool), pool, ctx
}

func insertKey(t *testing.T, st *store.Store, ctx context.Context) string {
	t.Helper()
	id := uuid.NewString()
	now := time.Now()
	if err := st.InsertSigningKey(ctx, &store.SigningKey{
		ID: id, Algorithm: "RS256", PrivateKeyEnc: []byte("enc-" + id),
		RotateAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour),
	}); err != nil {
		t.Fatalf("insert signing key: %v", err)
	}
	return id
}

func listed(t *testing.T, st *store.Store, ctx context.Context, id string) bool {
	t.Helper()
	keys, err := st.ListSigningKeys(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, k := range keys {
		if k.ID == id {
			return true
		}
	}
	return false
}

// simulateRestoreBefore models an IAM PostgreSQL restore/PITR to a point before
// the revocation: the key row is back and ACTIVE, its tombstone is gone, and the
// local reconciliation marker is rewound. The independent authority is untouched.
func simulateRestoreBefore(t *testing.T, pool *pgxpool.Pool, ctx context.Context, id string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id); err != nil {
		t.Fatalf("restore (drop tombstone): %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE signing_keys SET state='ACTIVE', revoked_at=NULL, revoked_reason=NULL WHERE id=$1`, id); err != nil {
		t.Fatalf("restore (reactivate row): %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE revocation_reconciliation SET reconciled_epoch=0 WHERE id`); err != nil {
		t.Fatalf("restore (rewind marker): %v", err)
	}
}

// Scenario 1-10: a revoked key resurrected by a restore is re-suppressed by
// reconciliation, and only reconciliation (not a marker rewind) can clear it.
func TestReconcileReappliesRevocationAfterRestore(t *testing.T) {
	st, pool, ctx := openStore(t)
	defer pool.Close()
	id := insertKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)
	defer pool.Exec(ctx, `UPDATE revocation_reconciliation SET reconciled_epoch=0 WHERE id`)

	auth := revepoch.NewMemAuthority()
	// Revoke: authority first, then local, then reconcile the marker.
	if _, err := auth.Record(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeSigningKey(ctx, id, "api_key:op", "leak"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := Reconcile(ctx, st, auth); err != nil {
		t.Fatalf("reconcile after revoke: %v", err)
	}
	if listed(t, st, ctx, id) {
		t.Fatal("key still listed right after revocation")
	}

	// Restore to before the revocation: the key is resurrected locally.
	simulateRestoreBefore(t, pool, ctx, id)
	if !listed(t, st, ctx, id) {
		t.Fatal("restore simulation did not resurrect the key")
	}

	// Reconcile against the authority (still ahead): the revocation is re-applied.
	epoch, err := Reconcile(ctx, st, auth)
	if err != nil {
		t.Fatalf("reconcile after restore: %v", err)
	}
	if epoch != 1 {
		t.Errorf("reconciled epoch = %d; want 1", epoch)
	}
	if listed(t, st, ctx, id) {
		t.Error("key is still listed after reconciliation re-applied the revocation")
	}
	var tomb bool
	pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM revoked_signing_keys WHERE id=$1)`, id).Scan(&tomb)
	if !tomb {
		t.Error("tombstone not re-applied by reconciliation")
	}
}

// Scenario 12: a crash after the authority recorded the revocation but before the
// local commit still results in the key being suppressed, via reconciliation.
func TestReconcileRecoversRecordWithoutLocalCommit(t *testing.T) {
	st, pool, ctx := openStore(t)
	defer pool.Close()
	id := insertKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)
	defer pool.Exec(ctx, `UPDATE revocation_reconciliation SET reconciled_epoch=0 WHERE id`)

	auth := revepoch.NewMemAuthority()
	if _, err := auth.Record(ctx, id); err != nil { // authority ahead, local never committed
		t.Fatal(err)
	}
	if !listed(t, st, ctx, id) {
		t.Fatal("key should still be listed (local revoke never happened)")
	}
	if _, err := Reconcile(ctx, st, auth); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if listed(t, st, ctx, id) {
		t.Error("reconciliation did not suppress a key the authority had recorded")
	}
}

// Scenarios 13/14: reconciliation is idempotent across retries.
func TestReconcileIdempotentRetries(t *testing.T) {
	st, pool, ctx := openStore(t)
	defer pool.Close()
	id := insertKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)
	defer pool.Exec(ctx, `UPDATE revocation_reconciliation SET reconciled_epoch=0 WHERE id`)

	auth := revepoch.NewMemAuthority()
	auth.Record(ctx, id)
	for i := 0; i < 3; i++ {
		if _, err := Reconcile(ctx, st, auth); err != nil {
			t.Fatalf("reconcile #%d: %v", i, err)
		}
	}
	var n int
	pool.QueryRow(ctx, `SELECT count(*) FROM revoked_signing_keys WHERE id=$1`, id).Scan(&n)
	if n != 1 {
		t.Errorf("tombstones after repeated reconcile = %d; want 1", n)
	}
}

// Scenario 15: an authority rollback (Current below the local reconciled epoch)
// is fail-closed — Reconcile reports ErrRollback and never lowers local state.
func TestReconcileRollbackFailsClosed(t *testing.T) {
	st, pool, ctx := openStore(t)
	defer pool.Close()
	id := insertKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)
	defer pool.Exec(ctx, `UPDATE revocation_reconciliation SET reconciled_epoch=0 WHERE id`)

	auth := revepoch.NewMemAuthority()
	auth.Record(ctx, id)
	if _, err := Reconcile(ctx, st, auth); err != nil {
		t.Fatalf("initial reconcile: %v", err)
	}
	// Authority rolls back below the local marker.
	auth.ForceRollback(0)
	_, err := Reconcile(ctx, st, auth)
	if !errors.Is(err, revepoch.ErrRollback) {
		t.Fatalf("reconcile after rollback = %v; want ErrRollback", err)
	}
	// Local marker must not have been lowered.
	local, _ := st.ReconciledEpoch(ctx)
	if local != 1 {
		t.Errorf("local reconciled epoch = %d after rollback; want 1 (unchanged)", local)
	}
}

// Gate + Runner: the gate starts closed, opens after a successful reconcile,
// closes on rollback, and tolerates a transient outage once already open.
func TestRunnerGatePolicy(t *testing.T) {
	st, pool, ctx := openStore(t)
	defer pool.Close()
	id := insertKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)
	defer pool.Exec(ctx, `UPDATE revocation_reconciliation SET reconciled_epoch=0 WHERE id`)

	auth := revepoch.NewMemAuthority()
	auth.Record(ctx, id)
	r, gate := NewRunner(st, auth, 0, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	if gate.Err() == nil {
		t.Fatal("gate must start closed")
	}
	// Startup outage: gate stays closed (fail closed).
	auth.SetUnavailable(true)
	_ = r.ReconcileOnce(ctx)
	if gate.Err() == nil {
		t.Error("gate must stay closed while authority is unavailable at startup")
	}
	// Authority back: reconcile succeeds, gate opens.
	auth.SetUnavailable(false)
	if err := r.ReconcileOnce(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if gate.Err() != nil {
		t.Errorf("gate must open after successful reconcile: %v", gate.Err())
	}
	// Transient outage once already open: gate stays open (availability).
	auth.SetUnavailable(true)
	_ = r.ReconcileOnce(ctx)
	if gate.Err() != nil {
		t.Errorf("gate must tolerate a transient outage once open: %v", gate.Err())
	}
	// Rollback: gate closes.
	auth.SetUnavailable(false)
	auth.ForceRollback(0)
	_ = r.ReconcileOnce(ctx)
	if gate.Err() == nil {
		t.Error("gate must close on authority rollback")
	}
}

// Concurrency / multi-instance: two independent Stores reconciling the same
// restore against one authority is safe and converges to a single tombstone.
func TestReconcileConcurrentInstancesSafe(t *testing.T) {
	stA, poolA, ctx := openStore(t)
	defer poolA.Close()
	id := insertKey(t, stA, ctx)
	defer poolA.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, id)
	defer poolA.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, id)
	defer poolA.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, id)
	defer poolA.Exec(ctx, `UPDATE revocation_reconciliation SET reconciled_epoch=0 WHERE id`)

	poolB, err := pgxpool.New(ctx, os.Getenv("IAM_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	defer poolB.Close()
	stB := store.New(poolB)

	auth := revepoch.NewMemAuthority()
	auth.Record(ctx, id)

	var wg sync.WaitGroup
	for _, st := range []*store.Store{stA, stB} {
		wg.Add(1)
		go func(s *store.Store) {
			defer wg.Done()
			if _, err := Reconcile(ctx, s, auth); err != nil {
				t.Errorf("concurrent reconcile: %v", err)
			}
		}(st)
	}
	wg.Wait()

	var n int
	poolA.QueryRow(ctx, `SELECT count(*) FROM revoked_signing_keys WHERE id=$1`, id).Scan(&n)
	if n != 1 {
		t.Errorf("tombstones after concurrent reconcile = %d; want 1", n)
	}
	if listed(t, stA, ctx, id) {
		t.Error("key still listed after concurrent reconciliation")
	}
}
