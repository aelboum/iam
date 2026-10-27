package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigrateLockAcquisitionIsCancellable proves the migration advisory lock
// fails closed under contention: if another session already holds the lock, a
// Migrate whose context is cancelled/times out must return promptly with an
// error rather than block forever (which would hang a replica's startup behind
// a stuck migrator), and it must leave no state behind so that a later Migrate
// succeeds once the lock frees.
//
// Needs a disposable superuser database (IAM_TEST_DATABASE_URL); it creates and
// drops a throwaway database of its own.
func TestMigrateLockAcquisitionIsCancellable(t *testing.T) {
	base := os.Getenv("IAM_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set IAM_TEST_DATABASE_URL to a disposable database to run this test")
	}
	ctx := context.Background()

	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close()

	name := fmt.Sprintf("iam_migrate_lockcancel_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	defer func() {
		_, _ = admin.Exec(context.Background(),
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1", name)
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name); err != nil {
			t.Logf("drop database %s: %v", name, err)
		}
	}()

	pool, err := pgxpool.New(ctx, swapDatabase(base, name))
	if err != nil {
		t.Fatalf("connect target: %v", err)
	}
	defer pool.Close()

	// Hold the migration advisory lock on a dedicated session, so any Migrate
	// blocks on acquisition.
	holder, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire holder: %v", err)
	}
	if _, err := holder.Exec(ctx, "SELECT pg_advisory_lock($1)", migrateAdvisoryLockKey); err != nil {
		holder.Release()
		t.Fatalf("hold lock: %v", err)
	}
	released := false
	releaseHolder := func() {
		if released {
			return
		}
		released = true
		_, _ = holder.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrateAdvisoryLockKey)
		holder.Release()
	}
	defer releaseHolder()

	// Migrate with a short deadline must return an error within roughly that
	// deadline, not hang on the held lock.
	cctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	err = Migrate(cctx, pool)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("Migrate returned nil while the lock was held; expected a context error")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Migrate blocked %v on a held lock; acquisition is not cancellable", elapsed)
	}

	// Releasing the lock must let a fresh Migrate complete: the timed-out attempt
	// left no lock held and no connection stranded.
	releaseHolder()
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatalf("Migrate after the lock was released: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected migrations to be recorded after a successful Migrate, got 0")
	}
}
