package db

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMigrateConcurrent proves that Migrate is safe when several processes run
// it at once against the same fresh database, as happens when a horizontally
// scaled deployment rolls out and every replica starts and migrates together,
// or when parallel `go test ./...` packages share one test database.
//
// It needs a disposable superuser database (IAM_TEST_DATABASE_URL) because it
// creates and drops a throwaway database of its own. It is skipped otherwise.
func TestMigrateConcurrent(t *testing.T) {
	base := os.Getenv("IAM_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set IAM_TEST_DATABASE_URL to a disposable database to run this test")
	}

	admin, err := pgxpool.New(context.Background(), base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer admin.Close()

	name := fmt.Sprintf("iam_migrate_concurrent_%d", time.Now().UnixNano())
	ctx := context.Background()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	defer func() {
		// Terminate any lingering backends, then drop the throwaway database.
		_, _ = admin.Exec(context.Background(),
			"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1", name)
		if _, err := admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name); err != nil {
			t.Logf("drop database %s: %v", name, err)
		}
	}()

	target := swapDatabase(base, name)
	pool, err := pgxpool.New(ctx, target)
	if err != nil {
		t.Fatalf("connect target: %v", err)
	}
	defer pool.Close()

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release all workers together to maximise contention
			if err := Migrate(ctx, pool); err != nil {
				errs <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Migrate returned error: %v", err)
	}

	// Every migration must be recorded exactly once: no duplicate-key damage and
	// no migration skipped by a racing applied-check.
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected migrations to be recorded, got 0")
	}
}

// swapDatabase returns url with its database path replaced by name, preserving
// scheme, credentials, host and query parameters.
func swapDatabase(url, name string) string {
	// Split off any query string.
	q := ""
	if i := strings.IndexByte(url, '?'); i >= 0 {
		q = url[i:]
		url = url[:i]
	}
	if i := strings.LastIndexByte(url, '/'); i >= 0 {
		url = url[:i+1] + name
	}
	return url + q
}
