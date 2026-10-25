package store

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Audit M10: with the database unreachable the shared limiter must not fail
// open; it falls back to the per-instance limit, and it answers quickly.
func TestPGLimiterFallsBackToLocalLimit(t *testing.T) {
	// Nothing listens on port 1; pgxpool connects lazily, so New succeeds.
	pool, err := pgxpool.New(context.Background(), "postgres://iam:iam@127.0.0.1:1/iam?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	l := New(pool).NewPGLimiter("test", 5, 5)

	start := time.Now()
	allowed := 0
	for range 20 {
		if l.Allow("203.0.113.1") {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("allowed %d of 20 with the database down, want the local limit of 5", allowed)
	}
	if !l.Allow("203.0.113.2") {
		t.Fatal("another key must still be allowed (no global fail-closed)")
	}
	if elapsed := time.Since(start); elapsed > 21*limiterTimeout {
		t.Fatalf("took %v; each decision must be bounded by %v", elapsed, limiterTimeout)
	}
}
