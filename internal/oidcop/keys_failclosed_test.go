package oidcop

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
)

// TestCurrentFailsClosedWhenStoreUnavailable proves the CRYPTO-05 fail-closed
// guarantee (plan AC / FAILCLOSED-1): once the per-store key cache has expired,
// current() reloads from the database, and if the store is unavailable it
// returns the error rather than silently continuing to serve the stale cached
// key. This is the invariant that bounds a revoked key to one cache interval:
// an engine that cannot confirm the current key set stops signing instead of
// trusting a cache that may name a revoked key. Needs IAM_TEST_DATABASE_URL.
func TestCurrentFailsClosedWhenStoreUnavailable(t *testing.T) {
	url := os.Getenv("IAM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set IAM_TEST_DATABASE_URL to a disposable database to run this test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st := store.New(pool)
	ks := newKeyStore(st, secret.NewBox([32]byte{71}), 30*24*time.Hour)

	// Seed a usable cached key so the only reason to reload is cache expiry. priv
	// is never dereferenced on this path (signer returns the key; nothing signs).
	now := ks.now()
	ks.keys = []*signingKey{{id: "cached", createdAt: now.Add(-time.Hour), rotateAt: now.Add(29 * 24 * time.Hour)}}
	ks.loadedAt = now

	// Within the cache TTL, current() serves the cached key without touching the
	// database at all.
	if _, _, err := ks.current(ctx); err != nil {
		t.Fatalf("within TTL current() errored unexpectedly: %v", err)
	}

	// Make the store unreachable and force the cache to look expired. current()
	// must now reload, fail, and surface the error — never serve the stale key.
	pool.Close()
	ks.loadedAt = ks.now().Add(-2 * keyCacheTTL)

	if _, _, err := ks.current(ctx); err == nil {
		t.Fatal("current() must fail closed when the cache expired and the store is unavailable, not serve a stale key")
	}
}
