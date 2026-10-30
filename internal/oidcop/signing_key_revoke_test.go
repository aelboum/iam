package oidcop

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Emergency revocation (audit CRYPTO-05): deleting a signing key must drop it
// from the published JWKS (KeySet) on the next key reload, and the key store
// must keep producing a usable signer afterwards — here by generating a fresh
// key because the revoked one was the only key. Needs IAM_TEST_DATABASE_URL.
func TestRevokedKeyLeavesJWKSAndResigns(t *testing.T) {
	url := os.Getenv("IAM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set IAM_TEST_DATABASE_URL to a disposable database to run this test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Start from a clean key table so the assertions are about this test's keys.
	if _, err := pool.Exec(ctx, `DELETE FROM signing_keys`); err != nil {
		t.Fatalf("clear signing_keys: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM signing_keys`)

	st := store.New(pool)
	ks := newKeyStore(st, secret.NewBox([32]byte{59}), time.Hour)

	// First use generates the initial signing key.
	k1, _, err := ks.current(ctx)
	if err != nil {
		t.Fatalf("initial current: %v", err)
	}
	id1 := k1.id

	inJWKS := func() map[string]bool {
		keys, err := ks.KeySet(ctx)
		if err != nil {
			t.Fatalf("keyset: %v", err)
		}
		set := map[string]bool{}
		for _, k := range keys {
			set[k.ID()] = true
		}
		return set
	}
	if !inJWKS()[id1] {
		t.Fatalf("the initial key %s must be published in the JWKS", id1)
	}

	// Revoke it, then force the cache to reload (as another instance would within
	// keyCacheTTL).
	if err := st.DeleteSigningKey(ctx, id1); err != nil {
		t.Fatalf("revoke key: %v", err)
	}
	ks.mu.Lock()
	ks.loadedAt = time.Time{}
	ks.keys = nil
	ks.mu.Unlock()

	k2, _, err := ks.current(ctx)
	if err != nil {
		t.Fatalf("current after revocation: %v", err)
	}
	if k2.id == id1 {
		t.Fatal("the signer is still the revoked key")
	}
	set := inJWKS()
	if set[id1] {
		t.Error("the revoked key is still published in the JWKS")
	}
	if !set[k2.id] {
		t.Error("the replacement signing key is not published in the JWKS")
	}

	// A signer is still available (signing did not break).
	sk, err := ks.SigningKey(ctx)
	if err != nil {
		t.Fatalf("signing key after revocation: %v", err)
	}
	if sk.ID() == id1 {
		t.Error("SigningKey still returns the revoked key")
	}
}
