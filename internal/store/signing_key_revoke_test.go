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

// DeleteSigningKey is the emergency-revocation primitive (audit CRYPTO-05): a
// deleted key no longer appears in ListSigningKeys, which is what feeds the
// published JWKS, so revoking a leaked key drops it from /keys. Deleting an
// unknown id changes nothing and reports ErrNotFound. Needs IAM_TEST_DATABASE_URL.
func TestDeleteSigningKeyRemovesFromList(t *testing.T) {
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
	st := New(pool)

	now := time.Now()
	mk := func() string {
		id := uuid.NewString()
		if err := st.InsertSigningKey(ctx, &SigningKey{
			ID: id, Algorithm: "RS256", PrivateKeyEnc: []byte("enc-" + id),
			RotateAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour),
		}); err != nil {
			t.Fatalf("insert signing key: %v", err)
		}
		return id
	}
	id1, id2 := mk(), mk()
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id = ANY($1)`, []string{id1, id2})

	listed := func() map[string]bool {
		keys, err := st.ListSigningKeys(ctx)
		if err != nil {
			t.Fatalf("list signing keys: %v", err)
		}
		set := map[string]bool{}
		for _, k := range keys {
			set[k.ID] = true
		}
		return set
	}

	if l := listed(); !l[id1] || !l[id2] {
		t.Fatalf("both keys must be listed before revocation: %v", l)
	}

	// Revoke id1.
	if err := st.DeleteSigningKey(ctx, id1); err != nil {
		t.Fatalf("delete signing key: %v", err)
	}
	if l := listed(); l[id1] {
		t.Error("revoked key is still published in ListSigningKeys")
	} else if !l[id2] {
		t.Error("revoking one key must not remove the other")
	}

	// Revoking an unknown id changes nothing and reports ErrNotFound.
	if err := st.DeleteSigningKey(ctx, uuid.NewString()); err != ErrNotFound {
		t.Errorf("deleting an unknown key = %v, want ErrNotFound", err)
	}
	if l := listed(); !l[id2] {
		t.Error("a no-op delete must not remove the surviving key")
	}
}
