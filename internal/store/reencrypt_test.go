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

// TestScanEncryptedReadOnlyDoesNotPurge proves that the scan used by
// `rotate-keys --check` leaves expired rows (and all other state) untouched
// (audit M9 / improvement A): it must only read, never purge.
//
// It needs a real database, so it is skipped unless IAM_TEST_DATABASE_URL is
// set (e.g. a disposable test database). It never resets or purges the
// database: it inserts one uniquely-named expired signing key, runs the
// read-only scan, checks the row survived, and removes only that row.
func TestScanEncryptedReadOnlyDoesNotPurge(t *testing.T) {
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
	// The disposable test database may be empty; apply migrations so the schema
	// this test relies on (signing_keys) exists. Migrate is idempotent, so it is
	// a no-op when the database is already migrated.
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	st := New(pool)

	id := "check-test-" + uuid.NewString()
	if err := st.InsertSigningKey(ctx, &SigningKey{
		ID: id, Algorithm: "RS256", PrivateKeyEnc: []byte("not-a-real-key"),
		RotateAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour), // already expired
	}); err != nil {
		t.Fatalf("insert expired signing key: %v", err)
	}
	// Always clean up the one row this test created.
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id = $1`, id)

	before := countSigningKeys(t, st)

	seen := false
	if err := st.ScanEncryptedReadOnly(ctx, func(v EncryptedValue) error {
		if v.Table == "signing_keys" && v.ID == id {
			seen = true
		}
		return nil
	}); err != nil {
		t.Fatalf("ScanEncryptedReadOnly: %v", err)
	}

	if !seen {
		t.Error("read-only scan did not visit the expired signing key")
	}
	if after := countSigningKeys(t, st); after != before {
		t.Errorf("row count changed across a read-only scan: before=%d after=%d (it must not purge)", before, after)
	}
	var stillThere bool
	if err := pool.QueryRow(ctx, `SELECT exists(SELECT 1 FROM signing_keys WHERE id = $1)`, id).Scan(&stillThere); err != nil {
		t.Fatalf("existence check: %v", err)
	}
	if !stillThere {
		t.Error("read-only scan deleted the expired signing key; --check must leave expired records in place")
	}
}

func countSigningKeys(t *testing.T, st *Store) int {
	t.Helper()
	var n int
	if err := st.pool.QueryRow(context.Background(), `SELECT count(*) FROM signing_keys`).Scan(&n); err != nil {
		t.Fatalf("count signing_keys: %v", err)
	}
	return n
}
