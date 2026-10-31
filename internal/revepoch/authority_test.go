package revepoch

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// --- Test adapter (MemAuthority) ------------------------------------------------
//
// These exercise the Authority contract against the in-memory test adapter. They
// prove the required semantics (monotonic, idempotent, since-ordering, outage,
// rollback) without infrastructure. They are NOT evidence about a production
// authority; see the PGAuthority tests for the reference adapter.

func TestMemAuthorityMonotonicAndIdempotent(t *testing.T) {
	ctx := context.Background()
	a := NewMemAuthority()

	if e, err := a.Current(ctx); err != nil || e != 0 {
		t.Fatalf("empty authority Current = %d, %v; want 0, nil", e, err)
	}
	e1, err := a.Record(ctx, "k1")
	if err != nil || e1 != 1 {
		t.Fatalf("Record k1 = %d, %v; want 1, nil", e1, err)
	}
	e2, err := a.Record(ctx, "k2")
	if err != nil || e2 != 2 {
		t.Fatalf("Record k2 = %d, %v; want 2, nil", e2, err)
	}
	// Idempotent: recording k1 again returns its epoch and does not advance.
	again, err := a.Record(ctx, "k1")
	if err != nil || again != 1 {
		t.Fatalf("re-Record k1 = %d, %v; want 1, nil", again, err)
	}
	if cur, _ := a.Current(ctx); cur != 2 {
		t.Fatalf("Current after idempotent re-record = %d; want 2 (no advance)", cur)
	}
}

func TestMemAuthorityRevokedSinceOrdered(t *testing.T) {
	ctx := context.Background()
	a := NewMemAuthority()
	a.Record(ctx, "k1")
	a.Record(ctx, "k2")
	a.Record(ctx, "k3")

	recs, err := a.RevokedSince(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].KeyID != "k2" || recs[1].KeyID != "k3" {
		t.Fatalf("RevokedSince(1) = %+v; want k2,k3 ascending", recs)
	}
	if recs[0].Epoch >= recs[1].Epoch {
		t.Fatalf("RevokedSince not ascending by epoch: %+v", recs)
	}
}

func TestMemAuthorityOutageFailsClosed(t *testing.T) {
	ctx := context.Background()
	a := NewMemAuthority()
	a.Record(ctx, "k1")
	a.SetUnavailable(true)
	if _, err := a.Current(ctx); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Current during outage = %v; want ErrUnavailable", err)
	}
	if _, err := a.Record(ctx, "k2"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Record during outage = %v; want ErrUnavailable", err)
	}
	if _, err := a.RevokedSince(ctx, 0); !errors.Is(err, ErrUnavailable) {
		t.Errorf("RevokedSince during outage = %v; want ErrUnavailable", err)
	}
}

// --- Reference adapter (PGAuthority) --------------------------------------------
//
// These exercise the reference PostgreSQL adapter against a DISPOSABLE database.
// They prove the adapter's SQL-level semantics (durable append-only log,
// monotonic bigint epoch, idempotent record). They are NOT evidence that a
// production authority deployed on infrastructure independent of IAM PostgreSQL
// exists or has been operated; that remains an operational prerequisite.
func openPGAuthority(t *testing.T) (*PGAuthority, *pgxpool.Pool, context.Context) {
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
	a := NewPGAuthority(pool)
	if err := a.Migrate(ctx); err != nil {
		pool.Close()
		t.Fatalf("migrate authority: %v", err)
	}
	return a, pool, ctx
}

func TestPGAuthorityMonotonicIdempotentDurable(t *testing.T) {
	a, pool, ctx := openPGAuthority(t)
	defer pool.Close()
	k1 := "test-" + uuid.NewString()
	k2 := "test-" + uuid.NewString()
	defer pool.Exec(ctx, `DELETE FROM revocation_epoch_log WHERE key_id IN ($1,$2)`, k1, k2)

	e1, err := a.Record(ctx, k1)
	if err != nil {
		t.Fatalf("record k1: %v", err)
	}
	e2, err := a.Record(ctx, k2)
	if err != nil || e2 <= e1 {
		t.Fatalf("record k2 = %d, %v; want > %d", e2, err, e1)
	}
	// Idempotent: same epoch, no advance.
	again, err := a.Record(ctx, k1)
	if err != nil || again != e1 {
		t.Fatalf("re-record k1 = %d, %v; want %d", again, err, e1)
	}
	// RevokedSince returns our keys after e1-1 in ascending order.
	recs, err := a.RevokedSince(ctx, e1-1)
	if err != nil {
		t.Fatal(err)
	}
	var sawK1, sawK2 bool
	for _, r := range recs {
		if r.KeyID == k1 {
			sawK1 = true
		}
		if r.KeyID == k2 {
			sawK2 = true
		}
	}
	if !sawK1 || !sawK2 {
		t.Errorf("RevokedSince missing inserted keys: %+v", recs)
	}
}
