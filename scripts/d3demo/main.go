//go:build demo

// Command d3demo is the CRYPTO-05 D3 restore/PITR operational-demo helper. It is
// NOT part of the normal build (build tag "demo") and is driven by
// scripts/d3_restore_demo.sh, which owns the disposable databases and performs a
// real pg_dump/restore between the helper's phases. Each phase runs as its own
// process (so no connection pools are held across the restore) and exercises the
// real production code: internal/store, internal/revepoch and internal/revocation.
//
// Phases:
//
//	setup                 migrate IAM + authority, insert a signing key, print its id
//	revoke   <key-id>     authority-first revoke + reconcile (the supported ordering)
//	listed   <key-id>     print "LISTED <id>" or "SUPPRESSED <id>" (always exit 0)
//	reconcile             reconcile against the authority; exit 0 iff the gate opens
//	failclosed            reconcile with the authority unreachable; exit 0 iff the gate stays closed
//
// Environment: IAM_DATABASE_URL, IAM_REVOCATION_AUTHORITY_URL.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/aelboum/iam/internal/revepoch"
	"github.com/aelboum/iam/internal/revocation"
	"github.com/aelboum/iam/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: d3demo <setup|revoke|listed|reconcile|failclosed> [key-id]")
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "setup":
		setup(ctx)
	case "revoke":
		revoke(ctx, arg(2))
	case "listed":
		listed(ctx, arg(2))
	case "reconcile":
		reconcile(ctx, false)
	case "failclosed":
		reconcile(ctx, true)
	default:
		fail("unknown phase %q", os.Args[1])
	}
}

func setup(ctx context.Context) {
	st, pool := openIAM(ctx)
	defer pool.Close()
	auth, apool := openAuthority(ctx, mustEnv("IAM_REVOCATION_AUTHORITY_URL"))
	defer apool.Close()
	if err := auth.Migrate(ctx); err != nil {
		fail("authority migrate: %v", err)
	}
	id := uuid.NewString()
	now := time.Now()
	if err := st.InsertSigningKey(ctx, &store.SigningKey{
		ID: id, Algorithm: "RS256", PrivateKeyEnc: []byte("demo-enc-" + id),
		RotateAt: now.Add(time.Hour), ExpiresAt: now.Add(2 * time.Hour),
	}); err != nil {
		fail("insert key: %v", err)
	}
	fmt.Println(id)
}

func revoke(ctx context.Context, id string) {
	st, pool := openIAM(ctx)
	defer pool.Close()
	auth, apool := openAuthority(ctx, mustEnv("IAM_REVOCATION_AUTHORITY_URL"))
	defer apool.Close()
	// Authority-first ordering, then the atomic local commit, then reconcile.
	if _, err := auth.Record(ctx, id); err != nil {
		fail("authority record: %v", err)
	}
	if err := st.RevokeSigningKey(ctx, id, "api_key:demo-operator", "D3 demo revocation"); err != nil {
		fail("local revoke: %v", err)
	}
	if _, err := revocation.Reconcile(ctx, st, auth); err != nil {
		fail("reconcile: %v", err)
	}
	fmt.Println("revoked", id)
}

func listed(ctx context.Context, id string) {
	st, pool := openIAM(ctx)
	defer pool.Close()
	keys, err := st.ListSigningKeys(ctx)
	if err != nil {
		fail("list: %v", err)
	}
	for _, k := range keys {
		if k.ID == id {
			fmt.Println("LISTED", id)
			return
		}
	}
	fmt.Println("SUPPRESSED", id)
}

// reconcile runs one reconciliation through the real Runner/gate. With
// failClosed, the authority URL is expected to be unreachable, so the gate must
// stay closed; otherwise a successful reconcile must open it.
func reconcile(ctx context.Context, failClosed bool) {
	st, pool := openIAM(ctx)
	defer pool.Close()
	auth, apool := openAuthority(ctx, mustEnv("IAM_REVOCATION_AUTHORITY_URL"))
	defer apool.Close()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	runner, gate := revocation.NewRunner(st, auth, 0, log)
	_ = runner.ReconcileOnce(ctx)

	closed := gate.Err() != nil
	if failClosed {
		if closed {
			fmt.Println("GATE CLOSED (fail-closed as required)")
			os.Exit(0)
		}
		fail("gate OPEN while authority unreachable — fail-open!")
	}
	if !closed {
		fmt.Println("GATE OPEN (reconciled)")
		os.Exit(0)
	}
	fail("gate still CLOSED after reconcile: %v", gate.Err())
}

func openIAM(ctx context.Context) (*store.Store, *pgxpool.Pool) {
	pool, err := db.Open(ctx, mustEnv("IAM_DATABASE_URL"))
	if err != nil {
		fail("open IAM: %v", err)
	}
	if err := db.Migrate(ctx, pool); err != nil {
		fail("migrate IAM: %v", err)
	}
	return store.New(pool), pool
}

func openAuthority(ctx context.Context, url string) (*revepoch.PGAuthority, *pgxpool.Pool) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		fail("open authority: %v", err)
	}
	return revepoch.NewPGAuthority(pool), pool
}

func arg(i int) string {
	if len(os.Args) <= i || os.Args[i] == "" {
		fail("missing argument %d", i)
	}
	return os.Args[i]
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		fail("%s is required", k)
	}
	return v
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "d3demo: "+format+"\n", a...)
	os.Exit(1)
}
