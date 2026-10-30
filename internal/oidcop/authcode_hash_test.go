package oidcop

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Authorization codes must be stored as their SHA-256, never in the clear, so a
// leaked backup or a SQL read of auth_requests cannot be replayed to redeem a
// token. SaveAuthCode hashes before storing and AuthRequestByCode hashes before
// looking up, so the raw code round-trips while only its hash ever touches the
// column (audit N17). Needs IAM_TEST_DATABASE_URL.
func TestAuthCodeStoredHashedAtRest(t *testing.T) {
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
	st := store.New(pool)
	s := NewStorage(st, nil, secret.NewBox([32]byte{53}), TokenConfig{
		KeyRotation: time.Hour, AccessToken: 5 * time.Minute,
		RefreshIdle: time.Hour, SessionMaxAge: 24 * time.Hour,
	})

	id := uuid.NewString()
	if _, err := st.CreateAuthRequest(ctx, &store.AuthRequest{
		ID: id, ClientID: "ac-client", RedirectURI: "https://app.test/cb",
		ResponseType: "code", Scopes: []string{"openid"}, Prompt: []string{},
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create auth request: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM auth_requests WHERE id = $1`, id)
	if err := st.CompleteAuthRequest(ctx, id, uuid.NewString(), time.Now(), []string{"pwd"}); err != nil {
		t.Fatalf("complete auth request: %v", err)
	}

	const rawCode = "the-authorization-code-value"
	if err := s.SaveAuthCode(ctx, id, rawCode); err != nil {
		t.Fatalf("save auth code: %v", err)
	}

	// The column must hold the hash, not the code.
	var stored string
	if err := pool.QueryRow(ctx, `SELECT code FROM auth_requests WHERE id = $1`, id).Scan(&stored); err != nil {
		t.Fatalf("read stored code: %v", err)
	}
	if stored == rawCode {
		t.Fatal("authorization code is stored in the clear")
	}
	if stored != secret.Hash(rawCode) {
		t.Errorf("stored code = %q, want SHA-256 of the raw code", stored)
	}

	// The raw code resolves the request.
	ar, err := s.AuthRequestByCode(ctx, rawCode)
	if err != nil {
		t.Fatalf("lookup by raw code: %v", err)
	}
	if ar.GetID() != id {
		t.Errorf("resolved auth request id = %q, want %q", ar.GetID(), id)
	}

	// Presenting the stored hash as if it were the code must NOT resolve: it is
	// re-hashed before the lookup, so only the original code works.
	if _, err := s.AuthRequestByCode(ctx, stored); err == nil {
		t.Error("the stored hash must not be usable as the code")
	}
}
