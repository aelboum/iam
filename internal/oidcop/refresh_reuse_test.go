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

// TestRefreshReuseRevokesOnlyTheReusedFamily pins the OIDC refresh-reuse
// contract in TokenRequestByRefreshToken: presenting a refresh token that was
// already rotated out (used) is treated as theft and revokes the whole login
// family, but must not touch an unrelated family. An unknown token is rejected
// and revokes nothing. The tokens are seeded directly through the store, so no
// OIDC/HTTP round trip is needed. Needs IAM_TEST_DATABASE_URL.
func TestRefreshReuseRevokesOnlyTheReusedFamily(t *testing.T) {
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
	s := NewStorage(st, nil, secret.NewBox([32]byte{31}), TokenConfig{
		KeyRotation: time.Hour, AccessToken: 5 * time.Minute,
		RefreshIdle: time.Hour, SessionMaxAge: 24 * time.Hour,
	})

	org, err := st.CreateOrg(ctx, "rr-"+uuid.NewString(), "rr-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID) })
	user, err := st.CreateUser(ctx, store.NewUser{OrgID: org.ID, Username: "u-" + uuid.NewString(), Email: uuid.NewString() + "@rr.test"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	alive := func(what, atID, rtID string) bool {
		_, aerr := st.GetAccessToken(ctx, atID)
		_, rerr := st.GetRefreshTokenByID(ctx, rtID)
		if (aerr == nil) != (rerr == nil) {
			t.Fatalf("%s: inconsistent token state access=%v refresh=%v", what, aerr, rerr)
		}
		return aerr == nil
	}
	mkPair := func(rawRefresh, family string) (atID, rtID string) {
		atID, rtID = uuid.NewString(), uuid.NewString()
		at := &store.AccessToken{
			ID: atID, ClientID: "client-1", Subject: user.ID, Audience: []string{"client-1"},
			Scopes: []string{}, RefreshTokenID: &rtID, ExpiresAt: time.Now().Add(time.Hour),
		}
		rt := &store.RefreshToken{
			ID: rtID, TokenHash: secret.Hash(rawRefresh), ClientID: "client-1", Subject: user.ID,
			Audience: []string{"client-1"}, Scopes: []string{}, AMR: []string{}, AuthTime: time.Now(),
			AccessTokenID: &atID, ExpiresAt: time.Now().Add(24 * time.Hour), FamilyID: family,
		}
		if err := st.CreateTokens(ctx, at, rt); err != nil {
			t.Fatalf("create tokens: %v", err)
		}
		return atID, rtID
	}

	// Family 1: an initial pair, then rotate it so the first token is "used".
	famRaw0 := secret.Token(32)
	fam1 := uuid.NewString()
	mkPair(famRaw0, fam1)
	famRaw1 := secret.Token(32)
	rotAT, rotRT := uuid.NewString(), uuid.NewString()
	nAT := &store.AccessToken{
		ID: rotAT, ClientID: "client-1", Subject: user.ID, Audience: []string{"client-1"},
		Scopes: []string{}, RefreshTokenID: &rotRT, ExpiresAt: time.Now().Add(time.Hour),
	}
	nRT := &store.RefreshToken{
		ID: rotRT, TokenHash: secret.Hash(famRaw1), ClientID: "client-1", Subject: user.ID,
		Audience: []string{"client-1"}, Scopes: []string{}, AMR: []string{}, AuthTime: time.Now(),
		AccessTokenID: &rotAT, ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := st.RotateRefreshToken(ctx, secret.Hash(famRaw0), nAT, nRT); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// An unrelated family that must survive the reuse revocation.
	otherRaw := secret.Token(32)
	otherAT, otherRT := mkPair(otherRaw, uuid.NewString())

	// Reuse: present the rotated-out (used) first refresh token again.
	if _, err := s.TokenRequestByRefreshToken(ctx, famRaw0); err == nil {
		t.Fatal("reuse of a rotated-out refresh token must be rejected")
	}
	if alive("reused family current token", rotAT, rotRT) {
		t.Error("reuse must revoke the whole family, including the current rotated token")
	}
	if !alive("unrelated family", otherAT, otherRT) {
		t.Error("reuse must not revoke an unrelated family")
	}

	// An unknown refresh token is rejected and revokes nothing.
	if _, err := s.TokenRequestByRefreshToken(ctx, secret.Token(32)); err == nil {
		t.Fatal("an unknown refresh token must be rejected")
	}
	if !alive("unrelated family after unknown token", otherAT, otherRT) {
		t.Error("an unknown refresh token must not revoke anything")
	}
}
