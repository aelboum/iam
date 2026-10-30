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
	"github.com/zitadel/oidc/v3/pkg/op"
)

// RP-initiated logout (`end_session`) must require a verified id_token_hint to
// revoke anything. The library only fills EndSessionRequest.UserID from a
// validated hint, so a hint-less call arrives with an empty UserID. Revoking by
// client_id alone would let any unauthenticated caller end every user's session
// for that client, so TerminateSessionFromRequest rejects the hint-less call and
// revokes nothing; with a user it revokes that user's tokens on the client and
// returns the post-logout redirect (audit L-01). Needs IAM_TEST_DATABASE_URL.
func TestTerminateSessionFromRequestRequiresHint(t *testing.T) {
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

	org, err := st.CreateOrg(ctx, "es-"+uuid.NewString(), "es-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID)
	user, err := st.CreateUser(ctx, store.NewUser{OrgID: org.ID, Username: "u-" + uuid.NewString(), Email: uuid.NewString() + "@es.test"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	const clientID = "es-client"
	seedToken := func() (atID, rtID string) {
		atID, rtID = uuid.NewString(), uuid.NewString()
		at := &store.AccessToken{
			ID: atID, ClientID: clientID, Subject: user.ID, Audience: []string{clientID},
			Scopes: []string{}, RefreshTokenID: &rtID, ExpiresAt: time.Now().Add(time.Hour),
		}
		rt := &store.RefreshToken{
			ID: rtID, TokenHash: secret.Hash(secret.Token(32)), ClientID: clientID, Subject: user.ID,
			Audience: []string{clientID}, Scopes: []string{}, AMR: []string{}, AuthTime: time.Now(),
			AccessTokenID: &atID, ExpiresAt: time.Now().Add(24 * time.Hour), FamilyID: uuid.NewString(),
		}
		if err := st.CreateTokens(ctx, at, rt); err != nil {
			t.Fatalf("create tokens: %v", err)
		}
		return atID, rtID
	}
	alive := func(atID, rtID string) bool {
		_, aerr := st.GetAccessToken(ctx, atID)
		_, rerr := st.GetRefreshTokenByID(ctx, rtID)
		return aerr == nil && rerr == nil
	}

	// Hint-less logout: empty UserID must be rejected and revoke nothing.
	at1, rt1 := seedToken()
	if _, err := s.TerminateSessionFromRequest(ctx, &op.EndSessionRequest{ClientID: clientID}); err == nil {
		t.Error("hint-less end_session must be rejected")
	}
	if !alive(at1, rt1) {
		t.Error("hint-less end_session must not revoke any token")
	}

	// Hinted logout: a resolved user revokes that user's tokens on the client and
	// returns the post-logout redirect.
	const redirect = "https://app.es.test/bye"
	if got, err := s.TerminateSessionFromRequest(ctx, &op.EndSessionRequest{
		UserID: user.ID, ClientID: clientID, RedirectURI: redirect,
	}); err != nil {
		t.Fatalf("hinted end_session: %v", err)
	} else if got != redirect {
		t.Errorf("redirect = %q, want %q", got, redirect)
	}
	if alive(at1, rt1) {
		t.Error("hinted end_session must revoke the user's tokens on the client")
	}
}
