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

// TestRevokeTokenScopesToClientAndFamily pins the RFC 7009 revocation contract
// in Storage.RevokeToken, exercised directly through the store (no HTTP/op
// round trip):
//
//   - a refresh token is revoked family-wide (RevokeRefreshFamily); an access
//     token is revoked on its own (DeleteAccessToken) and leaves its refresh
//     family alive — the two token types are handled differently on purpose;
//   - the authenticated client must match the token's client_id, for both token
//     types, or the call fails with invalid_client and revokes nothing;
//   - tokens of other clients, other users and other families (incl. another
//     tenant) are never touched;
//   - an unknown or already-revoked token returns no error and revokes nothing
//     (revocation is idempotent).
//
// Needs IAM_TEST_DATABASE_URL.
func TestRevokeTokenScopesToClientAndFamily(t *testing.T) {
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
	s := NewStorage(st, nil, secret.NewBox([32]byte{29}), TokenConfig{
		KeyRotation: time.Hour, AccessToken: 5 * time.Minute,
		RefreshIdle: time.Hour, SessionMaxAge: 24 * time.Hour,
	})

	mkUser := func(prefix string) *store.User {
		o, err := st.CreateOrg(ctx, prefix+"-"+uuid.NewString(), prefix+"-"+uuid.NewString())
		if err != nil {
			t.Fatalf("create org: %v", err)
		}
		t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, o.ID) })
		u, err := st.CreateUser(ctx, store.NewUser{OrgID: o.ID, Username: "u-" + uuid.NewString(), Email: uuid.NewString() + "@rv.test"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		return u
	}

	// mkPair seeds an access+refresh pair for a subject on a client in a family
	// and returns the access id, refresh id and the raw refresh value.
	mkPair := func(clientID, subject, family string) (atID, rtID, raw string) {
		atID, rtID, raw = uuid.NewString(), uuid.NewString(), secret.Token(32)
		at := &store.AccessToken{
			ID: atID, ClientID: clientID, Subject: subject, Audience: []string{clientID},
			Scopes: []string{}, RefreshTokenID: &rtID, ExpiresAt: time.Now().Add(time.Hour),
		}
		rt := &store.RefreshToken{
			ID: rtID, TokenHash: secret.Hash(raw), ClientID: clientID, Subject: subject,
			Audience: []string{clientID}, Scopes: []string{}, AMR: []string{}, AuthTime: time.Now(),
			AccessTokenID: &atID, ExpiresAt: time.Now().Add(24 * time.Hour), FamilyID: family,
		}
		if err := st.CreateTokens(ctx, at, rt); err != nil {
			t.Fatalf("create tokens: %v", err)
		}
		return atID, rtID, raw
	}
	accessAliveID := func(id string) bool {
		_, err := st.GetAccessToken(ctx, id)
		return err == nil
	}
	refreshAliveID := func(id string) bool {
		_, err := st.GetRefreshTokenByID(ctx, id)
		return err == nil
	}

	userA := mkUser("a")
	userB := mkUser("b")
	userC := mkUser("c") // a different tenant

	// --- 1 + 5: revoking a refresh token with the right client revokes the
	// whole family and only that family. Family F1 holds two refresh tokens.
	f1 := uuid.NewString()
	at1, rt1, _ := mkPair("client-1", userA.ID, f1)
	at1b, rt1b, _ := mkPair("client-1", userA.ID, f1)

	// Bystanders that must survive the family revocation.
	at2, rt2, _ := mkPair("client-1", userA.ID, uuid.NewString()) // same user+client, other family
	atB, rtB, _ := mkPair("client-1", userB.ID, uuid.NewString()) // other user
	atC, rtC, _ := mkPair("client-2", userC.ID, uuid.NewString()) // other client + other tenant

	if e := s.RevokeToken(ctx, rt1, userA.ID, "client-1"); e != nil {
		t.Fatalf("revoke refresh with right client: %v", e)
	}
	if accessAliveID(at1) || refreshAliveID(rt1) || accessAliveID(at1b) || refreshAliveID(rt1b) {
		t.Error("refresh revoke must remove the whole family (both pairs)")
	}
	if !(accessAliveID(at2) && refreshAliveID(rt2)) {
		t.Error("another family of the same user+client must survive")
	}
	if !(accessAliveID(atB) && refreshAliveID(rtB)) {
		t.Error("another user's tokens must survive")
	}
	if !(accessAliveID(atC) && refreshAliveID(rtC)) {
		t.Error("another client's / another tenant's tokens must survive")
	}

	// --- 2: client_id mismatch on a refresh token is rejected and revokes
	// nothing. client-2 tries to revoke userA's client-1 family F2 (at2/rt2).
	if e := s.RevokeToken(ctx, rt2, userA.ID, "client-2"); e == nil {
		t.Error("a client must not revoke a refresh token issued to another client")
	}
	if !(accessAliveID(at2) && refreshAliveID(rt2)) {
		t.Error("a rejected mismatched refresh revoke must not revoke anything")
	}

	// --- access vs refresh: revoking an access token removes only that access
	// token and leaves its refresh family alive.
	fAcc := uuid.NewString()
	atX, rtX, _ := mkPair("client-1", userA.ID, fAcc)
	if e := s.RevokeToken(ctx, atX, userA.ID, "client-1"); e != nil {
		t.Fatalf("revoke access with right client: %v", e)
	}
	if accessAliveID(atX) {
		t.Error("access-token revoke must delete that access token")
	}
	if !refreshAliveID(rtX) {
		t.Error("access-token revoke must leave the refresh family alive (narrow by contract)")
	}

	// --- 2 (access): client_id mismatch on an access token is rejected.
	fAccM := uuid.NewString()
	atM, _, _ := mkPair("client-1", userA.ID, fAccM)
	if e := s.RevokeToken(ctx, atM, userA.ID, "client-2"); e == nil {
		t.Error("a client must not revoke an access token issued to another client")
	}
	if !accessAliveID(atM) {
		t.Error("a rejected mismatched access revoke must not revoke anything")
	}

	// --- 4: unknown and already-revoked tokens are idempotent no-ops.
	if e := s.RevokeToken(ctx, uuid.NewString(), userA.ID, "client-1"); e != nil {
		t.Errorf("unknown token id with userID set must be a no-op, got %v", e)
	}
	if e := s.RevokeToken(ctx, secret.Token(32), "", "client-1"); e != nil {
		t.Errorf("unknown raw token must be a no-op, got %v", e)
	}
	// rt1 was already revoked above; revoking it again must stay a no-op.
	if e := s.RevokeToken(ctx, rt1, userA.ID, "client-1"); e != nil {
		t.Errorf("already-revoked token must be a no-op, got %v", e)
	}
	// The bystanders are still intact after all the no-op calls.
	if !(accessAliveID(atB) && refreshAliveID(rtB) && accessAliveID(atC) && refreshAliveID(rtC)) {
		t.Error("idempotent no-op revokes must not touch other tokens")
	}
}
