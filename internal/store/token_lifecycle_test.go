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

// These tests pin the scoping of the OIDC token-lifecycle store methods that
// logout, refresh rotation and refresh-reuse detection depend on:
// TerminateTokens (one user at one client), RevokeRefreshFamily (one login
// family), and RotateRefreshToken (consume the presented token, issue the next
// in the same family). Needs IAM_TEST_DATABASE_URL.

func lifecycleStore(t *testing.T) (*Store, *pgxpool.Pool) {
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
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return New(pool), pool
}

func lifecycleUser(t *testing.T, st *Store, pool *pgxpool.Pool) *User {
	t.Helper()
	ctx := context.Background()
	o, err := st.CreateOrg(ctx, "tl-"+uuid.NewString(), "tl-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, o.ID) })
	u, err := st.CreateUser(ctx, NewUser{OrgID: o.ID, Username: "u-" + uuid.NewString(), Email: uuid.NewString() + "@tl.test"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

// lifecycleTokens inserts an access+refresh pair for a subject on a client in a
// given family (a new random family when familyID is "") and returns the access
// id, refresh id and refresh hash.
func lifecycleTokens(t *testing.T, st *Store, clientID, subject, familyID string) (atID, rtID, rtHash string) {
	t.Helper()
	if familyID == "" {
		familyID = uuid.NewString()
	}
	atID, rtID, rtHash = uuid.NewString(), uuid.NewString(), uuid.NewString()
	at := &AccessToken{
		ID: atID, ClientID: clientID, Subject: subject, Audience: []string{clientID},
		Scopes: []string{}, RefreshTokenID: &rtID, ExpiresAt: time.Now().Add(time.Hour),
	}
	rt := &RefreshToken{
		ID: rtID, TokenHash: rtHash, ClientID: clientID, Subject: subject,
		Audience: []string{clientID}, Scopes: []string{}, AMR: []string{}, AuthTime: time.Now(),
		AccessTokenID: &atID, ExpiresAt: time.Now().Add(24 * time.Hour), FamilyID: familyID,
	}
	if err := st.CreateTokens(context.Background(), at, rt); err != nil {
		t.Fatalf("create tokens: %v", err)
	}
	return atID, rtID, rtHash
}

func accessAlive(t *testing.T, st *Store, id string) bool {
	t.Helper()
	_, err := st.GetAccessToken(context.Background(), id)
	if err == nil {
		return true
	}
	if err == ErrNotFound {
		return false
	}
	t.Fatalf("GetAccessToken(%s): %v", id, err)
	return false
}

func refreshAlive(t *testing.T, st *Store, id string) bool {
	t.Helper()
	_, err := st.GetRefreshTokenByID(context.Background(), id)
	if err == nil {
		return true
	}
	if err == ErrNotFound {
		return false
	}
	t.Fatalf("GetRefreshTokenByID(%s): %v", id, err)
	return false
}

// TestTerminateTokensScopedToUserAndClient: OIDC end-session revokes one user's
// tokens at one client only; the same user's tokens at another client and
// another user's tokens at the same client survive.
func TestTerminateTokensScopedToUserAndClient(t *testing.T) {
	st, pool := lifecycleStore(t)
	userU := lifecycleUser(t, st, pool)
	userV := lifecycleUser(t, st, pool)

	uC1at, uC1rt, _ := lifecycleTokens(t, st, "client-1", userU.ID, "")
	uC2at, uC2rt, _ := lifecycleTokens(t, st, "client-2", userU.ID, "")
	vC1at, vC1rt, _ := lifecycleTokens(t, st, "client-1", userV.ID, "")

	if err := st.TerminateTokens(context.Background(), userU.ID, "client-1"); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if accessAlive(t, st, uC1at) || refreshAlive(t, st, uC1rt) {
		t.Error("terminate must revoke the user's tokens at the target client")
	}
	if !accessAlive(t, st, uC2at) || !refreshAlive(t, st, uC2rt) {
		t.Error("terminate must not touch the same user's tokens at another client")
	}
	if !accessAlive(t, st, vC1at) || !refreshAlive(t, st, vC1rt) {
		t.Error("terminate must not touch another user's tokens at the same client")
	}
}

// TestRevokeRefreshFamilyScopedToFamily: refresh-reuse detection revokes exactly
// the compromised login family (its refresh and access tokens); another family
// of the same user and a family of another user are untouched.
func TestRevokeRefreshFamilyScopedToFamily(t *testing.T) {
	st, pool := lifecycleStore(t)
	userU := lifecycleUser(t, st, pool)
	userV := lifecycleUser(t, st, pool)

	famA := uuid.NewString()
	aAT, aRT, _ := lifecycleTokens(t, st, "client-1", userU.ID, famA)
	// A second access token in the same family (e.g. after a rotation).
	a2AT, a2RT, _ := lifecycleTokens(t, st, "client-1", userU.ID, famA)
	bAT, bRT, _ := lifecycleTokens(t, st, "client-1", userU.ID, "") // other family, same user
	vAT, vRT, _ := lifecycleTokens(t, st, "client-1", userV.ID, "") // other user

	if err := st.RevokeRefreshFamily(context.Background(), famA); err != nil {
		t.Fatalf("revoke family: %v", err)
	}
	if refreshAlive(t, st, aRT) || refreshAlive(t, st, a2RT) || accessAlive(t, st, aAT) || accessAlive(t, st, a2AT) {
		t.Error("revoke family must remove every refresh and access token of the family")
	}
	if !refreshAlive(t, st, bRT) || !accessAlive(t, st, bAT) {
		t.Error("revoke family must not touch another family of the same user")
	}
	if !refreshAlive(t, st, vRT) || !accessAlive(t, st, vAT) {
		t.Error("revoke family must not touch another user's family")
	}
}

// TestRotateRefreshTokenInvalidatesOldAndRejectsReplay: rotation consumes the
// presented refresh token (its old access token is deleted) and issues a new
// pair in the same family; presenting the already-used token again is rejected
// with ErrNotFound, which the OIDC layer maps to invalid_grant.
func TestRotateRefreshTokenInvalidatesOldAndRejectsReplay(t *testing.T) {
	st, pool := lifecycleStore(t)
	ctx := context.Background()
	userU := lifecycleUser(t, st, pool)

	famA := uuid.NewString()
	oldAT, _, oldHash := lifecycleTokens(t, st, "client-1", userU.ID, famA)

	newATID, newRTID, newHash := uuid.NewString(), uuid.NewString(), uuid.NewString()
	newAT := &AccessToken{
		ID: newATID, ClientID: "client-1", Subject: userU.ID, Audience: []string{"client-1"},
		Scopes: []string{}, RefreshTokenID: &newRTID, ExpiresAt: time.Now().Add(time.Hour),
	}
	newRT := &RefreshToken{
		ID: newRTID, TokenHash: newHash, ClientID: "client-1", Subject: userU.ID,
		Audience: []string{"client-1"}, Scopes: []string{}, AMR: []string{}, AuthTime: time.Now(),
		AccessTokenID: &newATID, ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := st.RotateRefreshToken(ctx, oldHash, newAT, newRT); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// The old access token is gone; the new pair exists and shares the family.
	if accessAlive(t, st, oldAT) {
		t.Error("rotation must delete the old access token")
	}
	if !accessAlive(t, st, newATID) || !refreshAlive(t, st, newRTID) {
		t.Error("rotation must store the new access and refresh tokens")
	}
	stored, err := st.GetRefreshTokenByHash(ctx, newHash)
	if err != nil {
		t.Fatalf("get new refresh: %v", err)
	}
	if stored.FamilyID != famA {
		t.Errorf("new refresh family = %s, want the rotated family %s", stored.FamilyID, famA)
	}
	// The old refresh token is retained but marked used (so reuse can be detected).
	old, err := st.GetRefreshTokenByHash(ctx, oldHash)
	if err != nil {
		t.Fatalf("get old refresh: %v", err)
	}
	if old.UsedAt == nil {
		t.Error("the rotated-out refresh token must be marked used, not deleted")
	}

	// Replay: rotating again with the already-used token is rejected.
	replayAT := &AccessToken{
		ID: uuid.NewString(), ClientID: "client-1", Subject: userU.ID, Audience: []string{"client-1"},
		Scopes: []string{}, ExpiresAt: time.Now().Add(time.Hour),
	}
	replayRT := &RefreshToken{
		ID: uuid.NewString(), TokenHash: uuid.NewString(), ClientID: "client-1", Subject: userU.ID,
		Audience: []string{"client-1"}, Scopes: []string{}, AMR: []string{}, AuthTime: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := st.RotateRefreshToken(ctx, oldHash, replayAT, replayRT); err != ErrNotFound {
		t.Fatalf("replay rotation: err=%v, want ErrNotFound", err)
	}
}
