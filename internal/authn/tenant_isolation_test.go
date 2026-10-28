package authn

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/aelboum/iam/internal/ratelimit"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSessionScopedToOwningOrg guards tenant isolation on the session path: a
// caller that presents another organization's org id must not be able to read
// or advance a session it does not own, even with the correct session id and
// token. loadSession rejects a mismatched non-empty Client.OrgID, so every
// session operation (GetSession, CheckPassword, ...) must fail with
// ErrSessionInvalid for the wrong org while succeeding for the owning org.
// Needs IAM_TEST_DATABASE_URL.
func TestSessionScopedToOwningOrg(t *testing.T) {
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
	svc := NewService(st, secret.NewBox([32]byte{17}), Config{
		Limits:          ratelimit.Memory,
		SessionLifetime: time.Hour,
		MaxFailedLogins: 5,
		HashWaitTimeout: time.Second,
		OrgLoginLimit:   1000,
	})

	mkOrg := func(prefix string) *store.Org {
		o, err := st.CreateOrg(ctx, prefix+"-"+uuid.NewString(), prefix+"-"+uuid.NewString())
		if err != nil {
			t.Fatalf("create org %s: %v", prefix, err)
		}
		t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, o.ID) })
		return o
	}
	orgA := mkOrg("tenant-a")
	orgB := mkOrg("tenant-b")

	const pw = "correct-horse-17"
	hash, err := svc.HashPassword(pw, "auser", "auser@tenant.test")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := st.CreateUser(ctx, store.NewUser{
		OrgID: orgA.ID, Username: "auser", Email: "auser@tenant.test", PasswordHash: &hash,
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	ss, err := svc.CreateSession(ctx, orgA.ID, "auser")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// The correct session id + token but org B's id must be rejected everywhere.
	wrongOrg := Client{OrgID: orgB.ID}
	if _, err := svc.GetSession(ctx, wrongOrg, ss.ID, ss.Token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("GetSession with another org: err=%v, want ErrSessionInvalid", err)
	}
	if _, err := svc.CheckPassword(ctx, wrongOrg, ss.ID, ss.Token, pw); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("CheckPassword with another org: err=%v, want ErrSessionInvalid", err)
	}

	// The owning org (and an internal empty-org caller) must succeed.
	if _, err := svc.GetSession(ctx, Client{OrgID: orgA.ID}, ss.ID, ss.Token); err != nil {
		t.Fatalf("GetSession with the owning org: err=%v, want nil", err)
	}
	if _, err := svc.GetSession(ctx, Client{}, ss.ID, ss.Token); err != nil {
		t.Fatalf("GetSession with an internal empty-org caller: err=%v, want nil", err)
	}

	// The cross-org rejection must not have advanced the owning session: a
	// correct password for org A still succeeds afterwards.
	if _, err := svc.CheckPassword(ctx, Client{OrgID: orgA.ID}, ss.ID, ss.Token, pw); err != nil {
		t.Fatalf("CheckPassword with the owning org after a cross-org probe: err=%v, want nil", err)
	}
}

// TestPasswordResetRevokesResettingUsersCredentials guards that a successful
// self-service password reset (ConfirmPasswordReset -> CompletePasswordReset)
// atomically revokes the resetting user's access tokens, refresh tokens and
// sessions, while leaving another user's credentials untouched. A reset that
// fails on a bad token must revoke nothing and must not report success.
// The revocation is part of CompletePasswordReset's transaction, so a password
// change and its credential revocation cannot be observed apart. Needs
// IAM_TEST_DATABASE_URL.
func TestPasswordResetRevokesResettingUsersCredentials(t *testing.T) {
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
	svc := NewService(st, secret.NewBox([32]byte{19}), Config{
		Limits:          ratelimit.Memory,
		SessionLifetime: time.Hour,
		MaxFailedLogins: 5,
		HashWaitTimeout: time.Second,
		OrgLoginLimit:   1000,
	})

	org, err := st.CreateOrg(ctx, "reset-"+uuid.NewString(), "reset-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID) })

	mkUserWithCreds := func(name string) (user *store.User, atID, rtID, sessID, sessTok string) {
		pw := "Str0ng-Passphrase-Zx9" // must not contain the username or email
		hash, err := svc.HashPassword(pw, name, name+"@reset.test")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		user, err = st.CreateUser(ctx, store.NewUser{
			OrgID: org.ID, Username: name, Email: name + "@reset.test", PasswordHash: &hash,
		})
		if err != nil {
			t.Fatalf("create user %s: %v", name, err)
		}
		atID, rtID = uuid.NewString(), uuid.NewString()
		at := &store.AccessToken{
			ID: atID, ClientID: "c-" + name, Subject: user.ID, Audience: []string{"c-" + name},
			Scopes: []string{}, RefreshTokenID: &rtID, ExpiresAt: time.Now().Add(time.Hour),
		}
		rt := &store.RefreshToken{
			ID: rtID, TokenHash: uuid.NewString(), ClientID: "c-" + name, Subject: user.ID,
			Audience: []string{"c-" + name}, Scopes: []string{}, AMR: []string{}, AuthTime: time.Now(),
			AccessTokenID: &atID, ExpiresAt: time.Now().Add(24 * time.Hour), FamilyID: uuid.NewString(),
		}
		if err := st.CreateTokens(ctx, at, rt); err != nil {
			t.Fatalf("create tokens for %s: %v", name, err)
		}
		ss, err := svc.CreateSession(ctx, org.ID, name)
		if err != nil {
			t.Fatalf("create session for %s: %v", name, err)
		}
		return user, atID, rtID, ss.ID, ss.Token
	}

	tokensGone := func(atID, rtID string) bool {
		_, aerr := st.GetAccessToken(ctx, atID)
		_, rerr := st.GetRefreshTokenByID(ctx, rtID)
		return errors.Is(aerr, store.ErrNotFound) && errors.Is(rerr, store.ErrNotFound)
	}
	sessionGone := func(sessID, tok string) bool {
		_, err := svc.GetSession(ctx, Client{OrgID: org.ID}, sessID, tok)
		return errors.Is(err, ErrSessionInvalid)
	}

	victim, vAT, vRT, vSess, vTok := mkUserWithCreds("victim")
	_, oAT, oRT, oSess, oTok := mkUserWithCreds("other")

	// Issue a reset token for the victim and confirm the reset.
	resetTok := secret.Token(32)
	if err := st.CreatePasswordReset(ctx, victim.ID, secret.Hash(resetTok), time.Now().Add(15*time.Minute)); err != nil {
		t.Fatalf("create password reset: %v", err)
	}
	if err := svc.ConfirmPasswordReset(ctx, Client{OrgID: org.ID}, resetTok, "new-correct-horse-9"); err != nil {
		t.Fatalf("confirm password reset: %v", err)
	}

	// The victim's tokens and session are gone.
	if !tokensGone(vAT, vRT) {
		t.Error("password reset must revoke the resetting user's access and refresh tokens")
	}
	if !sessionGone(vSess, vTok) {
		t.Error("password reset must end the resetting user's sessions")
	}
	// The other user is untouched.
	if tokensGone(oAT, oRT) {
		t.Error("password reset must not revoke another user's tokens")
	}
	if sessionGone(oSess, oTok) {
		t.Error("password reset must not end another user's sessions")
	}

	// Error path: a bad reset token must fail and revoke nothing. Re-issue the
	// victim's credentials first, then present a token that was never issued.
	_, vAT2, vRT2, vSess2, vTok2 := mkUserWithCreds("victim2")
	if err := svc.ConfirmPasswordReset(ctx, Client{OrgID: org.ID}, secret.Token(32), "another-pw-1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("confirm with an unknown token: err=%v, want ErrInvalidCredentials", err)
	}
	if tokensGone(vAT2, vRT2) || sessionGone(vSess2, vTok2) {
		t.Error("a failed password reset must not revoke any credentials")
	}
}
