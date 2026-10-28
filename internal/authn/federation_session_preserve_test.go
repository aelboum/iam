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

// TestFederatedLoginPreservesExistingSessions pins the invariant that a
// successful federated (SSO) login is additive: RedeemFederatedLogin creates a
// new session for the user but must NOT revoke the user's existing access
// tokens, refresh tokens or other sessions. Logging in through an IdP is not a
// credential change, so, unlike a password reset or an admin lock, it carries
// no revocation. The test seeds the IdP and a completed login intent directly
// through the store (no OIDC/HTTP mocking), then redeems it and checks the
// pre-existing credentials survive. Needs IAM_TEST_DATABASE_URL.
func TestFederatedLoginPreservesExistingSessions(t *testing.T) {
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
	svc := NewService(st, secret.NewBox([32]byte{29}), Config{
		Limits:          ratelimit.Memory,
		SessionLifetime: time.Hour,
		MaxFailedLogins: 5,
		HashWaitTimeout: time.Second,
		OrgLoginLimit:   1000,
	})

	org, err := st.CreateOrg(ctx, "fed-"+uuid.NewString(), "fed-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID) })

	user, err := st.CreateUser(ctx, store.NewUser{
		OrgID: org.ID, Username: "fed-user", Email: "fed-user@fed.test",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	idp, err := st.CreateIDP(ctx, store.IDP{
		OrgID: org.ID, Name: "idp", ProviderType: "oidc", Issuer: "https://idp.example.test",
		ClientID: "idp-client", ClientSecretEnc: []byte{}, Scopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("create idp: %v", err)
	}

	// A pre-existing access/refresh token and a pre-existing session for the user.
	atID, rtID := uuid.NewString(), uuid.NewString()
	at := &store.AccessToken{
		ID: atID, ClientID: "app-client", Subject: user.ID, Audience: []string{"app-client"},
		Scopes: []string{}, RefreshTokenID: &rtID, ExpiresAt: time.Now().Add(time.Hour),
	}
	rt := &store.RefreshToken{
		ID: rtID, TokenHash: uuid.NewString(), ClientID: "app-client", Subject: user.ID,
		Audience: []string{"app-client"}, Scopes: []string{}, AMR: []string{}, AuthTime: time.Now(),
		AccessTokenID: &atID, ExpiresAt: time.Now().Add(24 * time.Hour), FamilyID: uuid.NewString(),
	}
	if err := st.CreateTokens(ctx, at, rt); err != nil {
		t.Fatalf("create tokens: %v", err)
	}
	existing, err := svc.CreateSession(ctx, org.ID, "fed-user")
	if err != nil {
		t.Fatalf("create existing session: %v", err)
	}

	// Seed a completed login intent: CreateIntent then CompleteIntent records
	// the authenticated user and the one-time redeem code. The browser binding
	// supplied at redemption must match the stored binding hash.
	const code = "redeem-code-abc"
	const binding = "browser-binding-xyz"
	intent := &store.Intent{
		ID: uuid.NewString(), IDPID: idp.ID, StateHash: "state-" + uuid.NewString(),
		Nonce: "nonce-" + uuid.NewString(), CodeVerifierEnc: []byte{}, ReturnURL: "https://app.test/after",
		BindingHash: secret.Hash(binding), ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := st.CreateIntent(ctx, intent); err != nil {
		t.Fatalf("create intent: %v", err)
	}
	if err := st.CompleteIntent(ctx, intent.ID, user.ID, secret.Hash(code)); err != nil {
		t.Fatalf("complete intent: %v", err)
	}

	// Redeem the federated login.
	ss, err := svc.RedeemFederatedLogin(ctx, Client{OrgID: org.ID}, intent.ID, code, binding)
	if err != nil {
		t.Fatalf("redeem federated login: %v", err)
	}
	if ss == nil || ss.ID == "" || ss.ID == existing.ID {
		t.Fatalf("redeem should return a new session, got %+v", ss)
	}

	// The pre-existing access and refresh tokens must still be valid.
	if _, err := st.GetAccessToken(ctx, atID); err != nil {
		t.Errorf("federated login must not revoke an existing access token: err=%v", err)
	}
	if _, err := st.GetRefreshTokenByID(ctx, rtID); err != nil {
		t.Errorf("federated login must not revoke an existing refresh token: err=%v", err)
	}
	// The pre-existing session must still be usable.
	if _, err := svc.GetSession(ctx, Client{OrgID: org.ID}, existing.ID, existing.Token); err != nil {
		t.Errorf("federated login must not end an existing session: err=%v", err)
	}
	// Sanity: the one-time intent is used up (a replay fails).
	if _, err := svc.RedeemFederatedLogin(ctx, Client{OrgID: org.ID}, intent.ID, code, binding); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("intent replay: err=%v, want ErrInvalidCredentials", err)
	}
}
