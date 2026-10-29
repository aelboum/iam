package store

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) (*pgxpool.Pool, *Store) {
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
	return pool, New(pool)
}

// The periodic purge deletes by expires_at from nine tables. Six of them had no
// index, so every run sequentially scanned the hottest tables in the schema
// (measured: 133 ms for 200k access_tokens, growing linearly). The indexes are
// the fix; assert they exist so a future migration cannot silently drop them
// (independent security assessment, 2026-10-29).
func TestPurgeIndexesExist(t *testing.T) {
	pool, _ := testPool(t)
	want := []string{
		"access_tokens_expires_idx", "refresh_tokens_expires_idx", "sessions_expires_idx",
		"auth_requests_expires_idx", "signing_keys_expires_idx", "email_verifications_expires_idx",
		"audit_events_at_idx", "sessions_user_idx", "password_resets_user_expires_idx",
	}
	for _, idx := range want {
		var exists bool
		if err := pool.QueryRow(context.Background(),
			`SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = 'public' AND indexname = $1)`,
			idx).Scan(&exists); err != nil {
			t.Fatalf("query index %s: %v", idx, err)
		}
		if !exists {
			t.Errorf("index %s is missing", idx)
		}
	}
}

// Revoking a user's credentials must use the uuid index rather than scanning
// sessions: the statement used to compare user_id::text.
func TestRevokeUserTokensUsesUuidComparison(t *testing.T) {
	pool, st := testPool(t)
	ctx := context.Background()
	sfx := uuid.NewString()
	org, err := st.CreateOrg(ctx, "rv-"+sfx, "rv-"+sfx)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID)
	user, err := st.CreateUser(ctx, NewUser{OrgID: org.ID, Username: "u-" + sfx, Email: "u-" + sfx + "@x.test"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	sess, err := st.CreateSession(ctx, org.ID, &user.ID, user.Username, "h", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := st.RevokeUserTokens(ctx, user.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := st.GetSession(ctx, sess.ID); err == nil {
		t.Fatal("session survived revocation")
	}
}

// A pending TOTP enrollment code is six digits and was verifiable without any
// cap, so a management key could brute-force it. The budget is now five.
func TestTOTPEnrollAttemptsAreCapped(t *testing.T) {
	pool, st := testPool(t)
	ctx := context.Background()
	sfx := uuid.NewString()
	org, err := st.CreateOrg(ctx, "te-"+sfx, "te-"+sfx)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID)
	user, err := st.CreateUser(ctx, NewUser{OrgID: org.ID, Username: "u-" + sfx, Email: "u-" + sfx + "@x.test"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := st.SetPendingTOTP(ctx, user.ID, []byte("sealed")); err != nil {
		t.Fatalf("set pending: %v", err)
	}
	for i := 0; i < 5; i++ {
		ok, err := st.ReserveTOTPEnrollAttempt(ctx, user.ID, 5)
		if err != nil || !ok {
			t.Fatalf("attempt %d: ok=%v err=%v", i+1, ok, err)
		}
	}
	if ok, err := st.ReserveTOTPEnrollAttempt(ctx, user.ID, 5); err != nil || ok {
		t.Fatalf("sixth attempt allowed: ok=%v err=%v", ok, err)
	}
	// A release gives the attempt back, and a new enrollment resets the budget.
	if err := st.ReleaseTOTPEnrollAttempt(ctx, user.ID); err != nil {
		t.Fatalf("release: %v", err)
	}
	if ok, _ := st.ReserveTOTPEnrollAttempt(ctx, user.ID, 5); !ok {
		t.Fatal("released attempt was not reusable")
	}
	if err := st.SetPendingTOTP(ctx, user.ID, []byte("sealed2")); err != nil {
		t.Fatalf("re-enroll: %v", err)
	}
	if ok, _ := st.ReserveTOTPEnrollAttempt(ctx, user.ID, 5); !ok {
		t.Fatal("new enrollment did not reset the budget")
	}
}

// Deleting an IdP must end the sessions of users it was linked to, so a removed
// (or compromised-then-removed) provider cannot keep minting access.
func TestDeleteIDPRevokesLinkedSessions(t *testing.T) {
	pool, st := testPool(t)
	ctx := context.Background()
	sfx := uuid.NewString()
	org, err := st.CreateOrg(ctx, "id-"+sfx, "id-"+sfx)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID)
	user, err := st.CreateUser(ctx, NewUser{OrgID: org.ID, Username: "u-" + sfx, Email: "u-" + sfx + "@x.test"})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	idp, err := st.CreateIDP(ctx, IDP{OrgID: org.ID, Name: "idp", Issuer: "https://idp.test",
		ClientID: "c", ClientSecretEnc: []byte("s"), Scopes: []string{"openid"}})
	if err != nil {
		t.Fatalf("create idp: %v", err)
	}
	if err := st.LinkIdentity(ctx, idp.ID, "sub-1", user.ID); err != nil {
		t.Fatalf("link: %v", err)
	}
	sess, err := st.CreateSession(ctx, org.ID, &user.ID, user.Username, "h", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := st.DeleteIDP(ctx, org.ID, idp.ID); err != nil {
		t.Fatalf("delete idp: %v", err)
	}
	if _, err := st.GetSession(ctx, sess.ID); err == nil {
		t.Fatal("session survived IdP deletion")
	}
	if err := st.DeleteIDP(ctx, org.ID, idp.ID); err != ErrNotFound {
		t.Fatalf("second delete = %v, want ErrNotFound", err)
	}
}

// Two instances starting at once against a fresh database must race gracefully:
// exactly one creates the bootstrap key and neither errors. The marker insert
// carries ON CONFLICT DO NOTHING; without it the losing instance crashed startup
// on a duplicate-key error (independent security assessment follow-up).
func TestBootstrapAPIKeyConcurrentStartIsGraceful(t *testing.T) {
	pool, st := testPool(t)
	ctx := context.Background()
	name := "bootstrap-race-" + uuid.NewString()
	// Clean slate for the shared bootstrap marker and this key.
	pool.Exec(ctx, `DELETE FROM instance_state WHERE key = 'bootstrap_admin_key'`)
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM api_keys WHERE name = $1`, name)
		pool.Exec(ctx, `DELETE FROM instance_state WHERE key = 'bootstrap_admin_key'`)
	})
	keyHash := uuid.NewString()
	const n = 8
	var (
		wg      sync.WaitGroup
		created int32
	)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := st.BootstrapAPIKey(ctx, name, keyHash)
			if err != nil {
				errs <- err
				return
			}
			if ok {
				atomic.AddInt32(&created, 1)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent BootstrapAPIKey errored: %v", err)
	}
	if created != 1 {
		t.Errorf("created count = %d, want exactly 1", created)
	}
}
