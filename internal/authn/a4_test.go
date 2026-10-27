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

// TestOrgLoginBudget proves the A4 per-org password-login budget: it caps a
// single org's login-hash attempts aggregated across distinct accounts, and an
// unrelated org is unaffected (tenant isolation). The gate is checked before any
// lockout counter or hashing, so a shed attempt does not touch MFA/lockout state.
//
// Needs a disposable database (IAM_TEST_DATABASE_URL); creates two orgs and a few
// users and removes them (cascade) at the end.
func TestOrgLoginBudget(t *testing.T) {
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
	svc := NewService(st, secret.NewBox([32]byte{7}), Config{
		Limits:          ratelimit.Memory,
		SessionLifetime: time.Hour,
		MaxFailedLogins: 5,
		HashWaitTimeout: 2 * time.Second,
		OrgLoginLimit:   8, // burst = max(1, 8/4) = 2
	})

	const pw = "correct-horse-7" // no overlap with the usernames/emails below
	mkOrgUsers := func(prefix string, n int) (*store.Org, []string) {
		sfx := uuid.NewString()
		org, err := st.CreateOrg(ctx, prefix+"-"+sfx, prefix+"-"+sfx)
		if err != nil {
			t.Fatalf("create org: %v", err)
		}
		t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID) })
		names := make([]string, n)
		for i := 0; i < n; i++ {
			u := prefix + "user" + string(rune('0'+i))
			h, err := svc.HashPassword(pw, u, u+"@bench.test")
			if err != nil {
				t.Fatalf("hash: %v", err)
			}
			if _, err := st.CreateUser(ctx, store.NewUser{
				OrgID: org.ID, Username: u, Email: u + "@bench.test", PasswordHash: &h,
			}); err != nil {
				t.Fatalf("create user: %v", err)
			}
			names[i] = u
		}
		return org, names
	}
	orgA, aUsers := mkOrgUsers("a", 3)
	orgB, bUsers := mkOrgUsers("b", 1)

	login := func(org *store.Org, user string) error {
		ss, err := svc.CreateSession(ctx, org.ID, user)
		if err != nil {
			return err
		}
		_, err = svc.CheckPassword(ctx, Client{}, ss.ID, ss.Token, pw)
		return err
	}

	// Org A: the burst is 2. Two distinct users log in successfully; the third —
	// a fresh account, so the per-account limiter is NOT the cause — is shed by
	// the per-org budget, proving the budget aggregates across accounts.
	if err := login(orgA, aUsers[0]); err != nil {
		t.Fatalf("org A user0: %v, want success", err)
	}
	if err := login(orgA, aUsers[1]); err != nil {
		t.Fatalf("org A user1: %v, want success", err)
	}
	if err := login(orgA, aUsers[2]); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("org A user2: err=%v, want ErrRateLimited (per-org budget, not per-account)", err)
	}

	// Org B is independent: org A's exhausted budget must not affect it.
	if err := login(orgB, bUsers[0]); err != nil {
		t.Fatalf("org B user0: %v, want success (isolation from org A's budget)", err)
	}
}
