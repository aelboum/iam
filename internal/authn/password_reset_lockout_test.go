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

// TestPasswordResetDoesNotBypassLockout is a regression guard for audit L3 and
// the internal assurance review of 2026-10-29. A password reset performed during
// an active temporary lockout is allowed (account recovery), but it must not let
// the user log in before the lockout expires: ConfirmPasswordReset/
// CompletePasswordReset leave locked_until intact and CheckPassword re-checks
// IsLocked(), so a reset is recovery, not a lockout bypass. The store-level guard
// is in internal/store/password_reset_lockout_test.go.
//
// Needs a disposable database (IAM_TEST_DATABASE_URL); creates one org and user
// and removes them (cascade) at the end.
func TestPasswordResetDoesNotBypassLockout(t *testing.T) {
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
	svc := NewService(st, secret.NewBox([32]byte{23}), Config{
		Limits:          ratelimit.Memory,
		SessionLifetime: time.Hour,
		MaxFailedLogins: 5,
		HashWaitTimeout: time.Second,
		OrgLoginLimit:   1000,
	})

	org, err := st.CreateOrg(ctx, "l3svc-"+uuid.NewString(), "l3svc-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID) })

	const (
		name  = "victim"
		oldPw = "Str0ng-Passphrase-Zx9" // must not contain the username or email
		newPw = "new-correct-horse-Zx9"
		max   = 5
	)
	hash, err := svc.HashPassword(oldPw, name, name+"@l3.test")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{
		OrgID: org.ID, Username: name, Email: name + "@l3.test", PasswordHash: &hash,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Drive the account into a temporary password lockout at the store layer.
	for i := 0; i < max+2; i++ {
		st.ReserveAttempt(ctx, user.ID, store.FactorPassword, max)
		locked, err := st.AttemptFailed(ctx, user.ID, store.FactorPassword, max, time.Hour)
		if err != nil {
			t.Fatalf("attempt failed: %v", err)
		}
		if locked {
			break
		}
	}

	// A reset during the lockout is allowed (recovery): a manual lock would
	// block it, a temporary lockout does not.
	resetTok := secret.Token(32)
	if err := st.CreatePasswordReset(ctx, user.ID, secret.Hash(resetTok), time.Now().Add(15*time.Minute)); err != nil {
		t.Fatalf("create password reset: %v", err)
	}
	if err := svc.ConfirmPasswordReset(ctx, Client{OrgID: org.ID}, resetTok, newPw); err != nil {
		t.Fatalf("reset during a temporary lockout must be allowed: %v", err)
	}

	// But the new password must NOT log in while the lockout is still active:
	// the lockout stays in force (audit L3), so this is recovery, not a bypass.
	ss, err := svc.CreateSession(ctx, org.ID, name)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := svc.CheckPassword(ctx, Client{OrgID: org.ID}, ss.ID, ss.Token, newPw); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("login with the new password during an active lockout: err=%v, want ErrInvalidCredentials", err)
	}
}
