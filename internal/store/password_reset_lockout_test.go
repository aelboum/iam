package store

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCompletePasswordResetKeepsTemporaryLockout is a regression guard for
// audit L3 and the internal assurance review of 2026-10-29: a password reset is
// account recovery, not a lockout bypass. CompletePasswordReset clears only the
// password failure counter; it must leave an active temporary password lockout
// (locked_until) and TOTP lockout (mfa_locked_until) in force, and it must
// refuse a manually locked account outright (the NOT locked predicate). The
// temporary lockouts keep blocking at login because CheckPassword re-checks
// IsLocked()/IsMFALocked(); the service-level guard is in
// internal/authn/password_reset_lockout_test.go.
//
// Needs a disposable database (IAM_TEST_DATABASE_URL); creates one org and one
// user per sub-case and removes them (cascade) at the end.
func TestCompletePasswordResetKeepsTemporaryLockout(t *testing.T) {
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
	if err := db.Migrate(ctx, pool); err != nil { // idempotent; ensures mfa_locked_until exists
		t.Fatalf("migrate: %v", err)
	}
	st := New(pool)

	const max = 5
	lockFor := time.Hour

	// newUser creates a fresh human user with a password hash in its own org.
	newUser := func(t *testing.T) string {
		t.Helper()
		sfx := uuid.NewString()
		org, err := st.CreateOrg(ctx, "l3-"+sfx, "l3-"+sfx)
		if err != nil {
			t.Fatalf("create org: %v", err)
		}
		t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID) }) // cascades to the user
		pw := "original-hash"
		u, err := st.CreateUser(ctx, NewUser{
			OrgID: org.ID, Username: "l3-" + sfx, Email: "l3-" + sfx + "@example.test", PasswordHash: &pw,
		})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		return u.ID
	}

	// lockOut drives the user into a temporary lockout of factor f.
	lockOut := func(t *testing.T, userID string, f Factor) {
		t.Helper()
		for i := 0; i < max+2; i++ {
			st.ReserveAttempt(ctx, userID, f, max)
			locked, err := st.AttemptFailed(ctx, userID, f, max, lockFor)
			if err != nil {
				t.Fatalf("attempt failed %s: %v", f, err)
			}
			if locked {
				return
			}
		}
		t.Fatalf("factor %s never locked", f)
	}

	// reset issues a single-use token and completes the reset, returning its error.
	reset := func(t *testing.T, userID string) error {
		t.Helper()
		tokenHash := uuid.NewString()
		if err := st.CreatePasswordReset(ctx, userID, tokenHash, time.Now().Add(15*time.Minute)); err != nil {
			t.Fatalf("create password reset: %v", err)
		}
		return st.CompletePasswordReset(ctx, tokenHash, userID, "new-hash")
	}

	t.Run("password lockout stays in force", func(t *testing.T) {
		userID := newUser(t)
		lockOut(t, userID, FactorPassword)
		if err := reset(t, userID); err != nil {
			t.Fatalf("reset during a temporary password lockout must be allowed (recovery): %v", err)
		}
		u, err := st.GetUser(ctx, userID)
		if err != nil {
			t.Fatal(err)
		}
		if u.FailedLogins != 0 {
			t.Errorf("reset must clear the password failure counter: failed_logins=%d, want 0", u.FailedLogins)
		}
		if !u.IsLocked() {
			t.Error("reset must NOT clear the temporary password lockout (audit L3): IsLocked()=false, want true")
		}
		if u.PasswordHash == nil || *u.PasswordHash != "new-hash" {
			t.Errorf("reset must set the new password hash: got %v", u.PasswordHash)
		}
	})

	t.Run("TOTP lockout stays in force", func(t *testing.T) {
		userID := newUser(t)
		lockOut(t, userID, FactorTOTP)
		if err := reset(t, userID); err != nil {
			t.Fatalf("reset during a TOTP lockout must be allowed: %v", err)
		}
		u, err := st.GetUser(ctx, userID)
		if err != nil {
			t.Fatal(err)
		}
		if !u.IsMFALocked() {
			t.Error("reset must NOT clear the TOTP lockout (audit L3/N11): IsMFALocked()=false, want true")
		}
	})

	t.Run("manual lock refuses the reset", func(t *testing.T) {
		userID := newUser(t)
		if err := st.SetLocked(ctx, userID, true); err != nil {
			t.Fatalf("set locked: %v", err)
		}
		if err := reset(t, userID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("reset of a manually locked account must fail with ErrNotFound: %v", err)
		}
	})
}
