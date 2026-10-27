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

// Internal security audit N12 (integration): when the hashing pool is saturated,
// CheckPassword must shed as ErrOverloaded for every caller — a known user, a
// passwordless user and (implicitly) an unknown one alike, so overload is never
// an account-enumeration oracle — and a shed must not advance the account's
// lockout counter, because the password was never evaluated.
//
// Needs a disposable database (IAM_TEST_DATABASE_URL).
func TestOverloadDoesNotLeakOrEnumerate(t *testing.T) {
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
	svc := NewService(st, secret.NewBox([32]byte{9}), Config{
		Limits:          ratelimit.Memory,
		SessionLifetime: time.Hour,
		MaxFailedLogins: 5,
		HashWaitTimeout: 50 * time.Millisecond, // shed fast once the pool is full
		OrgLoginLimit:   1000,
	})

	sfx := uuid.NewString()
	org, err := st.CreateOrg(ctx, "ovl-"+sfx, "ovl-"+sfx)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID) })

	const pw = "correct-horse-9"
	hash, err := svc.HashPassword(pw, "withpw", "withpw@ovl.test")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	withPW, err := st.CreateUser(ctx, store.NewUser{
		OrgID: org.ID, Username: "withpw", Email: "withpw@ovl.test", PasswordHash: &hash,
	})
	if err != nil {
		t.Fatalf("create user with password: %v", err)
	}
	// A user with no password exercises the dummy-hash branch of CheckPassword.
	noPW, err := st.CreateUser(ctx, store.NewUser{
		OrgID: org.ID, Username: "nopw", Email: "nopw@ovl.test",
	})
	if err != nil {
		t.Fatalf("create user without password: %v", err)
	}

	failedLogins := func(id string) int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT failed_logins FROM users WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatalf("read failed_logins: %v", err)
		}
		return n
	}

	checkUnderOverload := func(user string) error {
		ss, err := svc.CreateSession(ctx, org.ID, user)
		if err != nil {
			t.Fatalf("create session for %s: %v", user, err)
		}
		// Saturate the process-wide hashing pool so the next acquire sheds.
		drainHashSlots()
		for i := 0; i < cap(hashSlots); i++ {
			hashSlots <- struct{}{}
		}
		defer drainHashSlots()
		_, err = svc.CheckPassword(ctx, Client{}, ss.ID, ss.Token, pw)
		return err
	}

	// Known user with a password: overload must surface as ErrOverloaded, not as a
	// wrong-password result, and must not advance the lockout counter.
	if err := checkUnderOverload("withpw"); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("known user under overload: err=%v, want ErrOverloaded", err)
	}
	if n := failedLogins(withPW.ID); n != 0 {
		t.Fatalf("known user failed_logins=%d after an overload shed; want 0 (the reserved attempt must be released)", n)
	}

	// Passwordless user (dummy-hash branch): overload must also surface as
	// ErrOverloaded, never ErrInvalidCredentials — otherwise the status code would
	// reveal whether the account can log in with a password.
	if err := checkUnderOverload("nopw"); !errors.Is(err, ErrOverloaded) {
		t.Fatalf("passwordless user under overload: err=%v, want ErrOverloaded (not ErrInvalidCredentials)", err)
	}
	if n := failedLogins(noPW.ID); n != 0 {
		t.Fatalf("passwordless user failed_logins=%d after an overload shed; want 0", n)
	}
}
