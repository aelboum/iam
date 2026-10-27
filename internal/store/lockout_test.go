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

// TestPerFactorLockout covers the N11 asymmetric lockout matrix at the store
// layer: a password lockout blocks the password factor but not the TOTP factor;
// a TOTP lockout blocks both factors (anti-bypass); a manual unlock clears both;
// and ReserveAttempt stays atomic under concurrent guesses.
//
// Needs a disposable database (IAM_TEST_DATABASE_URL); creates one org and one
// user and removes them (cascade) at the end.
func TestPerFactorLockout(t *testing.T) {
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

	sfx := uuid.NewString()
	org, err := st.CreateOrg(ctx, "n11-"+sfx, "n11-"+sfx)
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID) // cascades to the user

	pw := "not-a-real-hash"
	user, err := st.CreateUser(ctx, NewUser{
		OrgID: org.ID, Username: "n11-" + sfx, Email: "n11-" + sfx + "@example.test", PasswordHash: &pw,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	id := user.ID
	const max = 5
	lockFor := time.Hour

	reserve := func(f Factor) bool {
		ok, err := st.ReserveAttempt(ctx, id, f, max)
		if err != nil {
			t.Fatalf("reserve %s: %v", f, err)
		}
		return ok
	}
	lockOut := func(f Factor) {
		t.Helper()
		for i := 0; i < max+2; i++ {
			st.ReserveAttempt(ctx, id, f, max)
			locked, err := st.AttemptFailed(ctx, id, f, max, lockFor)
			if err != nil {
				t.Fatalf("attempt failed %s: %v", f, err)
			}
			if locked {
				return
			}
		}
		t.Fatalf("factor %s never locked", f)
	}
	state := func() *User {
		u, err := st.GetUser(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}

	// Row 1 + 2: a password lockout blocks the password factor but NOT TOTP.
	lockOut(FactorPassword)
	u := state()
	if !u.IsLocked() || u.IsMFALocked() {
		t.Fatalf("password lockout: IsLocked=%v IsMFALocked=%v, want true/false", u.IsLocked(), u.IsMFALocked())
	}
	if reserve(FactorPassword) {
		t.Fatal("row 1: password attempt must be refused during a password lockout")
	}
	if !reserve(FactorTOTP) {
		t.Fatal("row 2: a TOTP attempt must be allowed during a password lockout (SSO second factor)")
	}
	if err := st.SetLocked(ctx, id, false); err != nil { // clean slate
		t.Fatal(err)
	}

	// Row 3 + 5: a TOTP lockout blocks BOTH the TOTP factor and the password path.
	lockOut(FactorTOTP)
	u = state()
	if !u.IsMFALocked() {
		t.Fatal("TOTP lockout must report IsMFALocked()")
	}
	if reserve(FactorTOTP) {
		t.Fatal("row 5: a further TOTP guess must be refused during a TOTP lockout")
	}
	if reserve(FactorPassword) {
		t.Fatal("row 3: the password path must be refused during a TOTP lockout (anti-bypass)")
	}

	// Row 6: a manual unlock clears both lockouts.
	if err := st.SetLocked(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	u = state()
	if u.IsLocked() || u.IsMFALocked() {
		t.Fatal("row 6: SetLocked(false) must clear both lockouts")
	}
	if !reserve(FactorPassword) || !reserve(FactorTOTP) {
		t.Fatal("row 6: both factors must be allowed after an unlock")
	}

	// Row 7: concurrent password guesses never exceed the cap.
	if err := st.SetLocked(ctx, id, false); err != nil {
		t.Fatal(err)
	}
	var granted int64
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := st.ReserveAttempt(ctx, id, FactorPassword, max); ok {
				atomic.AddInt64(&granted, 1)
			}
		}()
	}
	wg.Wait()
	if granted != max {
		t.Fatalf("row 7: %d parallel reservations granted, want exactly %d", granted, max)
	}
}
