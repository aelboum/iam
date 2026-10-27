package authn

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/aelboum/iam/internal/ratelimit"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
)

// TestFactorStatusOnlyRecordedAfterSuccess guards the core authn invariant: a
// failed password or TOTP check must leave the session unmarked for that factor
// and not authenticated, while incrementing that factor's attempt counter; a
// successful check marks the factor and resets the counter. This protects
// against a regression that records factor status before (or regardless of)
// successful validation. Needs IAM_TEST_DATABASE_URL.
func TestFactorStatusOnlyRecordedAfterSuccess(t *testing.T) {
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
	box := secret.NewBox([32]byte{13})
	svc := NewService(st, box, Config{
		Limits:          ratelimit.Memory,
		SessionLifetime: time.Hour,
		MaxFailedLogins: 5,
		HashWaitTimeout: time.Second,
		OrgLoginLimit:   1000, // generous; this test is not about the per-org budget
	})

	org, err := st.CreateOrg(ctx, "inv-"+uuid.NewString(), "inv-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID) })

	const (
		username   = "invuser"
		password   = "correct-horse-13"
		totpSecret = "JBSWY3DPEHPK3PXP" // valid base32
	)
	hash, err := svc.HashPassword(password, username, username+"@inv.test")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	user, err := st.CreateUser(ctx, store.NewUser{
		OrgID: org.ID, Username: username, Email: username + "@inv.test", PasswordHash: &hash,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := st.SetPendingTOTP(ctx, user.ID, box.Seal([]byte(totpSecret))); err != nil {
		t.Fatalf("set totp: %v", err)
	}
	if err := st.MarkTOTPVerified(ctx, user.ID); err != nil {
		t.Fatalf("mark totp verified: %v", err)
	}

	counters := func() (pw, mfa int) {
		if err := pool.QueryRow(ctx,
			`SELECT failed_logins, mfa_failed_logins FROM users WHERE id = $1`, user.ID,
		).Scan(&pw, &mfa); err != nil {
			t.Fatalf("read counters: %v", err)
		}
		return
	}

	ss, err := svc.CreateSession(ctx, org.ID, username)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	get := func() *SessionState {
		state, err := svc.GetSession(ctx, Client{}, ss.ID, ss.Token)
		if err != nil {
			t.Fatalf("get session: %v", err)
		}
		return state
	}

	// 1. Wrong password: no factor marked, not authenticated, counter advances.
	if _, err := svc.CheckPassword(ctx, Client{}, ss.ID, ss.Token, "wrong-password"); err != ErrInvalidCredentials {
		t.Fatalf("wrong password: err=%v, want ErrInvalidCredentials", err)
	}
	if s := get(); s.PasswordChecked || s.Authenticated {
		t.Fatalf("after wrong password: PasswordChecked=%v Authenticated=%v, want both false", s.PasswordChecked, s.Authenticated)
	}
	if pw, _ := counters(); pw != 1 {
		t.Fatalf("after wrong password: failed_logins=%d, want 1", pw)
	}

	// 2. Correct password: factor marked, counter reset; still not authenticated
	//    because TOTP is enrolled (MFA required).
	if _, err := svc.CheckPassword(ctx, Client{}, ss.ID, ss.Token, password); err != nil {
		t.Fatalf("correct password: err=%v, want nil", err)
	}
	if s := get(); !s.PasswordChecked {
		t.Fatalf("after correct password: PasswordChecked=false, want true")
	} else if s.Authenticated {
		t.Fatalf("after correct password: Authenticated=true before TOTP, want false (MFA enrolled)")
	}
	if pw, _ := counters(); pw != 0 {
		t.Fatalf("after correct password: failed_logins=%d, want 0 (reset)", pw)
	}

	// 3. Wrong TOTP: TOTP factor not marked, not authenticated, mfa counter
	//    advances; the password factor stays marked.
	wrong := "000000"
	if good, _ := totp.GenerateCode(totpSecret, time.Now()); good == wrong {
		wrong = "111111"
	}
	if _, err := svc.CheckTOTP(ctx, Client{}, ss.ID, ss.Token, wrong); err != ErrInvalidCredentials {
		t.Fatalf("wrong totp: err=%v, want ErrInvalidCredentials", err)
	}
	if s := get(); s.TOTPChecked || s.Authenticated || !s.PasswordChecked {
		t.Fatalf("after wrong totp: TOTPChecked=%v Authenticated=%v PasswordChecked=%v, want false/false/true",
			s.TOTPChecked, s.Authenticated, s.PasswordChecked)
	}
	if _, mfa := counters(); mfa != 1 {
		t.Fatalf("after wrong totp: mfa_failed_logins=%d, want 1", mfa)
	}

	// 4. Correct TOTP: factor marked, authenticated, mfa counter reset.
	good, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	if _, err := svc.CheckTOTP(ctx, Client{}, ss.ID, ss.Token, good); err != nil {
		t.Fatalf("correct totp: err=%v, want nil", err)
	}
	if s := get(); !s.TOTPChecked || !s.Authenticated {
		t.Fatalf("after correct totp: TOTPChecked=%v Authenticated=%v, want both true", s.TOTPChecked, s.Authenticated)
	}
	if _, mfa := counters(); mfa != 0 {
		t.Fatalf("after correct totp: mfa_failed_logins=%d, want 0 (reset)", mfa)
	}
}
