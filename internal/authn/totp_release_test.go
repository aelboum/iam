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
)

// Internal security audit N12 (follow-up): a TOTP attempt whose code could not be
// evaluated — an unreadable/corrupt TOTP secret, or a transient store error in
// acceptTOTP — must NOT advance the MFA lockout counter, mirroring the password
// path. A genuinely wrong code must still count. Needs IAM_TEST_DATABASE_URL.
func TestCheckTOTPReleasesAttemptOnInternalError(t *testing.T) {
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
	box := secret.NewBox([32]byte{11})
	svc := NewService(st, box, Config{
		Limits:          ratelimit.Memory,
		SessionLifetime: time.Hour,
		MaxFailedLogins: 5,
		HashWaitTimeout: time.Second,
	})

	org, err := st.CreateOrg(ctx, "totp-"+uuid.NewString(), "totp-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, org.ID) })

	mfaFailed := func(id string) int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT mfa_failed_logins FROM users WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatalf("read mfa_failed_logins: %v", err)
		}
		return n
	}

	// mkUser creates a user whose first factor is already satisfied and whose TOTP
	// secret is the given (already-sealed) blob, marked verified.
	mkUser := func(name string, secretEnc []byte) (*store.User, string, string) {
		u, err := st.CreateUser(ctx, store.NewUser{OrgID: org.ID, Username: name, Email: name + "@totp.test"})
		if err != nil {
			t.Fatalf("create user %s: %v", name, err)
		}
		if err := st.SetPendingTOTP(ctx, u.ID, secretEnc); err != nil {
			t.Fatalf("set pending totp: %v", err)
		}
		if err := st.MarkTOTPVerified(ctx, u.ID); err != nil {
			t.Fatalf("mark totp verified: %v", err)
		}
		ss, err := svc.CreateSession(ctx, org.ID, name)
		if err != nil {
			t.Fatalf("create session: %v", err)
		}
		if err := st.MarkSessionPassword(ctx, ss.ID); err != nil { // first factor done
			t.Fatalf("mark session password: %v", err)
		}
		return u, ss.ID, ss.Token
	}

	// Case 1 — unreadable secret: a non-base32 blob decrypts fine but makes
	// totp.GenerateCode error inside acceptTOTP. The attempt must be released.
	badUser, badID, badTok := mkUser("totpbad", box.Seal([]byte("this is not valid base32 %%%")))
	if _, err := svc.CheckTOTP(ctx, Client{}, badID, badTok, "000000"); err == nil {
		t.Fatalf("corrupt-secret TOTP: want an internal error, got nil")
	}
	if n := mfaFailed(badUser.ID); n != 0 {
		t.Fatalf("corrupt-secret TOTP: mfa_failed_logins=%d after an unevaluated attempt; want 0 (released)", n)
	}

	// Case 2 — valid secret, wrong code: this IS an evaluated failure and must
	// still advance the counter (control proving the release is error-specific).
	okUser, okID, okTok := mkUser("totpok", box.Seal([]byte("JBSWY3DPEHPK3PXP")))
	if _, err := svc.CheckTOTP(ctx, Client{}, okID, okTok, "000000"); err == nil {
		t.Fatalf("wrong code: want ErrInvalidCredentials, got nil")
	}
	if n := mfaFailed(okUser.ID); n != 1 {
		t.Fatalf("wrong code: mfa_failed_logins=%d; want 1 (a real failure must count)", n)
	}
}
