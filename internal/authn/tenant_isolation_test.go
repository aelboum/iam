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
