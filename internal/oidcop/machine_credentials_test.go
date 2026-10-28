package oidcop

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TestMachineClientCredentialsRechecksGrantAtIssuance pins the authorization
// re-check a machine user passes when it asks for a NEW token through the
// client_credentials grant. ClientCredentialsTokenRequest validates the
// requested project scope live against the machine user's org:
// projectFromScopes -> AvailableRoles(project, machineUser.OrgID). So once the
// org's grant on that project is revoked, the next token request is refused
// with invalid_scope, while a machine user of another tenant that still holds a
// grant is unaffected.
//
// Contract notes (tested here, not assumed):
//   - this issuance path uses AvailableRoles directly and returns invalid_scope
//     ("no access to the requested project"); it is NOT checkUserCanUseProject
//     and does NOT return ErrNoAccess (that is the introspection/refresh path);
//   - machine users have only the client_credentials grant (no refresh /
//     offline_access), so there is no machine refresh-token flow to guard;
//   - a store-level grant revocation only fails this live check; it does not by
//     itself delete any already-issued token row (that is RevokeProjectTokens,
//     pinned separately in TestMachineUserTokenIntrospectionLive).
//
// Needs IAM_TEST_DATABASE_URL.
func TestMachineClientCredentialsRechecksGrantAtIssuance(t *testing.T) {
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
	s := NewStorage(st, nil, secret.NewBox([32]byte{43}), TokenConfig{
		KeyRotation: time.Hour, AccessToken: 5 * time.Minute,
		RefreshIdle: time.Hour, SessionMaxAge: 24 * time.Hour,
	})

	owner, err := st.CreateOrg(ctx, "own-"+uuid.NewString(), "own-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create owner org: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, owner.ID) })

	mkProject := func(name string) *store.Project {
		p, err := st.CreateProject(ctx, owner.ID, name+"-"+uuid.NewString())
		if err != nil {
			t.Fatalf("create project %s: %v", name, err)
		}
		if err := st.AddRole(ctx, p.ID, store.Role{Key: "viewer", DisplayName: "viewer"}); err != nil {
			t.Fatalf("add role: %v", err)
		}
		return p
	}
	projP := mkProject("P")
	projQ := mkProject("Q") // owner's second project; no tenant is granted it

	// mkMachine returns the machine user and its client id (User.ClientID is a
	// *string, so the known value is returned directly).
	mkMachine := func(org string) (*store.User, string) {
		clientID := "machine-" + uuid.NewString()
		m, err := st.CreateMachineUser(ctx, org, "m-"+uuid.NewString(), clientID, "sechash")
		if err != nil {
			t.Fatalf("create machine user: %v", err)
		}
		return m, clientID
	}

	// Tenant T granted viewer on P; tenant T2 also granted viewer on P.
	tenantT, err := st.CreateOrg(ctx, "t-"+uuid.NewString(), "t-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create tenant T: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, tenantT.ID) })
	grantT, err := st.CreateProjectGrant(ctx, projP.ID, tenantT.ID, []string{"viewer"})
	if err != nil {
		t.Fatalf("create grant T: %v", err)
	}
	mU, mUClient := mkMachine(tenantT.ID)

	tenantT2, err := st.CreateOrg(ctx, "t2-"+uuid.NewString(), "t2-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create tenant T2: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, tenantT2.ID) })
	if _, err := st.CreateProjectGrant(ctx, projP.ID, tenantT2.ID, []string{"viewer"}); err != nil {
		t.Fatalf("create grant T2: %v", err)
	}
	mX, mXClient := mkMachine(tenantT2.ID)

	scopeP := []string{ProjectScopePrefix + projP.ID}
	scopeQ := []string{ProjectScopePrefix + projQ.ID}

	request := func(clientID string, scopes []string) (subject string, err error) {
		req, e := s.ClientCredentialsTokenRequest(ctx, clientID, scopes)
		if e != nil {
			return "", e
		}
		if req.GetSubject() == "" {
			t.Fatal("issued token request has no subject")
		}
		return req.GetSubject(), nil
	}
	refusedInvalidScope := func(err error) bool {
		var oe *oidc.Error
		return errors.As(err, &oe) && oe.ErrorType == oidc.InvalidScope
	}

	// --- invariant 1: a granted machine user gets a token request for P. -----
	if sub, err := request(mUClient, scopeP); err != nil || sub != mU.ID {
		t.Fatalf("granted machine user on P: sub=%q err=%v, want subject=%s and no error", sub, err, mU.ID)
	}

	// --- invariant 4: a machine user cannot get a token for a project its org
	// was never granted (knowing the project id/scope is not enough).
	if _, err := request(mXClient, scopeQ); !refusedInvalidScope(err) {
		t.Errorf("ungranted project Q for T2: err=%v, want invalid_scope", err)
	}

	// --- invariant 5 (new-token refusal after revocation): revoke T's grant on
	// P at the store level; the next client_credentials request is refused.
	if err := st.DeleteProjectGrant(ctx, grantT.ID); err != nil {
		t.Fatalf("delete grant T: %v", err)
	}
	if _, err := request(mUClient, scopeP); !refusedInvalidScope(err) {
		t.Errorf("after grant revocation: err=%v, want invalid_scope (no new token)", err)
	}

	// --- invariant 6 (tenant isolation): T2 still holds its grant, so its
	// machine user still gets a token for P.
	if sub, err := request(mXClient, scopeP); err != nil || sub != mX.ID {
		t.Errorf("tenant T2 isolation on P: sub=%q err=%v, want subject=%s and no error", sub, err, mX.ID)
	}
}
