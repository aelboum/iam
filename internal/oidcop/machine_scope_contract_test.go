package oidcop

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/db"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// TestMachineClientCredentialsScopeContract pins the scope contract of the
// client_credentials grant end to end: what ClientCredentialsTokenRequest
// validates, and what machineAccessToken then actually stores and issues. The
// pure scope grammar is already unit-tested in TestMachineScopes and at the
// HTTP layer in scripts/features_test.py; this test covers the integrated Go
// outcome -- the stored/issued access-token scopes and the no-write guarantee
// on refusal -- which neither of those does.
//
// Contract (from MachineScopes + ClientCredentialsTokenRequest, tested as
// implemented): the only honoured scope is exactly one urn:iam:project:<uuid>
// whose project the machine user's org may use. An empty-string scope is
// safely dropped; any other scope (openid, offline_access, a second project
// scope, a malformed uuid) is an EXPLICIT refusal with invalid_scope, never a
// silent pass-through. The issued/stored token carries only the validated
// scope, and a refused request writes no token rows and changes no grants.
//
// Needs IAM_TEST_DATABASE_URL.
func TestMachineClientCredentialsScopeContract(t *testing.T) {
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
	s := NewStorage(st, nil, secret.NewBox([32]byte{47}), TokenConfig{
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
	projR := mkProject("R") // a second project the same tenant is also granted

	mkTenantMachine := func(prefix string, projects ...string) (string, string) {
		o, err := st.CreateOrg(ctx, prefix+"-"+uuid.NewString(), prefix+"-"+uuid.NewString())
		if err != nil {
			t.Fatalf("create tenant: %v", err)
		}
		t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, o.ID) })
		for _, p := range projects {
			if _, err := st.CreateProjectGrant(ctx, p, o.ID, []string{"viewer"}); err != nil {
				t.Fatalf("create grant: %v", err)
			}
		}
		clientID := "machine-" + uuid.NewString()
		m, err := st.CreateMachineUser(ctx, o.ID, "m-"+uuid.NewString(), clientID, "sechash")
		if err != nil {
			t.Fatalf("create machine user: %v", err)
		}
		return m.ID, clientID
	}

	// Tenant T is granted both P and R.
	subT, clientT := mkTenantMachine("t", projP.ID, projR.ID)
	// Tenant T2 is granted only P (independence check).
	_, clientT2 := mkTenantMachine("t2", projP.ID)

	scopeP := ProjectScopePrefix + projP.ID
	scopeR := ProjectScopePrefix + projR.ID

	// invalidScope reports whether err is the documented invalid_scope refusal.
	invalidScope := func(err error) bool {
		var oe *oidc.Error
		return errors.As(err, &oe) && oe.ErrorType == oidc.InvalidScope
	}
	countTokens := func(subject string) (access, refresh int) {
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM access_tokens WHERE subject = $1`, subject).Scan(&access); err != nil {
			t.Fatalf("count access: %v", err)
		}
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens WHERE subject = $1`, subject).Scan(&refresh); err != nil {
			t.Fatalf("count refresh: %v", err)
		}
		return access, refresh
	}
	countGrants := func(projectID string) (n int) {
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM project_grants WHERE project_id = $1`, projectID).Scan(&n); err != nil {
			t.Fatalf("count grants: %v", err)
		}
		return n
	}
	// issueScopes drives the real request builder and the real storage writer,
	// then returns the scopes actually persisted on the stored access token.
	issueScopes := func(clientID string, scopes []string) []string {
		req, err := s.ClientCredentialsTokenRequest(ctx, clientID, scopes)
		if err != nil {
			t.Fatalf("ClientCredentialsTokenRequest(%v): %v", scopes, err)
		}
		jwt, ok := req.(*oidc.JWTTokenRequest)
		if !ok {
			t.Fatalf("request type = %T, want *oidc.JWTTokenRequest", req)
		}
		atID, _, err := s.machineAccessToken(ctx, jwt)
		if err != nil {
			t.Fatalf("machineAccessToken: %v", err)
		}
		at, err := st.GetAccessToken(ctx, atID)
		if err != nil {
			t.Fatalf("GetAccessToken: %v", err)
		}
		return at.Scopes
	}

	// --- invariant 1 + 5: a valid project scope with a grant is accepted and
	// the stored token carries exactly that one validated scope.
	if got := issueScopes(clientT, []string{scopeP}); !slices.Equal(got, []string{scopeP}) {
		t.Errorf("stored scopes = %v, want exactly [%s]", got, scopeP)
	}
	// An empty-string scope is safely normalized away (dropped), not an error,
	// and still yields only the validated project scope.
	if got := issueScopes(clientT, []string{"", scopeP}); !slices.Equal(got, []string{scopeP}) {
		t.Errorf("stored scopes with an empty entry = %v, want exactly [%s]", got, scopeP)
	}

	// --- invariant 6 baseline: record state before the refusals.
	accBefore, refBefore := countTokens(subT)
	grantsP, grantsR := countGrants(projP.ID), countGrants(projR.ID)

	// --- invariants 2/3/4: non-project, extra, duplicate-project and malformed
	// scopes are EXPLICITLY refused with invalid_scope -- never silently passed
	// through or stored.
	refusals := map[string][]string{
		"openid passthrough":     {scopeP, "openid"},
		"offline_access":         {scopeP, "offline_access"},
		"unknown scope":          {"admin"},
		"two project scopes":     {scopeP, scopeR},
		"malformed project uuid": {ProjectScopePrefix + "not-a-uuid"},
	}
	for name, scopes := range refusals {
		if _, err := s.ClientCredentialsTokenRequest(ctx, clientT, scopes); !invalidScope(err) {
			t.Errorf("%s: err=%v, want invalid_scope", name, err)
		}
	}

	// --- invariant 6: no refused request wrote a token or refresh row, and no
	// grant changed.
	if accAfter, refAfter := countTokens(subT); accAfter != accBefore || refAfter != refBefore {
		t.Errorf("refused requests changed token rows: access %d->%d, refresh %d->%d",
			accBefore, accAfter, refBefore, refAfter)
	}
	if countGrants(projP.ID) != grantsP || countGrants(projR.ID) != grantsR {
		t.Error("refused requests changed project grants")
	}

	// --- invariant 7: a second tenant with its own valid grant is unaffected by
	// tenant T's refusals and still issues a token with only its validated scope.
	if got := issueScopes(clientT2, []string{scopeP}); !slices.Equal(got, []string{scopeP}) {
		t.Errorf("tenant T2 stored scopes = %v, want exactly [%s]", got, scopeP)
	}
}
