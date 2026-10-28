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

// TestMachineUserTokenIntrospectionLive pins the machine-user side of live
// token introspection. A machine user is a users row with kind='machine' and
// its own client_id; its token carries the project in a urn:iam:project:<id>
// scope rather than through an app's client_id. SetIntrospectionFromToken
// resolves the token's project via tokenProject -> GetMachineUserByClientID +
// projectFromScopes, then authorizes exactly like a human through
// checkUserCanUseProject -> AvailableRoles(project, machineUser.OrgID). So:
//
//   - a machine token is active only while its OWNER ORG actually has access to
//     the scoped project; merely naming a project in the scope grants nothing;
//   - the introspecting caller must be an app of that same project;
//   - the decision is live: revoking the org's project grant flips the next
//     introspection to inactive.
//
// It also separates the two revocation guarantees: a store-level
// DeleteProjectGrant fails the live check but leaves the token row in place,
// while RevokeProjectTokens physically deletes the machine token by matching
// its project scope. The tokens are seeded through the store; no OIDC/HTTP
// round trip is used. Needs IAM_TEST_DATABASE_URL.
func TestMachineUserTokenIntrospectionLive(t *testing.T) {
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
	s := NewStorage(st, nil, secret.NewBox([32]byte{41}), TokenConfig{
		KeyRotation: time.Hour, AccessToken: 5 * time.Minute,
		RefreshIdle: time.Hour, SessionMaxAge: 24 * time.Hour,
	})

	// Owner org owns projects P and Q; each project has a viewer role and an
	// API-backend app that does the introspecting.
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
	mkApp := func(proj string) string {
		clientID := "client-" + uuid.NewString()
		if _, err := st.CreateApp(ctx, store.App{
			ProjectID: proj, Name: "app", ClientID: clientID, AppType: "web",
			AuthMethod: "none", AccessTokenType: "bearer",
			RedirectURIs: []string{}, PostLogoutRedirectURIs: []string{},
		}); err != nil {
			t.Fatalf("create app: %v", err)
		}
		return clientID
	}
	projP := mkProject("P")
	projQ := mkProject("Q")
	callerP := mkApp(projP.ID) // API backend in P
	callerQ := mkApp(projQ.ID) // API backend in Q

	// mkMachineToken creates a machine user in org and an opaque token for it
	// scoped to projectID, and returns the machine user and the access-token id.
	mkMachineToken := func(org, projectID string, withViewerGrant bool) (*store.User, string) {
		clientID := "machine-" + uuid.NewString()
		m, err := st.CreateMachineUser(ctx, org, "m-"+uuid.NewString(), clientID, "sechash")
		if err != nil {
			t.Fatalf("create machine user: %v", err)
		}
		if withViewerGrant {
			if _, err := st.CreateUserGrant(ctx, m, projectID, []string{"viewer"}); err != nil {
				t.Fatalf("create machine user grant: %v", err)
			}
		}
		scopes := []string{ProjectScopePrefix + projectID}
		atID, rtID := uuid.NewString(), uuid.NewString()
		at := &store.AccessToken{
			ID: atID, ClientID: clientID, Subject: m.ID, Audience: []string{clientID},
			Scopes: scopes, RefreshTokenID: &rtID, ExpiresAt: time.Now().Add(time.Hour),
		}
		rt := &store.RefreshToken{
			ID: rtID, TokenHash: uuid.NewString(), ClientID: clientID, Subject: m.ID,
			Audience: []string{clientID}, Scopes: scopes, AMR: []string{}, AuthTime: time.Now(),
			AccessTokenID: &atID, ExpiresAt: time.Now().Add(24 * time.Hour), FamilyID: uuid.NewString(),
		}
		if err := st.CreateTokens(ctx, at, rt); err != nil {
			t.Fatalf("create tokens: %v", err)
		}
		return m, atID
	}
	accessPresent := func(atID string) bool {
		_, err := st.GetAccessToken(ctx, atID)
		if err == nil {
			return true
		}
		if errors.Is(err, store.ErrNotFound) {
			return false
		}
		t.Fatalf("GetAccessToken(%s): %v", atID, err)
		return false
	}
	introspect := func(caller, atID string) (active bool, roles []string) {
		resp := new(oidc.IntrospectionResponse)
		if err := s.SetIntrospectionFromToken(ctx, resp, atID, "", caller); err != nil {
			return false, nil
		}
		if v, ok := resp.Claims["roles"].([]string); ok {
			roles = append(roles, v...)
			slices.Sort(roles)
		}
		return true, roles
	}

	// Tenant T is granted viewer on P; its machine user mU is the subject under
	// test. mU also holds a viewer user-grant so a role is reported.
	tenantT, err := st.CreateOrg(ctx, "t-"+uuid.NewString(), "t-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create tenant T: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, tenantT.ID) })
	grantT, err := st.CreateProjectGrant(ctx, projP.ID, tenantT.ID, []string{"viewer"})
	if err != nil {
		t.Fatalf("create grant T: %v", err)
	}
	_, atU := mkMachineToken(tenantT.ID, projP.ID, true)

	// Tenant T2 is NOT granted P; its machine user mX scopes P anyway.
	tenantT2, err := st.CreateOrg(ctx, "t2-"+uuid.NewString(), "t2-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create tenant T2: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, tenantT2.ID) })
	_, atX := mkMachineToken(tenantT2.ID, projP.ID, false)

	// A bystander machine user in the owner org, scoped to Q (a different
	// project). It must stay active and present through all P operations.
	_, atZ := mkMachineToken(owner.ID, projQ.ID, false)

	// --- invariant 1+2: valid machine token on P is active via a P caller. ----
	if active, roles := introspect(callerP, atU); !active || !slices.Equal(roles, []string{"viewer"}) {
		t.Fatalf("machine token on P: active=%v roles=%v, want active with [viewer]", active, roles)
	}
	// Bystander in the owner org on Q is active via a Q caller (the owner org
	// always has access to its own project, even without a grant row).
	if active, _ := introspect(callerQ, atZ); !active {
		t.Fatal("owner-org machine token on Q must be active")
	}

	// --- invariant 4: another tenant cannot gain access by only naming P in the
	// scope; mX's org has no grant on P, so introspection is inactive.
	if active, _ := introspect(callerP, atX); active {
		t.Error("a machine user whose org has no grant must not be active just by scoping the project")
	}

	// --- invariant 3: a caller from another project gets an inactive result and
	// the token itself is unchanged.
	if active, _ := introspect(callerQ, atU); active {
		t.Error("a caller from another project must not get an active introspection of a P token")
	}
	if active, _ := introspect(callerP, atU); !active {
		t.Error("the cross-project rejection must not have changed the token")
	}

	// --- invariant 5 (live authorization): revoking T's grant on P at the store
	// level flips the live introspection to inactive, WITHOUT deleting the token
	// row (store DeleteProjectGrant does not touch tokens).
	if err := st.DeleteProjectGrant(ctx, grantT.ID); err != nil {
		t.Fatalf("delete grant T: %v", err)
	}
	if active, _ := introspect(callerP, atU); active {
		t.Error("after its org's grant is revoked, the machine token must introspect as inactive")
	}
	if !accessPresent(atU) {
		t.Error("a store-level grant revocation must NOT physically delete the token (live check only)")
	}
	// --- invariant 6: the bystander on Q is untouched by P's grant change.
	if active, _ := introspect(callerQ, atZ); !active {
		t.Error("revoking tenant T's grant on P must not affect an owner-org token on Q")
	}

	// --- physical revocation: RevokeProjectTokens deletes machine tokens by
	// matching the project scope (a separate, stronger guarantee than the live
	// check). It removes the P-scoped tokens and leaves the Q-scoped one.
	if err := st.RevokeProjectTokens(ctx, projP.ID, ""); err != nil {
		t.Fatalf("RevokeProjectTokens: %v", err)
	}
	if accessPresent(atU) || accessPresent(atX) {
		t.Error("RevokeProjectTokens must physically delete tokens carrying the project scope")
	}
	if !accessPresent(atZ) {
		t.Error("RevokeProjectTokens(P) must not delete a token scoped to another project")
	}
}
