package oidcop

import (
	"context"
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

// TestIntrospectionRechecksGrantLive proves that SetIntrospectionFromToken is a
// live authorization decision on an opaque bearer token, not a cached verdict:
// it re-reads the project grant and the user's effective roles on every call,
// through tokenProject -> checkUserCanUseProject -> AvailableRoles/EffectiveRoles.
// So revoking or narrowing a project grant changes the next introspection of an
// already-issued opaque token, while tokens of other tenants/projects stay
// isolated. The tokens are seeded directly through the store; no OIDC/HTTP round
// trip is needed. Needs IAM_TEST_DATABASE_URL.
//
// Scope note: this path applies to OPAQUE bearer tokens looked up in
// access_tokens. Self-contained JWT access tokens (access_token_type=jwt) are
// validated by signature at the resource server and are not re-checked here;
// narrowing a grant does NOT retroactively invalidate an already-issued JWT at
// an external resource server until it expires (bounded by the ~5m access-token
// TTL). This test makes no claim about JWT validation at external servers.
func TestIntrospectionRechecksGrantLive(t *testing.T) {
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
	s := NewStorage(st, nil, secret.NewBox([32]byte{37}), TokenConfig{
		KeyRotation: time.Hour, AccessToken: 5 * time.Minute,
		RefreshIdle: time.Hour, SessionMaxAge: 24 * time.Hour,
	})

	// --- fixtures ------------------------------------------------------------
	// Owner org with project P (roles admin+viewer), a resource app whose tokens
	// are introspected, an API-backend caller app (same project), and a second
	// project Q with its own app to prove cross-project isolation.
	owner, err := st.CreateOrg(ctx, "own-"+uuid.NewString(), "own-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create owner org: %v", err)
	}
	t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, owner.ID) })

	projP, err := st.CreateProject(ctx, owner.ID, "P-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create project P: %v", err)
	}
	for _, key := range []string{"admin", "viewer"} {
		if err := st.AddRole(ctx, projP.ID, store.Role{Key: key, DisplayName: key}); err != nil {
			t.Fatalf("add role %s: %v", key, err)
		}
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
	clientApp := mkApp(projP.ID) // tokens are issued to this client
	clientAPI := mkApp(projP.ID) // the API backend that introspects

	projQ, err := st.CreateProject(ctx, owner.ID, "Q-"+uuid.NewString())
	if err != nil {
		t.Fatalf("create project Q: %v", err)
	}
	clientQ := mkApp(projQ.ID)

	// Two customer tenants, each granted onto P and each with a user+token.
	type tenant struct {
		org   *store.Org
		user  *store.User
		grant *store.ProjectGrant
		atID  string
	}
	mkTenant := func(prefix string, projectRoles, userRoles []string) tenant {
		o, err := st.CreateOrg(ctx, prefix+"-"+uuid.NewString(), prefix+"-"+uuid.NewString())
		if err != nil {
			t.Fatalf("create tenant org: %v", err)
		}
		t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, o.ID) })
		g, err := st.CreateProjectGrant(ctx, projP.ID, o.ID, projectRoles)
		if err != nil {
			t.Fatalf("create project grant: %v", err)
		}
		u, err := st.CreateUser(ctx, store.NewUser{OrgID: o.ID, Username: "u-" + uuid.NewString(), Email: uuid.NewString() + "@in.test"})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}
		if _, err := st.CreateUserGrant(ctx, u, projP.ID, userRoles); err != nil {
			t.Fatalf("create user grant: %v", err)
		}
		atID, rtID := uuid.NewString(), uuid.NewString()
		at := &store.AccessToken{
			ID: atID, ClientID: clientApp, Subject: u.ID, Audience: []string{clientApp},
			Scopes: []string{oidc.ScopeOpenID}, RefreshTokenID: &rtID, ExpiresAt: time.Now().Add(time.Hour),
		}
		rt := &store.RefreshToken{
			ID: rtID, TokenHash: uuid.NewString(), ClientID: clientApp, Subject: u.ID,
			Audience: []string{clientApp}, Scopes: []string{oidc.ScopeOpenID}, AMR: []string{}, AuthTime: time.Now(),
			AccessTokenID: &atID, ExpiresAt: time.Now().Add(24 * time.Hour), FamilyID: uuid.NewString(),
		}
		if err := st.CreateTokens(ctx, at, rt); err != nil {
			t.Fatalf("create tokens: %v", err)
		}
		return tenant{org: o, user: u, grant: g, atID: atID}
	}

	tA := mkTenant("ta", []string{"admin", "viewer"}, []string{"admin", "viewer"})
	tB := mkTenant("tb", []string{"viewer"}, []string{"viewer"})

	// introspect runs SetIntrospectionFromToken with the API backend as caller
	// and returns the active flag (err == nil) and the reported roles.
	introspect := func(caller, atID, subject string) (active bool, roles []string) {
		resp := new(oidc.IntrospectionResponse)
		if err := s.SetIntrospectionFromToken(ctx, resp, atID, subject, caller); err != nil {
			return false, nil
		}
		if v, ok := resp.Claims["roles"].([]string); ok {
			roles = append(roles, v...)
			slices.Sort(roles)
		}
		return true, roles
	}

	// --- invariant 1: an initially valid token is active with its roles. -----
	if active, roles := introspect(clientAPI, tA.atID, tA.user.ID); !active || !slices.Equal(roles, []string{"admin", "viewer"}) {
		t.Fatalf("tenant A initial: active=%v roles=%v, want active with [admin viewer]", active, roles)
	}
	if active, roles := introspect(clientAPI, tB.atID, tB.user.ID); !active || !slices.Equal(roles, []string{"viewer"}) {
		t.Fatalf("tenant B initial: active=%v roles=%v, want active with [viewer]", active, roles)
	}

	// --- invariant 5a: a caller from another project cannot introspect this
	// token (token's project != caller's project), while the token stays valid.
	if active, _ := introspect(clientQ, tA.atID, tA.user.ID); active {
		t.Error("a caller from another project must not get an active introspection")
	}
	if active, _ := introspect(clientAPI, tA.atID, tA.user.ID); !active {
		t.Error("the cross-project rejection must not have affected the token itself")
	}

	// --- invariant 4: narrowing tenant A's grant to viewer drops admin from the
	// live introspection of the same, already-issued token.
	if _, err := st.UpdateProjectGrant(ctx, tA.grant.ID, []string{"viewer"}); err != nil {
		t.Fatalf("narrow grant: %v", err)
	}
	if active, roles := introspect(clientAPI, tA.atID, tA.user.ID); !active || !slices.Equal(roles, []string{"viewer"}) {
		t.Fatalf("tenant A after narrowing: active=%v roles=%v, want active with [viewer] only", active, roles)
	}

	// --- invariants 2+3: revoking tenant A's grant makes the same token report
	// inactive on the next live introspection.
	if err := st.DeleteProjectGrant(ctx, tA.grant.ID); err != nil {
		t.Fatalf("delete grant: %v", err)
	}
	if active, _ := introspect(clientAPI, tA.atID, tA.user.ID); active {
		t.Error("after its grant is revoked, the token must introspect as inactive")
	}

	// --- invariant 5b: tenant B is fully isolated -- revoking/narrowing tenant
	// A's grant left tenant B's token active with its own roles.
	if active, roles := introspect(clientAPI, tB.atID, tB.user.ID); !active || !slices.Equal(roles, []string{"viewer"}) {
		t.Errorf("tenant B isolation: active=%v roles=%v, want still active with [viewer]", active, roles)
	}
}
