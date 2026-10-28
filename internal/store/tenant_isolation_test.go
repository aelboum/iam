package store

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/aelboum/iam/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAvailableRolesCrossOrgIsolation guards the project authorization boundary:
// AvailableRoles must grant a project's roles only to the owning organization or
// to an organization that holds an explicit project grant, and must return
// ok=false for any other organization. This protects against a regression that
// would leak a project's roles to a foreign tenant. Needs IAM_TEST_DATABASE_URL.
func TestAvailableRolesCrossOrgIsolation(t *testing.T) {
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
	st := New(pool)

	mkOrg := func(p string) *Org {
		o, err := st.CreateOrg(ctx, p+"-"+uuid.NewString(), p+"-"+uuid.NewString())
		if err != nil {
			t.Fatalf("create org %s: %v", p, err)
		}
		t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, o.ID) })
		return o
	}
	owner := mkOrg("owner")
	outsider := mkOrg("outsider")
	granted := mkOrg("granted")

	proj, err := st.CreateProject(ctx, owner.ID, "iso-project")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}

	// Owner: authorized (ok=true), regardless of whether roles exist yet.
	if _, ok, err := st.AvailableRoles(ctx, proj.ID, owner.ID); err != nil || !ok {
		t.Fatalf("owner org: ok=%v err=%v, want ok=true", ok, err)
	}

	// Outsider with no grant: not authorized, no roles leaked.
	roles, ok, err := st.AvailableRoles(ctx, proj.ID, outsider.ID)
	if err != nil {
		t.Fatalf("outsider org: unexpected err=%v", err)
	}
	if ok || len(roles) != 0 {
		t.Fatalf("outsider org: ok=%v roles=%v, want ok=false and no roles", ok, roles)
	}

	// Granted org: authorized for exactly the granted role keys. The role must be
	// defined on the project before it can be granted.
	if err := st.AddRole(ctx, proj.ID, Role{Key: "viewer", DisplayName: "Viewer"}); err != nil {
		t.Fatalf("add role: %v", err)
	}
	if _, err := st.CreateProjectGrant(ctx, proj.ID, granted.ID, []string{"viewer"}); err != nil {
		t.Fatalf("create project grant: %v", err)
	}
	roles, ok, err = st.AvailableRoles(ctx, proj.ID, granted.ID)
	if err != nil || !ok {
		t.Fatalf("granted org: ok=%v err=%v, want ok=true", ok, err)
	}
	if !slices.Contains(roles, "viewer") {
		t.Fatalf("granted org: roles=%v, want it to contain the granted key \"viewer\"", roles)
	}

	// The grant to one org must not authorize a different outsider.
	if _, ok, err := st.AvailableRoles(ctx, proj.ID, outsider.ID); err != nil || ok {
		t.Fatalf("outsider after an unrelated grant: ok=%v err=%v, want ok=false", ok, err)
	}
}

// TestEffectiveRolesIntersectsWithOrgGrant guards the read-time authorization
// boundary in EffectiveRoles: a user's effective roles are always the
// intersection of the roles assigned to them and the roles their organization
// is currently allowed to hand out. This protects two regressions that would
// silently over-grant:
//   - a user whose org holds no access to the project must get no roles, even if
//     a stale user_grant row still names some;
//   - revoking the org's project grant must immediately drop the user's roles on
//     the next resolution, without having to rewrite each user_grant row.
//
// Needs IAM_TEST_DATABASE_URL.
func TestEffectiveRolesIntersectsWithOrgGrant(t *testing.T) {
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
	st := New(pool)

	mkOrg := func(p string) *Org {
		o, err := st.CreateOrg(ctx, p+"-"+uuid.NewString(), p+"-"+uuid.NewString())
		if err != nil {
			t.Fatalf("create org %s: %v", p, err)
		}
		t.Cleanup(func() { pool.Exec(ctx, `DELETE FROM orgs WHERE id = $1`, o.ID) })
		return o
	}
	owner := mkOrg("owner")
	tenant := mkOrg("tenant")

	proj, err := st.CreateProject(ctx, owner.ID, "eff-project")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	for _, key := range []string{"viewer", "editor"} {
		if err := st.AddRole(ctx, proj.ID, Role{Key: key, DisplayName: key}); err != nil {
			t.Fatalf("add role %s: %v", key, err)
		}
	}

	// A user in a tenant org that holds a project grant for only "viewer".
	user, err := st.CreateUser(ctx, NewUser{
		OrgID: tenant.ID, Username: "u-" + uuid.NewString(), Email: uuid.NewString() + "@tenant.test",
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	grant, err := st.CreateProjectGrant(ctx, proj.ID, tenant.ID, []string{"viewer"})
	if err != nil {
		t.Fatalf("create project grant: %v", err)
	}

	// Assign exactly what the org may hand out, then confirm it resolves.
	if _, err := st.CreateUserGrant(ctx, user, proj.ID, []string{"viewer"}); err != nil {
		t.Fatalf("create user grant: %v", err)
	}
	roles, err := st.EffectiveRoles(ctx, user, proj.ID)
	if err != nil {
		t.Fatalf("effective roles: %v", err)
	}
	if !slices.Equal(roles, []string{"viewer"}) {
		t.Fatalf("effective roles = %v, want [viewer]", roles)
	}

	// Widen the org grant to include "editor", then assign both to the user.
	if _, err := st.UpdateProjectGrant(ctx, grant.ID, []string{"viewer", "editor"}); err != nil {
		t.Fatalf("widen project grant: %v", err)
	}
	if _, err := st.UpdateUserGrant(ctx, user, mustUserGrantID(ctx, t, st, user.ID, proj.ID), []string{"viewer", "editor"}); err != nil {
		t.Fatalf("widen user grant: %v", err)
	}
	roles, err = st.EffectiveRoles(ctx, user, proj.ID)
	if err != nil {
		t.Fatalf("effective roles after widen: %v", err)
	}
	slices.Sort(roles)
	if !slices.Equal(roles, []string{"editor", "viewer"}) {
		t.Fatalf("effective roles = %v, want [editor viewer]", roles)
	}

	// Narrow the org grant back to "viewer" without touching the user_grant row.
	// EffectiveRoles must intersect at read time and drop "editor" immediately.
	if _, err := st.UpdateProjectGrant(ctx, grant.ID, []string{"viewer"}); err != nil {
		t.Fatalf("narrow project grant: %v", err)
	}
	roles, err = st.EffectiveRoles(ctx, user, proj.ID)
	if err != nil {
		t.Fatalf("effective roles after narrow: %v", err)
	}
	if !slices.Equal(roles, []string{"viewer"}) {
		t.Fatalf("effective roles after narrow = %v, want [viewer] (editor must be dropped at read time)", roles)
	}

	// Revoke the org's project grant entirely. The user must get no roles: the
	// org has lost all access, so AvailableRoles returns ok=false and
	// EffectiveRoles short-circuits to none without erroring.
	if err := st.DeleteProjectGrant(ctx, grant.ID); err != nil {
		t.Fatalf("delete project grant: %v", err)
	}
	roles, err = st.EffectiveRoles(ctx, user, proj.ID)
	if err != nil {
		t.Fatalf("effective roles after revoke: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("effective roles after revoke = %v, want none (org lost all access)", roles)
	}
}

// mustUserGrantID returns the id of the user's grant on a project, failing the
// test if it is absent.
func mustUserGrantID(ctx context.Context, t *testing.T, st *Store, userID, projectID string) string {
	t.Helper()
	grants, err := st.ListUserGrants(ctx, userID, Page{})
	if err != nil {
		t.Fatalf("list user grants: %v", err)
	}
	for _, g := range grants {
		if g.ProjectID == projectID {
			return g.ID
		}
	}
	t.Fatalf("no user grant for user %s on project %s", userID, projectID)
	return ""
}
