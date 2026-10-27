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
