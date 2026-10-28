package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/authn"
	"github.com/aelboum/iam/internal/db"
	"github.com/aelboum/iam/internal/ratelimit"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests drive the management handlers directly (bypassing the auth
// middleware with a hand-built admin principal) to verify the handler->store
// token-revocation wiring and its scoping: a grant or user change must revoke
// exactly the intended tokens, a failed change must not report success or
// revoke anything, and no other org, project or user may be affected. The
// store-level scoping of the revocation itself is pinned in the store package;
// here the subject is the handler wiring. Needs IAM_TEST_DATABASE_URL.

// adminReq builds a request carrying an admin principal, the given chi URL
// params, and an optional JSON body.
func adminReq(t *testing.T, params map[string]string, body any) *http.Request {
	t.Helper()
	var r *http.Request
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(buf))
	} else {
		r = httptest.NewRequest(http.MethodPost, "/", nil)
	}
	r.RemoteAddr = "127.0.0.1:1234"
	rctx := chi.NewRouteContext()
	for k, v := range params {
		rctx.URLParams.Add(k, v)
	}
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	// An admin key has a nil OrgID, so canAccessOrg is true for every org.
	ctx = context.WithValue(ctx, principalKey{}, &principal{key: &store.APIKey{ID: uuid.NewString()}})
	return r.WithContext(ctx)
}

func revocationTestStore(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("IAM_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set IAM_TEST_DATABASE_URL to a disposable database to run this test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return store.New(pool), pool
}

func TestProjectGrantHandlersRevokeScopedTokens(t *testing.T) {
	st, pool := revocationTestStore(t)
	srv := &Server{store: st}
	h := newRevHelper(t, st, pool)

	owner := h.org("owner")
	tenantX := h.org("tenant-x")
	tenantY := h.org("tenant-y")
	projP := h.project(owner, "P")
	projQ := h.project(owner, "Q")
	clientP := h.app(projP)
	clientQ := h.app(projQ)
	grantXP := h.grant(projP, tenantX)
	h.grant(projP, tenantY)
	h.grant(projQ, tenantX)
	userX := h.user(tenantX)
	userY := h.user(tenantY)

	// issue returns the four tokens the scoping assertions track: tenant X on
	// project P (via the app client and via the project scope), tenant Y on the
	// same project P, and tenant X on a different project Q.
	issue := func() (xp, xpScope, yp, xq tokenPair) {
		xp = h.token(clientP, userX.ID, nil)
		xpScope = h.token("machine-"+uuid.NewString(), userX.ID, []string{"urn:iam:project:" + projP.ID})
		yp = h.token(clientP, userY.ID, nil)
		xq = h.token(clientQ, userX.ID, nil)
		return
	}

	// updateProjectGrant (narrow to no roles) via the real handler.
	xp, xpScope, yp, xq := issue()
	rec := httptest.NewRecorder()
	srv.updateProjectGrant(rec, adminReq(t, map[string]string{"grantID": grantXP.ID}, map[string]any{"role_keys": []string{}}))
	if rec.Code != http.StatusOK {
		t.Fatalf("updateProjectGrant: status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	h.mustGone("update", xp, xpScope)
	h.mustAlive("update", yp, xq)

	// deleteProjectGrant via the real handler.
	xp, xpScope, yp, xq = issue()
	rec = httptest.NewRecorder()
	srv.deleteProjectGrant(rec, adminReq(t, map[string]string{"grantID": grantXP.ID}, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("deleteProjectGrant: status=%d body=%s, want 204", rec.Code, rec.Body.String())
	}
	h.mustGone("delete", xp, xpScope)
	h.mustAlive("delete", yp, xq)

	// Error path: a grant change that fails (missing grant) must not report
	// success and must not revoke any tokens.
	keep := h.token(clientQ, userX.ID, nil)
	rec = httptest.NewRecorder()
	srv.updateProjectGrant(rec, adminReq(t, map[string]string{"grantID": uuid.NewString()}, map[string]any{"role_keys": []string{"viewer"}}))
	if rec.Code >= 200 && rec.Code < 300 {
		t.Fatalf("updateProjectGrant on a missing grant: status=%d, want a non-2xx error", rec.Code)
	}
	if !h.alive(keep) {
		t.Error("error path: a failed grant change must not revoke any tokens")
	}
}

func TestUserLockAndDeleteRevokeOnlyThatUsersTokens(t *testing.T) {
	st, pool := revocationTestStore(t)
	srv := &Server{store: st}
	h := newRevHelper(t, st, pool)

	org := h.org("org")
	proj := h.project(org, "P")
	client := h.app(proj)
	userA := h.user(org)
	userB := h.user(org)

	// lockUser revokes user A's tokens, leaves user B untouched.
	a := h.token(client, userA.ID, nil)
	b := h.token(client, userB.ID, nil)
	rec := httptest.NewRecorder()
	srv.lockUser(rec, adminReq(t, map[string]string{"userID": userA.ID}, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("lockUser: status=%d body=%s, want 204", rec.Code, rec.Body.String())
	}
	h.mustGone("lock", a)
	h.mustAlive("lock", b)
	if u, err := st.GetUser(context.Background(), userA.ID); err != nil || !u.Locked {
		t.Fatalf("lockUser: user A locked state wrong (err=%v), want locked", err)
	}

	// deleteUser revokes the deleted user's tokens, leaves another user's.
	a2 := h.token(client, userA.ID, nil)
	b2 := h.token(client, userB.ID, nil)
	rec = httptest.NewRecorder()
	srv.deleteUser(rec, adminReq(t, map[string]string{"userID": userA.ID}, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("deleteUser: status=%d body=%s, want 204", rec.Code, rec.Body.String())
	}
	h.mustGone("delete", a2)
	h.mustAlive("delete", b2)

	// Error path: deleting a missing user must not report success or revoke.
	keep := h.token(client, userB.ID, nil)
	rec = httptest.NewRecorder()
	srv.deleteUser(rec, adminReq(t, map[string]string{"userID": uuid.NewString()}, nil))
	if rec.Code >= 200 && rec.Code < 300 {
		t.Fatalf("deleteUser on a missing user: status=%d, want a non-2xx error", rec.Code)
	}
	if !h.alive(keep) {
		t.Error("error path: a failed delete must not revoke any tokens")
	}
}

func TestSetPasswordHandlerRevokesOnlyTargetUser(t *testing.T) {
	st, pool := revocationTestStore(t)
	svc := authn.NewService(st, secret.NewBox([32]byte{23}), authn.Config{
		Limits:          ratelimit.Memory,
		SessionLifetime: time.Hour,
		MaxFailedLogins: 5,
		HashWaitTimeout: time.Second,
		OrgLoginLimit:   1000,
	})
	srv := &Server{store: st, authn: svc}
	h := newRevHelper(t, st, pool)

	org := h.org("org")
	proj := h.project(org, "P")
	client := h.app(proj)
	userA := h.user(org)
	userB := h.user(org)

	a := h.token(client, userA.ID, nil)
	b := h.token(client, userB.ID, nil)
	rec := httptest.NewRecorder()
	// The new password must not contain the username or email.
	srv.setPassword(rec, adminReq(t, map[string]string{"userID": userA.ID}, map[string]any{"password": "Str0ng-Passphrase-Qw7"}))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("setPassword: status=%d body=%s, want 204", rec.Code, rec.Body.String())
	}
	h.mustGone("setPassword", a)
	h.mustAlive("setPassword", b)

	// Error path: an invalid password is rejected and revokes nothing.
	keepA := h.token(client, userA.ID, nil)
	rec = httptest.NewRecorder()
	srv.setPassword(rec, adminReq(t, map[string]string{"userID": userA.ID}, map[string]any{"password": "short"}))
	if rec.Code >= 200 && rec.Code < 300 {
		t.Fatalf("setPassword with a weak password: status=%d, want a non-2xx error", rec.Code)
	}
	if !h.alive(keepA) {
		t.Error("error path: a rejected password change must not revoke any tokens")
	}
}

func TestDeleteOrgHandlerRevokesOnlyThatOrgsTokens(t *testing.T) {
	st, pool := revocationTestStore(t)
	srv := &Server{store: st}
	h := newRevHelper(t, st, pool)

	// Two orgs, each with a user and a token issued to the org's app.
	orgDel := h.org("to-delete")
	orgKeep := h.org("to-keep")
	projDel := h.project(orgDel, "D")
	projKeep := h.project(orgKeep, "K")
	clientDel := h.app(projDel)
	clientKeep := h.app(projKeep)
	userDel := h.user(orgDel)
	userKeep := h.user(orgKeep)

	victim := h.token(clientDel, userDel.ID, nil)
	survivor := h.token(clientKeep, userKeep.ID, nil)

	rec := httptest.NewRecorder()
	srv.deleteOrg(rec, adminReq(t, map[string]string{"orgID": orgDel.ID}, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("deleteOrg: status=%d body=%s, want 204", rec.Code, rec.Body.String())
	}
	h.mustGone("delete-org", victim)
	h.mustAlive("delete-org", survivor)
	if _, err := st.GetOrg(context.Background(), orgDel.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted org still present: err=%v, want ErrNotFound", err)
	}

	// Error path: deleting a non-existent org must report a non-2xx error and
	// must not revoke the surviving org's tokens. RevokeOrgTokens runs first and
	// matches no users, then DeleteOrg fails with ErrNotFound.
	rec = httptest.NewRecorder()
	srv.deleteOrg(rec, adminReq(t, map[string]string{"orgID": uuid.NewString()}, nil))
	if rec.Code >= 200 && rec.Code < 300 {
		t.Fatalf("deleteOrg on a missing org: status=%d, want a non-2xx error", rec.Code)
	}
	h.mustAlive("delete-missing-org", survivor)
}

func TestDeleteAppHandlerRevokesOnlyThatAppsTokens(t *testing.T) {
	st, pool := revocationTestStore(t)
	srv := &Server{store: st}
	h := newRevHelper(t, st, pool)

	// One project holds the app under deletion plus a sibling app; a second
	// project in a different tenant holds an unrelated app.
	owner := h.org("owner")
	other := h.org("other-tenant")
	projP := h.project(owner, "P")
	projOther := h.project(other, "O")

	appDel := h.appRow(projP)       // the app being deleted
	appSibling := h.appRow(projP)   // second app, same project, different client_id
	appOther := h.appRow(projOther) // app in another project and tenant

	user := h.user(owner)
	userOther := h.user(other)

	victim := h.token(appDel.ClientID, user.ID, nil)
	sibling := h.token(appSibling.ClientID, user.ID, nil)
	foreign := h.token(appOther.ClientID, userOther.ID, nil)

	rec := httptest.NewRecorder()
	srv.deleteApp(rec, adminReq(t, map[string]string{"appID": appDel.ID}, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("deleteApp: status=%d body=%s, want 204", rec.Code, rec.Body.String())
	}
	h.mustGone("delete-app", victim)
	h.mustAlive("delete-app", sibling, foreign)
	if _, err := st.GetApp(context.Background(), appDel.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("deleted app still present: err=%v, want ErrNotFound", err)
	}

	// Error path: deleting a missing app fails at the lookup (appForOwner),
	// before RevokeAppTokens runs, so a surviving app's tokens stay intact and
	// the handler must report a non-2xx error.
	keep := h.token(appSibling.ClientID, user.ID, nil)
	rec = httptest.NewRecorder()
	srv.deleteApp(rec, adminReq(t, map[string]string{"appID": uuid.NewString()}, nil))
	if rec.Code >= 200 && rec.Code < 300 {
		t.Fatalf("deleteApp on a missing app: status=%d, want a non-2xx error", rec.Code)
	}
	h.mustAlive("delete-missing-app", keep)
}

// --- test helper ------------------------------------------------------------

type revHelper struct {
	t    *testing.T
	st   *store.Store
	pool *pgxpool.Pool
	ctx  context.Context
}

func newRevHelper(t *testing.T, st *store.Store, pool *pgxpool.Pool) *revHelper {
	return &revHelper{t: t, st: st, pool: pool, ctx: context.Background()}
}

func (h *revHelper) org(prefix string) *store.Org {
	o, err := h.st.CreateOrg(h.ctx, prefix+"-"+uuid.NewString(), prefix+"-"+uuid.NewString())
	if err != nil {
		h.t.Fatalf("create org %s: %v", prefix, err)
	}
	h.t.Cleanup(func() { h.pool.Exec(h.ctx, `DELETE FROM orgs WHERE id = $1`, o.ID) })
	return o
}

func (h *revHelper) project(owner *store.Org, name string) *store.Project {
	p, err := h.st.CreateProject(h.ctx, owner.ID, name+"-"+uuid.NewString())
	if err != nil {
		h.t.Fatalf("create project %s: %v", name, err)
	}
	if err := h.st.AddRole(h.ctx, p.ID, store.Role{Key: "viewer", DisplayName: "Viewer"}); err != nil {
		h.t.Fatalf("add role: %v", err)
	}
	return p
}

func (h *revHelper) app(proj *store.Project) string { return h.appRow(proj).ClientID }

func (h *revHelper) appRow(proj *store.Project) *store.App {
	clientID := "client-" + uuid.NewString()
	a, err := h.st.CreateApp(h.ctx, store.App{
		ProjectID: proj.ID, Name: "app", ClientID: clientID, AppType: "web",
		AuthMethod: "none", AccessTokenType: "bearer",
		RedirectURIs: []string{}, PostLogoutRedirectURIs: []string{},
	})
	if err != nil {
		h.t.Fatalf("create app: %v", err)
	}
	return a
}

func (h *revHelper) grant(proj *store.Project, org *store.Org) *store.ProjectGrant {
	g, err := h.st.CreateProjectGrant(h.ctx, proj.ID, org.ID, []string{"viewer"})
	if err != nil {
		h.t.Fatalf("create project grant: %v", err)
	}
	return g
}

func (h *revHelper) user(org *store.Org) *store.User {
	u, err := h.st.CreateUser(h.ctx, store.NewUser{
		OrgID: org.ID, Username: "u-" + uuid.NewString(), Email: uuid.NewString() + "@t.test",
	})
	if err != nil {
		h.t.Fatalf("create user: %v", err)
	}
	return u
}

type tokenPair struct{ at, rt string }

func (h *revHelper) token(clientID, subject string, scopes []string) tokenPair {
	if scopes == nil {
		scopes = []string{}
	}
	atID, rtID := uuid.NewString(), uuid.NewString()
	at := &store.AccessToken{
		ID: atID, ClientID: clientID, Subject: subject, Audience: []string{clientID},
		Scopes: scopes, RefreshTokenID: &rtID, ExpiresAt: time.Now().Add(time.Hour),
	}
	rt := &store.RefreshToken{
		ID: rtID, TokenHash: uuid.NewString(), ClientID: clientID, Subject: subject,
		Audience: []string{clientID}, Scopes: scopes, AMR: []string{}, AuthTime: time.Now(),
		AccessTokenID: &atID, ExpiresAt: time.Now().Add(24 * time.Hour), FamilyID: uuid.NewString(),
	}
	if err := h.st.CreateTokens(h.ctx, at, rt); err != nil {
		h.t.Fatalf("create tokens: %v", err)
	}
	return tokenPair{atID, rtID}
}

func (h *revHelper) alive(p tokenPair) bool {
	_, aerr := h.st.GetAccessToken(h.ctx, p.at)
	_, rerr := h.st.GetRefreshTokenByID(h.ctx, p.rt)
	switch {
	case aerr == nil && rerr == nil:
		return true
	case errors.Is(aerr, store.ErrNotFound) && errors.Is(rerr, store.ErrNotFound):
		return false
	default:
		h.t.Fatalf("inconsistent token state: access err=%v refresh err=%v", aerr, rerr)
		return false
	}
}

func (h *revHelper) mustGone(label string, ps ...tokenPair) {
	for i, p := range ps {
		if h.alive(p) {
			h.t.Errorf("%s: token %d should have been revoked", label, i)
		}
	}
}

func (h *revHelper) mustAlive(label string, ps ...tokenPair) {
	for i, p := range ps {
		if !h.alive(p) {
			h.t.Errorf("%s: token %d must survive (wrong org/project/user revoked)", label, i)
		}
	}
}
