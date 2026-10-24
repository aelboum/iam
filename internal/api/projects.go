package api

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
)

var roleKeyPattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,64}$`)

// projectForOwner loads a project the caller administers (owner org).
func (s *Server) projectForOwner(r *http.Request, projectID string) (*store.Project, error) {
	p, err := s.store.GetProject(r.Context(), projectID)
	if err != nil {
		return nil, err
	}
	if !principalFrom(r.Context()).canAccessOrg(p.OwnerOrgID) {
		// Granted orgs may know the project exists (403); anyone else gets
		// the same 404 as for a missing project, so IDs cannot be probed.
		if _, err := s.projectForReader(r, projectID); err != nil {
			return nil, err
		}
		return nil, errForbidden
	}
	return p, nil
}

// projectForReader loads a project the caller owns or has been granted.
func (s *Server) projectForReader(r *http.Request, projectID string) (*store.Project, error) {
	p, err := s.store.GetProject(r.Context(), projectID)
	if err != nil {
		return nil, err
	}
	pr := principalFrom(r.Context())
	if pr.canAccessOrg(p.OwnerOrgID) {
		return p, nil
	}
	if _, ok, err := s.store.AvailableRoles(r.Context(), p.ID, *pr.key.OrgID); err != nil {
		return nil, err
	} else if !ok {
		return nil, store.ErrNotFound
	}
	return p, nil
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := validName("name", body.Name); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.checkQuota(r, store.QuotaProjectsPerOrg, chi.URLParam(r, "orgID")); err != nil {
		fail(w, r, err)
		return
	}
	p, err := s.store.CreateProject(r.Context(), chi.URLParam(r, "orgID"), body.Name)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, p.OwnerOrgID, "project.created", "project:"+p.ID, map[string]any{"name": p.Name})
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.store.ListProjects(r.Context(), chi.URLParam(r, "orgID"), pageFrom(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, projects)
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	p, err := s.projectForReader(r, chi.URLParam(r, "projectID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	p, err := s.projectForOwner(r, chi.URLParam(r, "projectID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	// Revoke first: the token lookup needs the project's apps to still exist.
	if err := s.store.RevokeProjectTokens(r.Context(), p.ID, ""); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.DeleteProject(r.Context(), p.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, p.OwnerOrgID, "project.deleted", "project:"+p.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- roles ------------------------------------------------------------------------------

func (s *Server) listRoles(w http.ResponseWriter, r *http.Request) {
	p, err := s.projectForReader(r, chi.URLParam(r, "projectID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	roles, err := s.store.ListRoles(r.Context(), p.ID)
	if err != nil {
		fail(w, r, err)
		return
	}
	// A granted org only sees the roles it was granted, not the vendor's full set.
	if pr := principalFrom(r.Context()); !pr.canAccessOrg(p.OwnerOrgID) {
		granted, _, err := s.store.AvailableRoles(r.Context(), p.ID, *pr.key.OrgID)
		if err != nil {
			fail(w, r, err)
			return
		}
		visible := []store.Role{}
		for _, role := range roles {
			if slices.Contains(granted, role.Key) {
				visible = append(visible, role)
			}
		}
		roles = visible
	}
	writeJSON(w, http.StatusOK, roles)
}

func (s *Server) addRole(w http.ResponseWriter, r *http.Request) {
	p, err := s.projectForOwner(r, chi.URLParam(r, "projectID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	var role store.Role
	if !decode(w, r, &role) {
		return
	}
	if !roleKeyPattern.MatchString(role.Key) {
		fail(w, r, validationError("key must be 1-64 chars of a-z, A-Z, 0-9, '_', '.', ':', '-'"))
		return
	}
	if len(role.DisplayName) > maxNameLength {
		fail(w, r, validationError("display_name is too long"))
		return
	}
	if err := s.checkQuota(r, store.QuotaRolesPerProject, p.ID); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.AddRole(r.Context(), p.ID, role); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, p.OwnerOrgID, "role.created", "project:"+p.ID, map[string]any{"role": role.Key})
	writeJSON(w, http.StatusCreated, role)
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	p, err := s.projectForOwner(r, chi.URLParam(r, "projectID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.DeleteRole(r.Context(), p.ID, chi.URLParam(r, "roleKey")); err != nil {
		fail(w, r, err)
		return
	}
	// Tokens may carry the removed role; end them so the change applies now.
	if err := s.store.RevokeProjectTokens(r.Context(), p.ID, ""); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, p.OwnerOrgID, "role.deleted", "project:"+p.ID, map[string]any{"role": chi.URLParam(r, "roleKey")})
	w.WriteHeader(http.StatusNoContent)
}

// --- apps ---------------------------------------------------------------------------------

func (s *Server) createApp(w http.ResponseWriter, r *http.Request) {
	p, err := s.projectForOwner(r, chi.URLParam(r, "projectID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	var body struct {
		Name                   string   `json:"name"`
		AppType                string   `json:"app_type"`
		AuthMethod             string   `json:"auth_method"`
		RedirectURIs           []string `json:"redirect_uris"`
		PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
		AccessTokenType        string   `json:"access_token_type"`
		LoginURL               string   `json:"login_url"`
		DevMode                bool     `json:"dev_mode"`
	}
	if !decode(w, r, &body) {
		return
	}
	app := store.App{
		ProjectID:              p.ID,
		Name:                   strings.TrimSpace(body.Name),
		ClientID:               secret.Token(16),
		AppType:                body.AppType,
		AuthMethod:             body.AuthMethod,
		RedirectURIs:           body.RedirectURIs,
		PostLogoutRedirectURIs: body.PostLogoutRedirectURIs,
		AccessTokenType:        body.AccessTokenType,
		LoginURL:               body.LoginURL,
		DevMode:                body.DevMode,
	}
	if app.DevMode && !s.devMode {
		// dev_mode lets the provider accept plain-http redirect URIs.
		fail(w, r, validationError("dev_mode apps are only allowed when the engine runs with IAM_DEV_MODE=true"))
		return
	}
	if err := normalizeApp(&app, s.devMode); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.checkQuota(r, store.QuotaAppsPerProject, p.ID); err != nil {
		fail(w, r, err)
		return
	}

	var clientSecret string
	if app.AuthMethod != "none" {
		clientSecret = secret.Token(32)
		hash, err := s.authn.HashSecret(clientSecret)
		if err != nil {
			fail(w, r, err)
			return
		}
		app.ClientSecretHash = &hash
	}
	created, err := s.store.CreateApp(r.Context(), app)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, p.OwnerOrgID, "app.created", "app:"+created.ID, map[string]any{"client_id": created.ClientID})
	writeJSON(w, http.StatusCreated, struct {
		*store.App
		ClientSecret string `json:"client_secret,omitempty"`
	}{created, clientSecret})
}

// normalizeApp applies defaults and validates an app definition.
func normalizeApp(a *store.App, devMode bool) error {
	if err := validName("name", a.Name); err != nil {
		return err
	}
	if err := validList("redirect_uris", a.RedirectURIs); err != nil {
		return err
	}
	if err := validList("post_logout_redirect_uris", a.PostLogoutRedirectURIs); err != nil {
		return err
	}
	switch a.AppType {
	case "web":
		if a.AuthMethod == "" {
			a.AuthMethod = "client_secret_basic"
		}
		if a.AuthMethod != "client_secret_basic" && a.AuthMethod != "client_secret_post" {
			return validationError("web apps use auth_method client_secret_basic or client_secret_post")
		}
	case "spa", "native":
		// Public clients cannot keep a secret; they must use PKCE.
		if a.AuthMethod != "" && a.AuthMethod != "none" {
			return validationError("spa and native apps use auth_method none (PKCE)")
		}
		a.AuthMethod = "none"
	default:
		return validationError("app_type must be web, spa or native")
	}
	switch a.AccessTokenType {
	case "":
		a.AccessTokenType = "jwt"
	case "jwt", "bearer":
	default:
		return validationError("access_token_type must be jwt or bearer")
	}
	if len(a.RedirectURIs) == 0 {
		return validationError("at least one redirect_uri is required")
	}
	for _, u := range a.RedirectURIs {
		if !redirectURLAllowed(u, a.AppType == "native", devMode) {
			return validationError("invalid redirect_uri (https required; http only for localhost native apps or in dev mode): " + u)
		}
	}
	if a.PostLogoutRedirectURIs == nil {
		a.PostLogoutRedirectURIs = []string{}
	}
	for _, u := range a.PostLogoutRedirectURIs {
		if !redirectURLAllowed(u, a.AppType == "native", devMode) {
			return validationError("invalid post_logout_redirect_uri: " + u)
		}
	}
	if !redirectURLAllowed(a.LoginURL, false, devMode) {
		return validationError("login_url must be an https URL of your login UI")
	}
	return nil
}

// redirectURLAllowed accepts https URLs. Plain http is accepted in dev mode,
// or for native apps on a loopback host (RFC 8252). Native apps may also use
// private custom schemes (com.example.app:/callback). Fragments, credentials
// and script-like schemes are always refused.
func redirectURLAllowed(raw string, native, devMode bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Fragment != "" || u.User != nil || len(raw) > 2048 {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return u.Host != ""
	case "http":
		host := u.Hostname()
		loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
		return u.Host != "" && (devMode || (native && loopback))
	case "javascript", "data", "vbscript", "file", "blob", "about":
		return false
	default:
		return native && strings.Contains(u.Scheme, ".") // reverse-domain custom scheme
	}
}

func (s *Server) listApps(w http.ResponseWriter, r *http.Request) {
	p, err := s.projectForOwner(r, chi.URLParam(r, "projectID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	apps, err := s.store.ListApps(r.Context(), p.ID, pageFrom(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, apps)
}

func (s *Server) appForOwner(r *http.Request) (*store.App, error) {
	app, err := s.store.GetApp(r.Context(), chi.URLParam(r, "appID"))
	if err != nil {
		return nil, err
	}
	if _, err := s.projectForOwner(r, app.ProjectID); err != nil {
		return nil, err
	}
	return app, nil
}

func (s *Server) getApp(w http.ResponseWriter, r *http.Request) {
	app, err := s.appForOwner(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (s *Server) deleteApp(w http.ResponseWriter, r *http.Request) {
	app, err := s.appForOwner(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.RevokeAppTokens(r.Context(), app.ID); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.DeleteApp(r.Context(), app.ID); err != nil {
		fail(w, r, err)
		return
	}
	if p, err := s.store.GetProject(r.Context(), app.ProjectID); err == nil {
		s.audit(r, p.OwnerOrgID, "app.deleted", "app:"+app.ID, map[string]any{"client_id": app.ClientID})
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- project grants ------------------------------------------------------------------------

func (s *Server) listProjectGrants(w http.ResponseWriter, r *http.Request) {
	p, err := s.projectForOwner(r, chi.URLParam(r, "projectID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	grants, err := s.store.ListProjectGrants(r.Context(), p.ID, "", pageFrom(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

// createProjectGrant onboards a customer org onto the project.
func (s *Server) createProjectGrant(w http.ResponseWriter, r *http.Request) {
	p, err := s.projectForOwner(r, chi.URLParam(r, "projectID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	var body struct {
		OrgID    string   `json:"org_id"`
		RoleKeys []string `json:"role_keys"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.RoleKeys == nil {
		body.RoleKeys = []string{}
	}
	if err := validList("role_keys", body.RoleKeys); err != nil {
		fail(w, r, err)
		return
	}
	grant, err := s.store.CreateProjectGrant(r.Context(), p.ID, body.OrgID, body.RoleKeys)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, grant.GrantedOrgID, "project_grant.created", "project:"+p.ID, map[string]any{"roles": grant.RoleKeys})
	writeJSON(w, http.StatusCreated, grant)
}

func (s *Server) projectGrantForOwner(r *http.Request) (*store.ProjectGrant, error) {
	grant, err := s.store.GetProjectGrant(r.Context(), chi.URLParam(r, "grantID"))
	if err != nil {
		return nil, err
	}
	if _, err := s.projectForOwner(r, grant.ProjectID); err != nil {
		return nil, err
	}
	return grant, nil
}

func (s *Server) updateProjectGrant(w http.ResponseWriter, r *http.Request) {
	grant, err := s.projectGrantForOwner(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	var body struct {
		RoleKeys []string `json:"role_keys"`
	}
	if !decode(w, r, &body) {
		return
	}
	if body.RoleKeys == nil {
		body.RoleKeys = []string{}
	}
	if err := validList("role_keys", body.RoleKeys); err != nil {
		fail(w, r, err)
		return
	}
	updated, err := s.store.UpdateProjectGrant(r.Context(), grant.ID, body.RoleKeys)
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.RevokeProjectTokens(r.Context(), grant.ProjectID, grant.GrantedOrgID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, updated.GrantedOrgID, "project_grant.updated", "project:"+updated.ProjectID, map[string]any{"roles": updated.RoleKeys})
	writeJSON(w, http.StatusOK, updated)
}

// deleteProjectGrant can be called by the project owner, or by the granted
// org itself to leave a project it no longer wants access to.
func (s *Server) deleteProjectGrant(w http.ResponseWriter, r *http.Request) {
	grant, err := s.store.GetProjectGrant(r.Context(), chi.URLParam(r, "grantID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if !principalFrom(r.Context()).canAccessOrg(grant.GrantedOrgID) {
		if _, err := s.projectForOwner(r, grant.ProjectID); err != nil {
			fail(w, r, err)
			return
		}
	}
	if err := s.store.DeleteProjectGrant(r.Context(), grant.ID); err != nil {
		fail(w, r, err)
		return
	}
	// Tokens the org's users hold for the project's apps stop working now.
	if err := s.store.RevokeProjectTokens(r.Context(), grant.ProjectID, grant.GrantedOrgID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, grant.GrantedOrgID, "project_grant.deleted", "project:"+grant.ProjectID, nil)
	w.WriteHeader(http.StatusNoContent)
}
