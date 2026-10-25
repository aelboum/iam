package api

import (
	"fmt"
	"github.com/aelboum/iam/internal/authn"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
)

var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

func (s *Server) createOrg(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if !decode(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if err := validName("name", body.Name); err != nil {
		fail(w, r, err)
		return
	}
	if !slugPattern.MatchString(body.Slug) {
		fail(w, r, validationError("slug must be 2-63 chars of a-z, 0-9 and '-'"))
		return
	}
	org, err := s.store.CreateOrg(r.Context(), body.Name, body.Slug)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, org.ID, "org.created", "org:"+org.ID, map[string]any{"slug": org.Slug})
	writeJSON(w, http.StatusCreated, org)
}

func (s *Server) listOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.store.ListOrgs(r.Context(), pageFrom(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, orgs)
}

func (s *Server) getOrg(w http.ResponseWriter, r *http.Request) {
	org, err := s.store.GetOrg(r.Context(), chi.URLParam(r, "orgID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (s *Server) deleteOrg(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "orgID")
	// Revoke first: the token lookup needs the org's users to still exist.
	if err := s.store.RevokeOrgTokens(r.Context(), id); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.DeleteOrg(r.Context(), id); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, "", "org.deleted", "org:"+id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- API keys -------------------------------------------------------------------------------

const (
	defaultOrgKeyDays = 90
	maxOrgKeyDays     = 365
)

type apiKeyRequest struct {
	Name string `json:"name"`
	// admin (management API) or login (session API only, for login UI backends).
	Scope string `json:"scope"`
	// Optional lifetime; the key stops working afterwards.
	ExpiresInDays int `json:"expires_in_days"`
}

func (s *Server) issueAPIKey(w http.ResponseWriter, r *http.Request, orgID *string) {
	var body apiKeyRequest
	if !decode(w, r, &body) {
		return
	}
	if err := validName("name", body.Name); err != nil {
		fail(w, r, err)
		return
	}
	caller := principalFrom(r.Context())
	if !caller.isAdmin() {
		// Tenant keys must expire, so a leaked one cannot live forever.
		if body.ExpiresInDays == 0 {
			body.ExpiresInDays = defaultOrgKeyDays
		}
		if body.ExpiresInDays > maxOrgKeyDays {
			fail(w, r, validationError(fmt.Sprintf("org keys may live at most %d days", maxOrgKeyDays)))
			return
		}
	}
	if orgID != nil {
		if err := s.checkQuota(r, store.QuotaKeysPerOrg, *orgID); err != nil {
			fail(w, r, err)
			return
		}
	}
	if body.Scope == "" {
		body.Scope = store.ScopeAdmin
	}
	if body.Scope != store.ScopeAdmin && body.Scope != store.ScopeLogin {
		fail(w, r, validationError("scope must be admin or login"))
		return
	}
	if body.ExpiresInDays < 0 || body.ExpiresInDays > 3650 {
		fail(w, r, validationError("expires_in_days must be between 0 and 3650"))
		return
	}
	var expires *time.Time
	if body.ExpiresInDays > 0 {
		t := time.Now().Add(time.Duration(body.ExpiresInDays) * 24 * time.Hour)
		expires = &t
	}
	raw := "iam_" + secret.Token(32)
	key, err := s.store.CreateAPIKey(r.Context(), body.Name, orgID, body.Scope, expires, secret.Hash(raw), &caller.key.ID)
	if err != nil {
		fail(w, r, err)
		return
	}
	org := ""
	if orgID != nil {
		org = *orgID
	}
	s.audit(r, org, "api_key.created", "api_key:"+key.ID, map[string]any{"name": key.Name, "scope": key.Scope})
	writeJSON(w, http.StatusCreated, struct {
		*store.APIKey
		Key string `json:"key"`
	}{key, raw})
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request, orgID *string) {
	keys, err := s.store.ListAPIKeys(r.Context(), orgID, pageFrom(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) revokeKey(w http.ResponseWriter, r *http.Request, orgID *string) {
	id := chi.URLParam(r, "keyID")
	if id == principalFrom(r.Context()).key.ID {
		fail(w, r, validationError("an API key cannot delete itself"))
		return
	}
	if err := s.store.DeleteAPIKey(r.Context(), orgID, id); err != nil {
		fail(w, r, err)
		return
	}
	org := ""
	if orgID != nil {
		org = *orgID
	}
	s.audit(r, org, "api_key.deleted", "api_key:"+id, nil)
	w.WriteHeader(http.StatusNoContent)
}

// Org-scoped keys let a customer org administer its own users (delegated administration).
func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s.issueAPIKey(w, r, &orgID)
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s.listKeys(w, r, &orgID)
}

func (s *Server) deleteAPIKey(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s.revokeKey(w, r, &orgID)
}

// Instance keys work across all orgs.
func (s *Server) createInstanceAPIKey(w http.ResponseWriter, r *http.Request) {
	s.issueAPIKey(w, r, nil)
}
func (s *Server) listInstanceAPIKeys(w http.ResponseWriter, r *http.Request)  { s.listKeys(w, r, nil) }
func (s *Server) deleteInstanceAPIKey(w http.ResponseWriter, r *http.Request) { s.revokeKey(w, r, nil) }

// --- audit ------------------------------------------------------------------------------------

func (s *Server) writeAudit(w http.ResponseWriter, r *http.Request, orgID *string) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	events, err := s.store.ListAudit(r.Context(), orgID, before, limit)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) { s.writeAudit(w, r, nil) }

func (s *Server) listOrgAudit(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	s.writeAudit(w, r, &orgID)
}

// --- identity providers (per-org SSO) --------------------------------------------------------

func (s *Server) createIDP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		// ProviderType: "oidc" (default, generic), "google", "microsoft"
		// (personal MSA), or "entra". For a preset the issuer is pinned by the
		// engine and Issuer must be omitted; Tenant is the Entra directory GUID.
		ProviderType    string   `json:"provider_type"`
		Tenant          string   `json:"tenant"`
		Issuer          string   `json:"issuer"`
		ClientID        string   `json:"client_id"`
		ClientSecret    string   `json:"client_secret"`
		Scopes          []string `json:"scopes"`
		AutoCreateUsers bool     `json:"auto_create_users"` // default false (audit M11)
		LinkByEmail     bool     `json:"link_by_email"`
		// Instance admin only (audit M2, D1).
		TrustEmail          bool     `json:"trust_email"`
		TrustMFA            bool     `json:"trust_mfa"`
		AllowedEmailDomains []string `json:"allowed_email_domains"`
	}
	if !decode(w, r, &body) {
		return
	}
	orgID := chi.URLParam(r, "orgID")
	if err := validName("name", body.Name); err != nil {
		fail(w, r, err)
		return
	}
	if body.ProviderType == "" {
		body.ProviderType = authn.ProviderOIDC
	}
	if !authn.KnownProviderType(body.ProviderType) {
		fail(w, r, validationError("provider_type must be one of: oidc, google, microsoft, entra"))
		return
	}
	// Normalize the tenant once, so the stored value matches the pinned issuer
	// (lowercased) and cannot be whitespace-padded.
	body.Tenant = strings.ToLower(strings.TrimSpace(body.Tenant))
	// Resolve the issuer. For a preset the engine pins it from the provider
	// type and tenant, so an org admin cannot point the provider at an
	// arbitrary issuer; for a generic provider the admin supplies it.
	issuer := strings.TrimRight(body.Issuer, "/")
	if body.ProviderType == authn.ProviderOIDC {
		if body.Tenant != "" {
			fail(w, r, validationError("tenant is only used with provider_type=entra"))
			return
		}
		if !redirectURLAllowed(issuer, false, s.devMode) {
			fail(w, r, validationError("issuer must be an https URL"))
			return
		}
	} else {
		if body.Issuer != "" {
			fail(w, r, validationError("issuer is set automatically for this provider_type; omit it"))
			return
		}
		pinned, err := authn.ProviderIssuer(body.ProviderType, body.Tenant)
		if err != nil {
			fail(w, r, validationError(err.Error()))
			return
		}
		issuer = pinned
	}
	if (body.TrustEmail || body.TrustMFA) && !principalFrom(r.Context()).isAdmin() {
		fail(w, r, validationError("only an instance admin can set trust_email or trust_mfa"))
		return
	}
	if body.LinkByEmail && !body.TrustEmail {
		fail(w, r, validationError("link_by_email requires trust_email (set by an instance admin)"))
		return
	}
	domains, err := normalizeDomains(body.AllowedEmailDomains)
	if err != nil {
		fail(w, r, err)
		return
	}
	if body.ClientID == "" || body.ClientSecret == "" || len(body.ClientID) > 256 || len(body.ClientSecret) > 1024 {
		fail(w, r, validationError("client_id and client_secret are required"))
		return
	}
	body.Scopes = authn.ProviderScopes(body.Scopes)
	if err := validList("scopes", body.Scopes); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.checkQuota(r, store.QuotaIDPsPerOrg, orgID); err != nil {
		fail(w, r, err)
		return
	}
	idp, err := s.store.CreateIDP(r.Context(), store.IDP{
		OrgID: orgID, Name: body.Name, ProviderType: body.ProviderType, Tenant: body.Tenant,
		Issuer: issuer, ClientID: body.ClientID,
		ClientSecretEnc: s.box.Seal([]byte(body.ClientSecret)), Scopes: body.Scopes,
		AutoCreateUsers: body.AutoCreateUsers, LinkByEmail: body.LinkByEmail,
		TrustEmail: body.TrustEmail, TrustMFA: body.TrustMFA, AllowedEmailDomains: domains,
	})
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, orgID, "idp.created", "idp:"+idp.ID, map[string]any{"issuer": idp.Issuer, "provider_type": idp.ProviderType})
	writeJSON(w, http.StatusCreated, struct {
		*store.IDP
		CallbackURL string `json:"callback_url"`
	}{idp, s.issuer + authn.CallbackPath})
}

// normalizeDomains lowercases and validates an email domain allowlist.
func normalizeDomains(in []string) ([]string, error) {
	if err := validList("allowed_email_domains", in); err != nil {
		return nil, err
	}
	out := []string{}
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(d))
		if !authn.ValidDomain(d) || !strings.Contains(d, ".") {
			return nil, validationError("invalid email domain: " + d + " (exact domains only, no wildcards)")
		}
		out = append(out, d)
	}
	return out, nil
}

// setIDPTrust lets an instance admin change an IdP's trust policy.
func (s *Server) setIDPTrust(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TrustEmail bool `json:"trust_email"`
		TrustMFA   bool `json:"trust_mfa"`
	}
	if !decode(w, r, &body) {
		return
	}
	orgID, id := chi.URLParam(r, "orgID"), chi.URLParam(r, "idpID")
	idp, err := s.store.SetIDPTrust(r.Context(), orgID, id, body.TrustEmail, body.TrustMFA)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, orgID, "idp.trust_changed", "idp:"+id, map[string]any{"trust_email": body.TrustEmail, "trust_mfa": body.TrustMFA})
	writeJSON(w, http.StatusOK, idp)
}

func (s *Server) listIDPs(w http.ResponseWriter, r *http.Request) {
	idps, err := s.store.ListIDPs(r.Context(), chi.URLParam(r, "orgID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, idps)
}

func (s *Server) deleteIDP(w http.ResponseWriter, r *http.Request) {
	orgID, id := chi.URLParam(r, "orgID"), chi.URLParam(r, "idpID")
	if err := s.store.DeleteIDP(r.Context(), orgID, id); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, orgID, "idp.deleted", "idp:"+id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listOrgProjectGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := s.store.ListProjectGrants(r.Context(), "", chi.URLParam(r, "orgID"), pageFrom(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, grants)
}
