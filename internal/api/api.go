// Package api is the engine's REST management and session API.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/aelboum/iam/internal/authn"
	"github.com/aelboum/iam/internal/ratelimit"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
)

type Server struct {
	store    *store.Store
	box      *secret.Box
	authn    *authn.Service
	provider *op.Provider
	issuer   string
	// devMode allows apps with dev_mode (plain-http redirect URIs).
	devMode bool
	// loginIPLimit caps session API calls per end-user IP.
	loginIPLimit ratelimit.Allower
	// loginKeyLimit caps session API calls per API key, so a leaked key that
	// forges X-End-User-IP still cannot flood the engine.
	loginKeyLimit ratelimit.Allower
	// mgmtKeyLimit caps management API calls per API key.
	mgmtKeyLimit ratelimit.Allower
	// authFailLimit caps invalid API key attempts per connecting address.
	authFailLimit ratelimit.Allower
}

func NewServer(st *store.Store, box *secret.Box, an *authn.Service, provider *op.Provider, issuer string, devMode bool, limits ratelimit.Factory) *Server {
	return &Server{
		store: st, box: box, authn: an, provider: provider, issuer: issuer, devMode: devMode,
		loginIPLimit:  limits("login-ip", 30, 20),
		loginKeyLimit: limits("login-key", 1200, 300),
		mgmtKeyLimit:  limits("mgmt-key", 600, 120),
		authFailLimit: limits("auth-fail", 30, 30),
	}
}

// Routes returns the /v1 API. Every route requires an API key.
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()
	r.Use(s.requireAPIKey)

	// Login API: usable by admin keys and by restricted login keys.
	r.Group(func(r chi.Router) {
		r.Use(s.limitLoginIP)
		r.Post("/sessions", s.createSession)
		r.Route("/sessions/{sessionID}", func(r chi.Router) {
			r.Get("/", s.getSession)
			r.Delete("/", s.deleteSession)
			r.Post("/password", s.checkPassword)
			r.Post("/totp", s.checkTOTP)
			r.Post("/recovery-code", s.checkRecoveryCode)
			r.Post("/passkey/begin", s.beginPasskeyLogin)
			r.Post("/passkey/finish", s.finishPasskeyLogin)
		})
		r.Get("/auth-requests/{authRequestID}", s.getAuthRequest)
		r.Post("/password-resets", s.startPasswordReset)
		r.Post("/federated-logins", s.startFederatedLogin)
		r.Post("/federated-logins/{intentID}/redeem", s.redeemFederatedLogin)
		r.Post("/password-resets/confirm", s.confirmPasswordReset)
		r.Post("/auth-requests/{authRequestID}/finalize", s.finalizeAuthRequest)
	})

	// Management API: admin-scoped keys only.
	r.Group(func(r chi.Router) {
		r.Use(requireAdminScope, s.limitManagement)

		r.With(requireInstanceAdmin).Post("/api-keys", s.createInstanceAPIKey)
		r.With(requireInstanceAdmin).Get("/api-keys", s.listInstanceAPIKeys)
		r.With(requireInstanceAdmin).Delete("/api-keys/{keyID}", s.deleteInstanceAPIKey)
		r.With(requireInstanceAdmin).Get("/audit", s.listAudit)

		r.Route("/orgs", func(r chi.Router) {
			r.With(requireInstanceAdmin).Post("/", s.createOrg)
			r.With(requireInstanceAdmin).Get("/", s.listOrgs)
			r.Route("/{orgID}", func(r chi.Router) {
				r.Use(requireOrgAccess)
				r.Get("/", s.getOrg)
				r.With(requireInstanceAdmin).Delete("/", s.deleteOrg)
				r.Post("/api-keys", s.createAPIKey)
				r.Get("/api-keys", s.listAPIKeys)
				r.Delete("/api-keys/{keyID}", s.deleteAPIKey)
				r.Get("/audit", s.listOrgAudit)
				r.Post("/users", s.createUser)
				r.Post("/machine-users", s.createMachineUser)
				r.Post("/idps", s.createIDP)
				r.Get("/idps", s.listIDPs)
				r.Delete("/idps/{idpID}", s.deleteIDP)
				r.With(requireInstanceAdmin).Put("/idps/{idpID}/trust", s.setIDPTrust)
				r.Get("/users", s.listUsers)
				r.Post("/projects", s.createProject)
				r.Get("/projects", s.listProjects)
				r.Get("/project-grants", s.listOrgProjectGrants)
			})
		})

		r.Route("/users/{userID}", func(r chi.Router) {
			r.Get("/", s.getUser)
			r.Patch("/", s.updateUser)
			r.Delete("/", s.deleteUser)
			r.Put("/password", s.setPassword)
			r.Post("/client-secret", s.rotateClientSecret)
			r.Post("/passkeys/registration", s.beginPasskeyRegistration)
			r.Post("/passkeys/registration/finish", s.finishPasskeyRegistration)
			r.Get("/passkeys", s.listPasskeys)
			r.Delete("/passkeys/{credentialID}", s.deletePasskey)
			r.Post("/lock", s.lockUser)
			r.Post("/unlock", s.unlockUser)
			r.Post("/logout", s.logoutUser)
			r.Post("/recovery-codes", s.generateRecoveryCodes)
			r.Post("/totp", s.enrollTOTP)
			r.Post("/totp/verify", s.verifyTOTP)
			r.Delete("/totp", s.removeTOTP)
			// The verification code is returned to the caller for delivery, so
			// whoever calls this can verify any address. Only the instance
			// operator (your SaaS backend) may run it, never a tenant.
			r.With(requireInstanceAdmin).Post("/email/verification", s.startEmailVerification)
			r.With(requireInstanceAdmin).Post("/email/verify", s.verifyEmail)
			r.Get("/grants", s.listUserGrants)
			r.Post("/grants", s.createUserGrant)
		})
		r.Patch("/user-grants/{grantID}", s.updateUserGrant)
		r.Delete("/user-grants/{grantID}", s.deleteUserGrant)

		r.Route("/projects/{projectID}", func(r chi.Router) {
			r.Get("/", s.getProject)
			r.Delete("/", s.deleteProject)
			r.Get("/roles", s.listRoles)
			r.Post("/roles", s.addRole)
			r.Delete("/roles/{roleKey}", s.deleteRole)
			r.Get("/apps", s.listApps)
			r.Post("/apps", s.createApp)
			r.Get("/grants", s.listProjectGrants)
			// Granting exposes a project to another tenant's users, so only the
			// instance operator may do it: an org cannot pull other orgs in.
			r.With(requireInstanceAdmin).Post("/grants", s.createProjectGrant)
		})
		r.Get("/apps/{appID}", s.getApp)
		r.Delete("/apps/{appID}", s.deleteApp)
		r.Patch("/project-grants/{grantID}", s.updateProjectGrant)
		r.Delete("/project-grants/{grantID}", s.deleteProjectGrant)
	})

	return r
}

// --- authentication of API callers -------------------------------------------------------------

type principalKey struct{}

// principal is the API key that authenticated the request.
type principal struct {
	key *store.APIKey
}

func (p *principal) isAdmin() bool { return p.key.OrgID == nil }

// canAccessOrg reports whether the caller may manage resources of orgID.
func (p *principal) canAccessOrg(orgID string) bool {
	return p.isAdmin() || *p.key.OrgID == orgID
}

func principalFrom(ctx context.Context) *principal {
	return ctx.Value(principalKey{}).(*principal)
}

func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || raw == "" {
			writeError(w, http.StatusUnauthorized, "missing bearer API key")
			return
		}
		key, err := s.store.AuthenticateAPIKey(r.Context(), secret.Hash(raw))
		if err != nil {
			// Only invalid keys are throttled, so a flood of bad keys from a
			// shared address (e.g. a NAT) can never lock out a valid key.
			peer := clientIP(r) // the connection address: no key, so no trusted header
			// Rate-limit before logging, so a flood of invalid keys from one
			// address cannot also flood the logs at line rate (internal security
			// audit B9).
			if !s.authFailLimit.Allow(peer) {
				fail(w, r, authn.ErrRateLimited)
				return
			}
			slog.WarnContext(r.Context(), "invalid API key", "ip", peer, "path", r.URL.Path)
			writeError(w, http.StatusUnauthorized, "invalid or expired API key")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, &principal{key: key})
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// A client that disconnects mid-request must not leave a change
			// half applied (e.g. user locked but tokens not yet revoked, or
			// the audit entry missing). Server timeouts still bound the work.
			ctx = context.WithoutCancel(ctx)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireAdminScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principalFrom(r.Context()).key.Scope != store.ScopeAdmin {
			writeError(w, http.StatusForbidden, "this API key may only use the login API")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireInstanceAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !principalFrom(r.Context()).isAdmin() {
			writeError(w, http.StatusForbidden, "instance admin key required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireOrgAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !principalFrom(r.Context()).canAccessOrg(chi.URLParam(r, "orgID")) {
			writeError(w, http.StatusForbidden, "API key has no access to this org")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// endUserIPHeader lets a login UI backend pass the browser's IP, so rate
// limits and audit entries apply to the end user rather than to the backend.
const endUserIPHeader = "X-End-User-IP"

type endUserIPKey struct{}

// clientIP is the end user's IP. On login API routes a valid X-End-User-IP
// from the authenticated login backend is used; everywhere else (e.g. the
// management API and its audit trail) only the connection's address counts.
func clientIP(r *http.Request) string {
	if trusted, _ := r.Context().Value(endUserIPKey{}).(bool); trusted {
		if ip := net.ParseIP(strings.TrimSpace(r.Header.Get(endUserIPHeader))); ip != nil {
			// Canonical form, so one address is one limiter and audit key and
			// cannot be varied by spelling (internal security audit B10).
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) limitLoginIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), endUserIPKey{}, true))
		if !s.loginKeyLimit.Allow(principalFrom(r.Context()).key.ID) || !s.loginIPLimit.Allow(clientIP(r)) {
			fail(w, r, authn.ErrRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// limitManagement caps management calls per API key, so one tenant cannot
// monopolise the engine (e.g. with expensive password hashing).
func (s *Server) limitManagement(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.mgmtKeyLimit.Allow(principalFrom(r.Context()).key.ID) {
			fail(w, r, authn.ErrRateLimited)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// audit records a management action taken by the calling API key.
func (s *Server) audit(r *http.Request, orgID string, action, target string, detail map[string]any) {
	var org *string
	if orgID != "" {
		org = &orgID
	}
	s.store.Audit(r.Context(), store.AuditEvent{
		OrgID: org, Actor: "api_key:" + principalFrom(r.Context()).key.ID,
		Action: action, Target: target, IP: clientIP(r), Detail: detail,
	})
}

// --- JSON helpers ---------------------------------------------------------------------------------

const maxBodyBytes = 1 << 20

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	// A declared oversize body is refused up front with 413. An unknown-length
	// (chunked) body has no ContentLength, so http.MaxBytesReader enforces the
	// same cap and reports *http.MaxBytesError, which is also surfaced as 413
	// rather than a confusing trailing-data 400.
	if r.ContentLength > maxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	// Exactly one JSON value: trailing data (a truncated or concatenated body)
	// is refused instead of being silently ignored; an oversize body caught only
	// on this second read is still a 413.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body is too large")
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: trailing data after the JSON value")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

var errForbidden = errors.New("forbidden")

// fail maps domain errors to HTTP responses.
func fail(w http.ResponseWriter, r *http.Request, err error) {
	var verr validationError
	var weak authn.WeakPasswordError
	switch {
	case errors.As(err, &verr):
		writeError(w, http.StatusBadRequest, verr.Error())
	case errors.As(err, &weak):
		writeError(w, http.StatusBadRequest, weak.Error())
	case errors.Is(err, errForbidden):
		writeError(w, http.StatusForbidden, "API key has no access to this resource")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, store.ErrInvalidReference),
		errors.Is(err, store.ErrInvalidRole),
		errors.Is(err, authn.ErrTOTPNotEnrolled),
		errors.Is(err, authn.ErrNotAuthenticated):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, authn.ErrInvalidCredentials),
		errors.Is(err, authn.ErrSessionInvalid):
		writeError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, authn.ErrNoAccess):
		writeError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, authn.ErrLocked):
		writeError(w, http.StatusLocked, err.Error())
	case errors.Is(err, authn.ErrUnsafeIdP):
		writeError(w, http.StatusBadGateway, "identity provider advertises an unsafe endpoint")
	case errors.Is(err, errQuota):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, authn.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, err.Error())
	case errors.Is(err, authn.ErrOverloaded):
		// Transient, server-side hashing shed (A1): 503 with a short Retry-After,
		// not the 429 window used for caller/tenant limits (internal security
		// audit N12/R4). The hint is advisory, never a capacity guarantee.
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, err.Error())
	default:
		slog.ErrorContext(r.Context(), "request failed", "method", r.Method, "path", r.URL.Path, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

type validationError string

func (e validationError) Error() string { return string(e) }

// --- pagination, size caps and quotas --------------------------------------------------------

// pageFrom reads ?limit= (default 100, max 1000) and ?offset= from the query.
func pageFrom(r *http.Request) store.Page {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	return store.Page{Limit: limit, Offset: offset}
}

const (
	maxNameLength = 200 // org, project, app, key and role display names
	maxListItems  = 50  // redirect URIs per app, role keys per grant
)

func validName(field, v string) error {
	if strings.TrimSpace(v) == "" {
		return validationError(field + " is required")
	}
	if len(v) > maxNameLength {
		return validationError(fmt.Sprintf("%s must be at most %d characters", field, maxNameLength))
	}
	return nil
}

func validList(field string, items []string) error {
	if len(items) > maxListItems {
		return validationError(fmt.Sprintf("%s may contain at most %d entries", field, maxListItems))
	}
	return nil
}

// quotaLimits bound how much one tenant can create, so no org can exhaust
// the shared database.
var quotaLimits = map[store.Quota]int{
	store.QuotaUsersPerOrg:     store.MaxUsersPerOrg,
	store.QuotaProjectsPerOrg:  100,
	store.QuotaKeysPerOrg:      50,
	store.QuotaAppsPerProject:  50,
	store.QuotaRolesPerProject: 200,
	store.QuotaIDPsPerOrg:      10,
}

var errQuota = errors.New("quota exceeded")

// checkQuota fails once owner has reached the limit for q.
func (s *Server) checkQuota(r *http.Request, q store.Quota, ownerID string) error {
	n, err := s.store.Count(r.Context(), q, ownerID)
	if err != nil {
		return err
	}
	if n >= quotaLimits[q] {
		return fmt.Errorf("%w: at most %d %s", errQuota, quotaLimits[q], q.Name)
	}
	return nil
}
