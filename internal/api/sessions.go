package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/aelboum/iam/internal/authn"
	"github.com/aelboum/iam/internal/oidcop"
	"github.com/aelboum/iam/internal/store"
)

// Session API: called by the SaaS's own login UI backend to authenticate a
// user step by step, then finalize a pending OIDC auth request. Pass the
// browser's IP in X-End-User-IP so limits and audit apply per end user.

const sessionTokenHeader = "X-Session-Token"

// loginClient describes the caller for authn: its org restriction and end-user IP.
func loginClient(r *http.Request) authn.Client {
	c := authn.Client{IP: clientIP(r)}
	if org := principalFrom(r.Context()).key.OrgID; org != nil {
		c.OrgID = *org
	}
	return c
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Org       string `json:"org"` // org id or slug
		LoginName string `json:"login_name"`
	}
	if !decode(w, r, &body) {
		return
	}
	p := principalFrom(r.Context())
	org, err := s.store.GetOrgByRef(r.Context(), body.Org)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		fail(w, r, err)
		return
	}
	// An org-scoped key gets the same answer for missing and foreign orgs,
	// so it cannot probe which org slugs exist.
	if err != nil || !p.canAccessOrg(org.ID) {
		if p.isAdmin() {
			fail(w, r, validationError("unknown org"))
		} else {
			fail(w, r, errForbidden)
		}
		return
	}
	if body.LoginName == "" || len(body.LoginName) > 256 {
		fail(w, r, validationError("login_name is required"))
		return
	}
	state, err := s.authn.CreateSession(r.Context(), org.ID, body.LoginName)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, state)
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	state, err := s.authn.GetSession(r.Context(), loginClient(r), chi.URLParam(r, "sessionID"), r.Header.Get(sessionTokenHeader))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	if err := s.authn.DeleteSession(r.Context(), loginClient(r), chi.URLParam(r, "sessionID"), r.Header.Get(sessionTokenHeader)); err != nil {
		fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) checkPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionToken string `json:"session_token"`
		Password     string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	state, err := s.authn.CheckPassword(r.Context(), loginClient(r), chi.URLParam(r, "sessionID"), body.SessionToken, body.Password)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) checkTOTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionToken string `json:"session_token"`
		Code         string `json:"code"`
	}
	if !decode(w, r, &body) {
		return
	}
	state, err := s.authn.CheckTOTP(r.Context(), loginClient(r), chi.URLParam(r, "sessionID"), body.SessionToken, body.Code)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) getAuthRequest(w http.ResponseWriter, r *http.Request) {
	info, err := s.authn.GetAuthRequest(r.Context(), loginClient(r), chi.URLParam(r, "authRequestID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) finalizeAuthRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionID    string `json:"session_id"`
		SessionToken string `json:"session_token"`
	}
	if !decode(w, r, &body) {
		return
	}
	id := chi.URLParam(r, "authRequestID")
	if err := s.authn.FinalizeAuthRequest(r.Context(), loginClient(r), id, body.SessionID, body.SessionToken); err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"callback_url": oidcop.CallbackURL(s.provider, s.issuer, id),
	})
}

// --- password reset ------------------------------------------------------------------------

// startPasswordReset returns a reset token for the login backend to email to
// the user. For unknown login names it returns 202 with no token, so the
// backend can show the same "check your inbox" message either way.
func (s *Server) startPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Org       string `json:"org"`
		LoginName string `json:"login_name"`
	}
	if !decode(w, r, &body) {
		return
	}
	p := principalFrom(r.Context())
	org, err := s.store.GetOrgByRef(r.Context(), body.Org)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		fail(w, r, err)
		return
	}
	if err != nil || !p.canAccessOrg(org.ID) {
		if p.isAdmin() {
			fail(w, r, validationError("unknown org"))
		} else {
			fail(w, r, errForbidden)
		}
		return
	}
	reset, err := s.authn.StartPasswordReset(r.Context(), loginClient(r), org.ID, body.LoginName)
	if err != nil {
		fail(w, r, err)
		return
	}
	if reset == nil {
		writeJSON(w, http.StatusAccepted, map[string]any{})
		return
	}
	writeJSON(w, http.StatusAccepted, reset)
}

func (s *Server) confirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.authn.ConfirmPasswordReset(r.Context(), loginClient(r), body.Token, body.Password); err != nil {
		fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- federated login (per-org SSO) -----------------------------------------------------------

func (s *Server) startFederatedLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Org       string `json:"org"`
		IDPID     string `json:"idp_id"`
		ReturnURL string `json:"return_url"`
		// BrowserBinding: random secret from the login UI's HttpOnly cookie (see authn).
		BrowserBinding string `json:"browser_binding"`
	}
	if !decode(w, r, &body) {
		return
	}
	p := principalFrom(r.Context())
	org, err := s.store.GetOrgByRef(r.Context(), body.Org)
	if err != nil || !p.canAccessOrg(org.ID) {
		fail(w, r, errForbidden)
		return
	}
	if !redirectURLAllowed(body.ReturnURL, false, s.devMode) {
		fail(w, r, validationError("return_url must be an https URL of your login UI"))
		return
	}
	start, err := s.authn.StartFederatedLogin(r.Context(), org.ID, body.IDPID, body.ReturnURL, body.BrowserBinding)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, start)
}

func (s *Server) redeemFederatedLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code           string `json:"code"`
		BrowserBinding string `json:"browser_binding"`
	}
	if !decode(w, r, &body) {
		return
	}
	state, err := s.authn.RedeemFederatedLogin(r.Context(), loginClient(r), chi.URLParam(r, "intentID"), body.Code, body.BrowserBinding)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, state)
}

// IDPCallback is where external identity providers send the browser back.
// It is public: the one-time state parameter authenticates the request.
// The redirect target is the intent's return_url, which was validated as an
// https origin when the login started (redirectURLAllowed), so the tainted
// value cannot become an open redirect.
func (s *Server) IDPCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target, err := s.authn.HandleCallback(r.Context(), q.Get("state"), q.Get("code"), q.Get("error"))
	if err != nil {
		http.Error(w, "invalid or expired login attempt", http.StatusBadRequest)
		return
	}
	// #nosec G710 -- target is a validated return_url, never a raw request value.
	http.Redirect(w, r, target, http.StatusFound)
}

// --- passkey login --------------------------------------------------------------------------

func (s *Server) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionToken string `json:"session_token"`
	}
	if !decode(w, r, &body) {
		return
	}
	options, err := s.authn.BeginPasskeyLogin(r.Context(), loginClient(r), chi.URLParam(r, "sessionID"), body.SessionToken)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionToken string          `json:"session_token"`
		Credential   json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &body) {
		return
	}
	state, err := s.authn.FinishPasskeyLogin(r.Context(), loginClient(r), chi.URLParam(r, "sessionID"), body.SessionToken, body.Credential)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}
