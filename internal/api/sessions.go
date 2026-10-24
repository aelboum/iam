package api

import (
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
