package api

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/aelboum/iam/internal/authn"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
)

// ASCII only: Unicode letters would allow look-alike usernames (homoglyphs).
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func validEmail(email string) error {
	// Same conservative rule the federation path uses: one @, a dotted DNS
	// domain, no whitespace or control characters. A dotless "a@b" would be
	// accepted here but refused as an IdP claim, so both paths agree.
	if !authn.ValidEmail(strings.ToLower(email)) {
		return validationError("a valid email is required")
	}
	return nil
}

// validUsername keeps usernames and emails apart: logins containing "@" are
// looked up by email, so a username may only contain "@" if it is the user's
// own email (the default when no username is given).
func validUsername(username, email string) error {
	if strings.Contains(username, "@") {
		if !strings.EqualFold(username, email) {
			return validationError("username may only contain '@' when it equals the email")
		}
		return nil
	}
	if !usernamePattern.MatchString(username) {
		return validationError("username must be 1-64 ASCII letters, digits, '.', '_' or '-'")
	}
	return nil
}

func validNames(names ...string) error {
	for _, n := range names {
		if len(n) > 100 {
			return validationError("names must be at most 100 characters")
		}
	}
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// userForCaller loads a user the caller is allowed to manage.
func (s *Server) userForCaller(r *http.Request, userID string) (*store.User, error) {
	user, err := s.store.GetUser(r.Context(), userID)
	if err != nil {
		return nil, err
	}
	if !principalFrom(r.Context()).canAccessOrg(user.OrgID) {
		return nil, store.ErrNotFound // do not reveal users of other orgs
	}
	return user, nil
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username      string `json:"username"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Password      string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	body.Username = strings.TrimSpace(body.Username)
	body.Email = strings.TrimSpace(body.Email)
	if err := validEmail(body.Email); err != nil {
		fail(w, r, err)
		return
	}
	if body.Username == "" {
		body.Username = body.Email
	}
	if err := validUsername(body.Username, body.Email); err != nil {
		fail(w, r, err)
		return
	}
	if err := validNames(body.GivenName, body.FamilyName); err != nil {
		fail(w, r, err)
		return
	}
	if body.EmailVerified && !principalFrom(r.Context()).isAdmin() {
		fail(w, r, validationError("org keys cannot mark emails verified directly; use /email/verification"))
		return
	}
	if err := s.checkQuota(r, store.QuotaUsersPerOrg, chi.URLParam(r, "orgID")); err != nil {
		fail(w, r, err)
		return
	}
	n := store.NewUser{
		OrgID:         chi.URLParam(r, "orgID"),
		Username:      body.Username,
		Email:         body.Email,
		EmailVerified: body.EmailVerified,
		GivenName:     body.GivenName,
		FamilyName:    body.FamilyName,
	}
	if body.Password != "" {
		hash, err := s.authn.HashPassword(body.Password, body.Username, body.Email)
		if err != nil {
			fail(w, r, err)
			return
		}
		n.PasswordHash = &hash
	}
	user, err := s.store.CreateUser(r.Context(), n)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.created", "user:"+user.ID, map[string]any{"username": user.Username})
	writeJSON(w, http.StatusCreated, user)
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context(), chi.URLParam(r, "orgID"), pageFrom(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	var patch store.UserPatch
	if !decode(w, r, &patch) {
		return
	}
	if patch.Email != nil {
		if err := validEmail(*patch.Email); err != nil {
			fail(w, r, err)
			return
		}
		// A username that is an email must keep matching the user's email.
		if strings.Contains(user.Username, "@") && !strings.EqualFold(user.Username, *patch.Email) {
			fail(w, r, validationError("this user's username is its email; create a new user to change it"))
			return
		}
	}
	if patch.GivenName != nil || patch.FamilyName != nil {
		if err := validNames(deref(patch.GivenName), deref(patch.FamilyName)); err != nil {
			fail(w, r, err)
			return
		}
	}
	if patch.EmailVerified != nil && *patch.EmailVerified && !principalFrom(r.Context()).isAdmin() {
		fail(w, r, validationError("org keys cannot mark emails verified directly; use /email/verification"))
		return
	}
	// A reset token emailed to the old address must not survive (audit M12).
	// Delete first: if the update then fails, no token was left valid.
	if patch.Email != nil {
		if err := s.store.DeletePasswordResets(r.Context(), user.ID); err != nil {
			fail(w, r, err)
			return
		}
	}
	updated, err := s.store.UpdateUser(r.Context(), user.ID, patch)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.updated", "user:"+user.ID, nil)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.DeleteUser(r.Context(), user.ID); err != nil {
		fail(w, r, err)
		return
	}
	// Tokens reference the user by subject only, so revoke them explicitly.
	if err := s.store.RevokeUserTokens(r.Context(), user.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.deleted", "user:"+user.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setPassword(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := humanOnly(user); err != nil {
		fail(w, r, err)
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.authn.SetPassword(r.Context(), user, body.Password); err != nil {
		fail(w, r, err)
		return
	}
	// A new password ends every session and token made with the old one.
	if err := s.store.RevokeUserTokens(r.Context(), user.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.password_set", "user:"+user.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// lockUser blocks sign-in and ends the user's sessions until unlocked.
func (s *Server) lockUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.SetLocked(r.Context(), user.ID, true); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.RevokeUserTokens(r.Context(), user.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.locked", "user:"+user.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// unlockUser clears the manual lock and any temporary lockout.
func (s *Server) unlockUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.SetLocked(r.Context(), user.ID, false); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.unlocked", "user:"+user.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// startEmailVerification returns a one-time code for the SaaS to deliver to
// the user's email address. The engine does not send email itself.
func (s *Server) startEmailVerification(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := humanOnly(user); err != nil {
		fail(w, r, err)
		return
	}
	code, expires, err := s.authn.StartEmailVerification(r.Context(), user)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.email_verification_started", "user:"+user.ID, nil)
	writeJSON(w, http.StatusCreated, map[string]any{"code": code, "email": user.Email, "expires_at": expires})
}

func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.authn.ConfirmEmail(r.Context(), user, body.Code); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.email_verified", "user:"+user.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// logoutUser revokes all of a user's sessions and tokens everywhere.
func (s *Server) logoutUser(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.RevokeUserTokens(r.Context(), user.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.logged_out", "user:"+user.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) enrollTOTP(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := humanOnly(user); err != nil {
		fail(w, r, err)
		return
	}
	if user.TOTPVerified {
		fail(w, r, store.ErrConflict)
		return
	}
	sec, uri, err := s.authn.EnrollTOTP(r.Context(), user)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.totp_enrollment_started", "user:"+user.ID, nil)
	writeJSON(w, http.StatusCreated, map[string]string{"secret": sec, "uri": uri})
}

func (s *Server) verifyTOTP(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.authn.VerifyTOTPEnrollment(r.Context(), user, body.Code); err != nil {
		fail(w, r, err)
		return
	}
	// Logins in progress were checked without the new factor.
	if err := s.store.DeleteUserSessions(r.Context(), user.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.totp_enabled", "user:"+user.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeTOTP(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.RemoveTOTP(r.Context(), user.ID); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.DeleteUserSessions(r.Context(), user.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.totp_removed", "user:"+user.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- user grants --------------------------------------------------------------------------

func (s *Server) listUserGrants(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	grants, err := s.store.ListUserGrants(r.Context(), user.ID, pageFrom(r))
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, grants)
}

func (s *Server) createUserGrant(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	var body struct {
		ProjectID string   `json:"project_id"`
		RoleKeys  []string `json:"role_keys"`
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
	grant, err := s.store.CreateUserGrant(r.Context(), user, body.ProjectID, body.RoleKeys)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user_grant.created", "user:"+user.ID,
		map[string]any{"project_id": grant.ProjectID, "roles": grant.RoleKeys})
	writeJSON(w, http.StatusCreated, grant)
}

// userGrantForCaller loads a user grant and the user it belongs to.
func (s *Server) userGrantForCaller(r *http.Request) (*store.UserGrant, *store.User, error) {
	grant, err := s.store.GetUserGrant(r.Context(), chi.URLParam(r, "grantID"))
	if err != nil {
		return nil, nil, err
	}
	user, err := s.userForCaller(r, grant.UserID)
	if err != nil {
		return nil, nil, err
	}
	return grant, user, nil
}

func (s *Server) updateUserGrant(w http.ResponseWriter, r *http.Request) {
	grant, user, err := s.userGrantForCaller(r)
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
	updated, err := s.store.UpdateUserGrant(r.Context(), user, grant.ID, body.RoleKeys)
	if err != nil {
		fail(w, r, err)
		return
	}
	// Tokens may carry removed roles; end them so the change applies now.
	if err := s.store.RevokeUserProjectTokens(r.Context(), grant.ProjectID, user.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user_grant.updated", "user:"+user.ID,
		map[string]any{"project_id": updated.ProjectID, "roles": updated.RoleKeys})
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deleteUserGrant(w http.ResponseWriter, r *http.Request) {
	grant, user, err := s.userGrantForCaller(r)
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.DeleteUserGrant(r.Context(), grant.ID); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.RevokeUserProjectTokens(r.Context(), grant.ProjectID, user.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user_grant.deleted", "user:"+user.ID, map[string]any{"project_id": grant.ProjectID})
	w.WriteHeader(http.StatusNoContent)
}

// --- machine users -------------------------------------------------------------------------

// createMachineUser adds a service account that gets tokens with the client
// credentials grant. The secret is returned only once.
func (s *Server) createMachineUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	if !usernamePattern.MatchString(body.Name) {
		fail(w, r, validationError("name must be 1-64 ASCII letters, digits, '.', '_' or '-'"))
		return
	}
	orgID := chi.URLParam(r, "orgID")
	if err := s.checkQuota(r, store.QuotaUsersPerOrg, orgID); err != nil {
		fail(w, r, err)
		return
	}
	clientID, clientSecret := "m_"+secret.Token(16), secret.Token(32)
	hash, err := s.authn.HashSecret(clientSecret)
	if err != nil {
		fail(w, r, err)
		return
	}
	user, err := s.store.CreateMachineUser(r.Context(), orgID, body.Name, clientID, hash)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, orgID, "machine_user.created", "user:"+user.ID, map[string]any{"name": user.Username})
	writeJSON(w, http.StatusCreated, struct {
		*store.User
		ClientSecret string `json:"client_secret"`
	}{user, clientSecret})
}

// rotateClientSecret issues a new secret for a machine user; the old one stops working.
func (s *Server) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if user.Kind != store.KindMachine {
		fail(w, r, validationError("only machine users have a client secret"))
		return
	}
	clientSecret := secret.Token(32)
	hash, err := s.authn.HashSecret(clientSecret)
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.SetClientSecret(r.Context(), user.ID, hash); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.RevokeUserTokens(r.Context(), user.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "machine_user.secret_rotated", "user:"+user.ID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"client_id": *user.ClientID, "client_secret": clientSecret})
}

// --- passkey registration ------------------------------------------------------------------

func (s *Server) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := humanOnly(user); err != nil {
		fail(w, r, err)
		return
	}
	options, err := s.authn.BeginPasskeyRegistration(r.Context(), user)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, options)
}

func (s *Server) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	var body struct {
		Name       string          `json:"name"`
		Credential json.RawMessage `json:"credential"`
	}
	if !decode(w, r, &body) {
		return
	}
	key, err := s.authn.FinishPasskeyRegistration(r.Context(), user, body.Name, body.Credential)
	if err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.passkey_added", "user:"+user.ID, map[string]any{"credential_id": key.ID})
	writeJSON(w, http.StatusCreated, key)
}

func (s *Server) listPasskeys(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	keys, err := s.store.ListPasskeys(r.Context(), user.ID)
	if err != nil {
		fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (s *Server) deletePasskey(w http.ResponseWriter, r *http.Request) {
	user, err := s.userForCaller(r, chi.URLParam(r, "userID"))
	if err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.DeletePasskey(r.Context(), user.ID, chi.URLParam(r, "credentialID")); err != nil {
		fail(w, r, err)
		return
	}
	if err := s.store.DeleteUserSessions(r.Context(), user.ID); err != nil {
		fail(w, r, err)
		return
	}
	s.audit(r, user.OrgID, "user.passkey_removed", "user:"+user.ID, map[string]any{"credential_id": chi.URLParam(r, "credentialID")})
	w.WriteHeader(http.StatusNoContent)
}

// humanOnly rejects operations that make no sense for machine users.
func humanOnly(user *store.User) error {
	if user.Kind != store.KindHuman {
		return validationError("not available for machine users")
	}
	return nil
}
