package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/aelboum/iam/internal/store"
)

// Passkeys (WebAuthn). Registration runs through the management API for a
// user; login runs through the session API, where a user-verified passkey
// alone authenticates the session (it is phishing resistant and proves both
// possession and the user's PIN or biometric).

const registrationLifetime = 5 * time.Minute

// webUser adapts a user and their passkeys to the WebAuthn library.
type webUser struct {
	user  *store.User
	creds []webauthn.Credential
}

func (u *webUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *webUser) WebAuthnName() string                       { return u.user.Email }
func (u *webUser) WebAuthnDisplayName() string                { return displayName(u.user) }
func (u *webUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func displayName(u *store.User) string {
	if name := joinNames(u.GivenName, u.FamilyName); name != "" {
		return name
	}
	return u.Username
}

func joinNames(given, family string) string {
	switch {
	case given == "":
		return family
	case family == "":
		return given
	default:
		return given + " " + family
	}
}

func (s *Service) loadWebUser(ctx context.Context, user *store.User) (*webUser, []*store.Passkey, error) {
	keys, err := s.store.ListPasskeys(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}
	wu := &webUser{user: user}
	for _, k := range keys {
		var c webauthn.Credential
		if err := json.Unmarshal(k.Credential, &c); err != nil {
			return nil, nil, err
		}
		wu.creds = append(wu.creds, c)
	}
	return wu, keys, nil
}

func credentialID(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

// BeginPasskeyRegistration returns the options for navigator.credentials.create().
func (s *Service) BeginPasskeyRegistration(ctx context.Context, user *store.User) (*protocol.CredentialCreation, error) {
	wu, _, err := s.loadWebUser(ctx, user)
	if err != nil {
		return nil, err
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(wu.creds))
	for _, c := range wu.creds {
		exclude = append(exclude, c.Descriptor())
	}
	creation, session, err := s.webauthn.BeginRegistration(wu,
		webauthn.WithExclusions(exclude),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationRequired,
		}))
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return nil, err
	}
	if err := s.store.SetPasskeyRegistration(ctx, user.ID, data, time.Now().Add(registrationLifetime)); err != nil {
		return nil, err
	}
	return creation, nil
}

// FinishPasskeyRegistration verifies the browser's attestation response and
// stores the new passkey.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, user *store.User, name string, response []byte) (*store.Passkey, error) {
	data, err := s.store.TakePasskeyRegistration(ctx, user.ID)
	if err != nil {
		return nil, ErrSessionInvalid
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	wu, _, err := s.loadWebUser(ctx, user)
	if err != nil {
		return nil, err
	}
	cred, err := s.webauthn.CreateCredential(wu, session, parsed)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	stored, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	id := credentialID(cred.ID)
	if err := s.store.AddPasskey(ctx, id, user.ID, truncate(name, 100), stored); err != nil {
		return nil, err
	}
	// Logins in progress were checked without the new factor.
	if err := s.store.DeleteUserSessions(ctx, user.ID); err != nil {
		return nil, err
	}
	return &store.Passkey{ID: id, UserID: user.ID, Name: name, CreatedAt: time.Now()}, nil
}

// BeginPasskeyLogin returns the options for navigator.credentials.get().
// Sessions for unknown users or users without passkeys get options that
// look the same, so callers cannot tell them apart.
func (s *Service) BeginPasskeyLogin(ctx context.Context, c Client, id, token string) (*protocol.CredentialAssertion, error) {
	sess, user, err := s.loadSession(ctx, c, id, token)
	if err != nil {
		return nil, err
	}
	var assertion *protocol.CredentialAssertion
	var session *webauthn.SessionData
	opts := webauthn.WithUserVerification(protocol.VerificationRequired)
	var wu *webUser
	if user != nil {
		if wu, _, err = s.loadWebUser(ctx, user); err != nil {
			return nil, err
		}
	}
	if wu != nil && len(wu.creds) > 0 {
		assertion, session, err = s.webauthn.BeginLogin(wu, opts)
	} else {
		assertion, session, err = s.webauthn.BeginDiscoverableLogin(opts)
	}
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(session)
	if err != nil {
		return nil, err
	}
	if err := s.store.SetSessionChallenge(ctx, sess.ID, data); err != nil {
		return nil, err
	}
	return assertion, nil
}

// FinishPasskeyLogin verifies the browser's assertion against the pending challenge.
func (s *Service) FinishPasskeyLogin(ctx context.Context, c Client, id, token string, response []byte) (*SessionState, error) {
	sess, user, err := s.loadSession(ctx, c, id, token)
	if err != nil {
		return nil, err
	}
	if !s.accountLimit.Allow(attemptKey(sess)) {
		return nil, ErrRateLimited
	}
	if sess.WebAuthnSession == nil || user == nil || user.IsLocked() {
		return nil, ErrInvalidCredentials
	}
	// The challenge is single use, whatever the outcome.
	if err := s.store.SetSessionChallenge(ctx, sess.ID, nil); err != nil {
		return nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(sess.WebAuthnSession, &session); err != nil {
		return nil, err
	}
	if !session.Expires.IsZero() && time.Now().After(session.Expires) {
		return nil, ErrInvalidCredentials
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	wu, _, err := s.loadWebUser(ctx, user)
	if err != nil {
		return nil, err
	}
	if len(session.UserID) == 0 {
		session.UserID = wu.WebAuthnID() // discoverable challenge: bind to this session's user
	}
	cred, err := s.webauthn.ValidateLogin(wu, session, parsed)
	if err != nil {
		s.audit(ctx, c, user, "login.failed", map[string]any{"factor": "passkey"})
		return nil, ErrInvalidCredentials
	}
	if cred.Authenticator.CloneWarning {
		// The signature counter went backwards: the key may have been cloned.
		s.audit(ctx, c, user, "passkey.clone_warning", map[string]any{"credential_id": credentialID(cred.ID)})
		return nil, ErrInvalidCredentials
	}
	stored, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	if err := s.store.UpdatePasskeyUse(ctx, credentialID(cred.ID), stored); err != nil {
		return nil, err
	}
	if err := s.store.MarkSessionPasskey(ctx, sess.ID); err != nil {
		return nil, err
	}
	return s.GetSession(ctx, c, id, token)
}

// NewWebAuthn configures the relying party. rpID is the domain passkeys are
// bound to (the login UI's domain or a parent of it); origins are the login
// UI origins allowed to run the ceremony.
func NewWebAuthn(rpID, displayName string, origins []string) (*webauthn.WebAuthn, error) {
	if rpID == "" || len(origins) == 0 {
		return nil, errors.New("webauthn: RP ID and at least one origin are required")
	}
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: displayName,
		RPOrigins:     origins,
	})
}
