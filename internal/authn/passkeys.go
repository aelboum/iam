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
// The options never list the user's credential IDs (allowCredentials stays
// empty, as in a discoverable login), so they are identical for known users,
// users without passkeys and unknown login names, and disclose no credential
// IDs (audit M5). FinishPasskeyLogin binds the assertion to the session's user.
func (s *Service) BeginPasskeyLogin(ctx context.Context, c Client, id, token string) (*protocol.CredentialAssertion, error) {
	sess, _, err := s.loadSession(ctx, c, id, token)
	if err != nil {
		return nil, err
	}
	assertion, session, err := s.webauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
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
	if challengeExpired(session, time.Now()) {
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
	if err := s.store.UpdatePasskeyUse(ctx, credentialID(cred.ID), stored, cred.Authenticator.SignCount); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// A concurrent login already used this or a higher counter value.
			s.audit(ctx, c, user, "passkey.clone_warning", map[string]any{"credential_id": credentialID(cred.ID)})
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if err := s.store.MarkSessionPasskey(ctx, sess.ID, cred.Flags.BackupEligible); err != nil {
		return nil, err
	}
	return s.GetSession(ctx, c, id, token)
}

// challengeExpired reports whether a stored WebAuthn challenge has passed the
// server-side deadline recorded when it was issued (audit L7). The engine
// enforces this itself, so expiry does not depend on the client honouring the
// ceremony timeout. A zero Expires (older challenges) means no deadline.
func challengeExpired(session webauthn.SessionData, now time.Time) bool {
	return !session.Expires.IsZero() && now.After(session.Expires)
}

// NewWebAuthn configures the relying party. rpID is the domain passkeys are
// bound to (the login UI's domain or a parent of it); origins are the login
// UI origins allowed to run the ceremony.
func NewWebAuthn(rpID, displayName string, origins []string) (*webauthn.WebAuthn, error) {
	if rpID == "" || len(origins) == 0 {
		return nil, errors.New("webauthn: RP ID and at least one origin are required")
	}
	// Enforce the ceremony timeouts on the server too, so a challenge cannot
	// be answered long after it was issued (audit L7).
	timeout := webauthn.TimeoutConfig{Enforce: true, Timeout: 5 * time.Minute, TimeoutUVD: 5 * time.Minute}
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: displayName,
		RPOrigins:     origins,
		Timeouts:      webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
	})
}
