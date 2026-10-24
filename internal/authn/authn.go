// Package authn implements user authentication: password hashing, TOTP and
// the headless login session flow that completes OIDC auth requests.
package authn

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"github.com/zitadel/passwap"
	"github.com/zitadel/passwap/argon2"
	"github.com/zitadel/passwap/bcrypt"

	"github.com/aelboum/iam/internal/ratelimit"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
)

var (
	// ErrInvalidCredentials is deliberately vague to avoid user enumeration.
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrLocked             = errors.New("user is locked")
	ErrRateLimited        = errors.New("too many attempts, try again later")
	ErrSessionInvalid     = errors.New("session invalid or expired")
	ErrNotAuthenticated   = errors.New("session is not fully authenticated")
	ErrNoAccess           = errors.New("user's org has no access to this application")
	ErrTOTPNotEnrolled    = errors.New("totp not enrolled")
)

// WeakPasswordError explains why a password was rejected.
type WeakPasswordError string

func (e WeakPasswordError) Error() string { return string(e) }

const (
	minPasswordLength = 10
	maxPasswordLength = 256 // bounds hashing cost
	totpPeriod        = 30 * time.Second
	emailCodeLifetime = 15 * time.Minute
)

type Config struct {
	IssuerName string
	// Issuer is the engine's public URL (for the federation callback).
	Issuer string
	// DevMode allows identity providers on private networks and plain http.
	DevMode  bool
	WebAuthn *webauthn.WebAuthn
	// CodeKey keys the HMAC of stored email codes, so a database leak alone
	// does not reveal them (6-digit codes are trivially brute-forced from a plain hash).
	CodeKey         [32]byte
	SessionLifetime time.Duration
	MaxFailedLogins int
	// Limits builds the rate limiters (in-memory or shared).
	Limits          ratelimit.Factory
	LockoutDuration time.Duration
}

type Service struct {
	store     *store.Store
	box       *secret.Box
	passwords *passwap.Swapper
	cfg       Config
	// accountLimit caps password/TOTP attempts per user, whatever the source IP.
	accountLimit ratelimit.Allower
	// dummyHash is verified for unknown users so response time does not reveal them.
	dummyHash string
	// httpClient talks to external identity providers (SSRF-guarded).
	httpClient *http.Client
	webauthn   *webauthn.WebAuthn
}

func NewService(st *store.Store, box *secret.Box, cfg Config) *Service {
	s := &Service{
		store: st,
		box:   box,
		// Hash with argon2id; still verify bcrypt so imported users can log in
		// and get upgraded to argon2id on their next successful login.
		passwords: passwap.NewSwapper(
			argon2.NewArgon2id(argon2.RecommendedIDParams, nil),
			bcrypt.NewVerifier(nil),
		),
		cfg:          cfg,
		accountLimit: cfg.Limits("login-account", 10, 10),
		httpClient:   NewOutboundClient(cfg.DevMode),
		webauthn:     cfg.WebAuthn,
	}
	hash, err := s.passwords.Hash(secret.Token(16))
	if err != nil {
		panic(err)
	}
	s.dummyHash = hash
	return s
}

// --- passwords --------------------------------------------------------------------

// CheckPasswordPolicy rejects passwords that are too short, too long or
// built from the user's own identifiers.
func CheckPasswordPolicy(password, username, email string) error {
	n := utf8.RuneCountInString(password)
	if n < minPasswordLength {
		return WeakPasswordError(fmt.Sprintf("password must be at least %d characters", minPasswordLength))
	}
	if n > maxPasswordLength {
		return WeakPasswordError(fmt.Sprintf("password must be at most %d characters", maxPasswordLength))
	}
	lower := strings.ToLower(password)
	local, _, _ := strings.Cut(strings.ToLower(email), "@")
	for _, ident := range []string{strings.ToLower(username), local} {
		if len(ident) >= 3 && strings.Contains(lower, ident) {
			return WeakPasswordError("password must not contain the username or email")
		}
	}
	return nil
}

func (s *Service) HashPassword(password, username, email string) (string, error) {
	if err := CheckPasswordPolicy(password, username, email); err != nil {
		return "", err
	}
	return s.hash(password)
}

// HashSecret hashes a client secret. Secrets are random, so no policy applies.
func (s *Service) HashSecret(v string) (string, error) {
	return s.hash(v)
}

// VerifySecret checks a client secret against its hash.
func (s *Service) VerifySecret(hash, v string) bool {
	_, err := s.verify(hash, v)
	return err == nil
}

func (s *Service) SetPassword(ctx context.Context, user *store.User, password string) error {
	hash, err := s.HashPassword(password, user.Username, user.Email)
	if err != nil {
		return err
	}
	return s.store.SetPasswordHash(ctx, user.ID, hash)
}

// --- TOTP ---------------------------------------------------------------------------

// EnrollTOTP creates a pending TOTP secret and returns it with its otpauth:// URI.
// The secret becomes active after VerifyTOTPEnrollment succeeds.
func (s *Service) EnrollTOTP(ctx context.Context, user *store.User) (secretValue, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.cfg.IssuerName, AccountName: user.Email})
	if err != nil {
		return "", "", err
	}
	if err := s.store.SetPendingTOTP(ctx, user.ID, s.box.Seal([]byte(key.Secret()))); err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

func (s *Service) VerifyTOTPEnrollment(ctx context.Context, user *store.User, code string) error {
	ok, err := s.acceptTOTP(ctx, user, code)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCredentials
	}
	return s.store.MarkTOTPVerified(ctx, user.ID)
}

// acceptTOTP checks code against the current time step and one step either
// side, and accepts each time step at most once (replay protection).
func (s *Service) acceptTOTP(ctx context.Context, user *store.User, code string) (bool, error) {
	if user.TOTPSecretEnc == nil {
		return false, nil
	}
	sec, err := s.box.Open(user.TOTPSecretEnc)
	if err != nil {
		return false, err
	}
	now := time.Now()
	for _, skew := range []time.Duration{0, -totpPeriod, totpPeriod} {
		t := now.Add(skew)
		expected, err := totp.GenerateCode(string(sec), t)
		if err != nil {
			return false, err
		}
		if secret.Equal(expected, code) {
			return s.store.AcceptTOTPStep(ctx, user.ID, t.Unix()/int64(totpPeriod.Seconds()))
		}
	}
	return false, nil
}

// --- email verification ------------------------------------------------------------------

// StartEmailVerification creates a 6-digit code for the user's current email.
// The SaaS delivers it (e.g. by email); the engine never sends mail itself.
func (s *Service) codeHash(userID, code string) string {
	return secret.HMAC(s.cfg.CodeKey, userID+":"+code)
}

func (s *Service) StartEmailVerification(ctx context.Context, user *store.User) (string, time.Time, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", time.Time{}, err
	}
	code := fmt.Sprintf("%06d", n.Int64())
	expires := time.Now().Add(emailCodeLifetime)
	if err := s.store.SetEmailVerification(ctx, user.ID, user.Email, s.codeHash(user.ID, code), expires); err != nil {
		if errors.Is(err, store.ErrTooSoon) {
			return "", time.Time{}, ErrRateLimited
		}
		return "", time.Time{}, err
	}
	return code, expires, nil
}

func (s *Service) ConfirmEmail(ctx context.Context, user *store.User, code string) error {
	ok, err := s.store.ConsumeEmailVerification(ctx, user.ID, func(hash string) bool {
		return secret.Equal(hash, s.codeHash(user.ID, code))
	})
	if errors.Is(err, store.ErrNotFound) || (err == nil && !ok) {
		return ErrInvalidCredentials
	}
	return err
}

// --- password reset -------------------------------------------------------------------------

const passwordResetLifetime = 30 * time.Minute

// PasswordReset is returned to the login backend, which emails the token to
// the user (typically as a link to its reset page).
type PasswordReset struct {
	Token     string    `json:"token"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
}

// StartPasswordReset issues a single-use reset token for a human user. For an
// unknown login name it returns nil without error, so the end user always
// sees the same "if the account exists, we sent an email" message.
func (s *Service) StartPasswordReset(ctx context.Context, c Client, orgID, loginName string) (*PasswordReset, error) {
	user, err := s.store.FindUserForLogin(ctx, orgID, loginName)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if user.Kind != store.KindHuman || user.Locked {
		return nil, nil // machine users have no password; a manual lock stays in force
	}
	token := secret.Token(32)
	expires := time.Now().Add(passwordResetLifetime)
	if err := s.store.CreatePasswordReset(ctx, user.ID, secret.Hash(token), expires); err != nil {
		if errors.Is(err, store.ErrTooSoon) {
			return nil, ErrRateLimited
		}
		return nil, err
	}
	s.audit(ctx, c, user, "user.password_reset_requested", nil)
	return &PasswordReset{Token: token, Email: user.Email, ExpiresAt: expires}, nil
}

// ConfirmPasswordReset sets a new password with a reset token. All sessions
// and tokens are revoked and any failed-login lockout is cleared. If allowOrg
// is set, the token must belong to a user of that org.
func (s *Service) ConfirmPasswordReset(ctx context.Context, c Client, token, password string) error {
	if len(token) > 128 {
		return ErrInvalidCredentials
	}
	// Check the new password before using up the token, so a rejected
	// password does not force the user to request a new email.
	userID, err := s.store.PeekPasswordReset(ctx, secret.Hash(token))
	if errors.Is(err, store.ErrNotFound) {
		return ErrInvalidCredentials
	} else if err != nil {
		return err
	}
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if c.OrgID != "" && c.OrgID != user.OrgID {
		return ErrInvalidCredentials
	}
	hash, err := s.HashPassword(password, user.Username, user.Email)
	if err != nil {
		return err
	}
	if _, err := s.store.ConsumePasswordReset(ctx, secret.Hash(token)); err != nil {
		return ErrInvalidCredentials // used concurrently
	}
	if err := s.store.SetPasswordHash(ctx, user.ID, hash); err != nil {
		return err
	}
	if err := s.store.RevokeUserTokens(ctx, user.ID); err != nil {
		return err
	}
	if err := s.store.ClearTemporaryLockout(ctx, user.ID); err != nil {
		return err
	}
	s.audit(ctx, c, user, "user.password_reset", nil)
	return nil
}

// --- sessions ---------------------------------------------------------------------------

// SessionState is the view of a session returned to the login UI.
type SessionState struct {
	ID              string `json:"session_id"`
	Token           string `json:"session_token,omitempty"`
	PasswordChecked bool   `json:"password_checked"`
	TOTPChecked     bool   `json:"totp_checked"`
	PasskeyChecked  bool   `json:"passkey_checked"`
	IDPChecked      bool   `json:"idp_checked"`
	MFARequired     bool   `json:"mfa_required"`
	// AMR lists how the user authenticated (RFC 8176 values), once authenticated.
	AMR           []string   `json:"amr,omitempty"`
	Authenticated bool       `json:"authenticated"`
	ExpiresAt     time.Time  `json:"expires_at"`
	AuthTime      *time.Time `json:"auth_time,omitempty"`
	// Only revealed once the password was verified.
	OrgID  string `json:"org_id,omitempty"`
	UserID string `json:"user_id,omitempty"`
}

// Client describes who is calling: the org an API key is restricted to
// ("" for instance keys) and the end user's IP for auditing.
type Client struct {
	OrgID string
	IP    string
}

// CreateSession starts a login. It behaves identically for unknown login
// names (the session just has no user), so callers cannot discover which
// users exist; the password step then fails as for a wrong password.
func (s *Service) CreateSession(ctx context.Context, orgID, loginName string) (*SessionState, error) {
	var userID *string
	user, err := s.store.FindUserForLogin(ctx, orgID, loginName)
	if err == nil {
		userID = &user.ID
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	token := secret.Token(32)
	sess, err := s.store.CreateSession(ctx, orgID, userID, strings.ToLower(loginName),
		secret.Hash(token), time.Now().Add(s.cfg.SessionLifetime))
	if err != nil {
		return nil, err
	}
	return &SessionState{ID: sess.ID, Token: token, ExpiresAt: sess.ExpiresAt}, nil
}

// loadSession verifies the session token and the caller's org restriction.
// The user is nil when the session's login name matched no user.
func (s *Service) loadSession(ctx context.Context, c Client, id, token string) (*store.Session, *store.User, error) {
	sess, err := s.store.GetSession(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, ErrSessionInvalid
	} else if err != nil {
		return nil, nil, err
	}
	if !secret.Equal(sess.TokenHash, secret.Hash(token)) || (c.OrgID != "" && c.OrgID != sess.OrgID) {
		return nil, nil, ErrSessionInvalid
	}
	if sess.UserID == nil {
		return sess, nil, nil
	}
	user, err := s.store.GetUser(ctx, *sess.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return sess, nil, nil // user deleted mid-login
	} else if err != nil {
		return nil, nil, err
	}
	return sess, user, nil
}

// attemptKey rate-limits by login identity, so known and unknown login names
// are throttled identically.
func attemptKey(sess *store.Session) string {
	return sess.OrgID + ":" + sess.LoginName
}

func (s *Service) GetSession(ctx context.Context, c Client, id, token string) (*SessionState, error) {
	sess, user, err := s.loadSession(ctx, c, id, token)
	if err != nil {
		return nil, err
	}
	return s.state(sess, user), nil
}

func (s *Service) CheckPassword(ctx context.Context, c Client, id, token, password string) (*SessionState, error) {
	sess, user, err := s.loadSession(ctx, c, id, token)
	if err != nil {
		return nil, err
	}
	if !s.accountLimit.Allow(attemptKey(sess)) {
		return nil, ErrRateLimited
	}
	// Reserve the attempt before verifying, so parallel guesses cannot exceed
	// the lockout threshold. Unknown and locked users take the same path and
	// time, and get the same answer as a wrong password; a locked account's
	// password is never evaluated.
	reserved := false
	if user != nil && !user.IsLocked() {
		if reserved, err = s.store.ReserveAttempt(ctx, user.ID, store.FactorPassword, s.cfg.MaxFailedLogins); err != nil {
			return nil, err
		}
	}
	if !reserved || !user.HasPassword() || utf8.RuneCountInString(password) > maxPasswordLength {
		s.verifyDummy(password)
		if reserved {
			return nil, s.attemptFailed(ctx, c, user, store.FactorPassword)
		}
		if user != nil {
			s.audit(ctx, c, user, "login.rejected_locked", nil)
		}
		return nil, ErrInvalidCredentials
	}
	updated, verr := s.verify(*user.PasswordHash, password)
	if verr != nil {
		if !errors.Is(verr, passwap.ErrPasswordMismatch) {
			return nil, verr
		}
		return nil, s.attemptFailed(ctx, c, user, store.FactorPassword)
	}
	if updated != "" {
		// Upgrade the hash only if it was not changed meanwhile (e.g. an admin reset).
		if err := s.store.UpgradePasswordHash(ctx, user.ID, *user.PasswordHash, updated); err != nil {
			return nil, err
		}
	}
	if err := s.store.AttemptSucceeded(ctx, user.ID, store.FactorPassword); err != nil {
		return nil, err
	}
	if err := s.store.MarkSessionPassword(ctx, sess.ID); err != nil {
		return nil, err
	}
	return s.GetSession(ctx, c, id, token)
}

func (s *Service) CheckTOTP(ctx context.Context, c Client, id, token, code string) (*SessionState, error) {
	sess, user, err := s.loadSession(ctx, c, id, token)
	if err != nil {
		return nil, err
	}
	if sess.PasswordCheckedAt == nil || user == nil {
		return nil, ErrNotAuthenticated // password first, so TOTP cannot be probed alone
	}
	if !user.TOTPVerified {
		return nil, ErrTOTPNotEnrolled
	}
	if !s.accountLimit.Allow(attemptKey(sess)) {
		return nil, ErrRateLimited
	}
	if user.IsLocked() {
		return nil, ErrLocked
	}
	reserved, err := s.store.ReserveAttempt(ctx, user.ID, store.FactorTOTP, s.cfg.MaxFailedLogins)
	if err != nil {
		return nil, err
	}
	if !reserved {
		return nil, ErrLocked // the caller already proved the password
	}
	ok, err := s.acceptTOTP(ctx, user, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, s.attemptFailed(ctx, c, user, store.FactorTOTP)
	}
	if err := s.store.AttemptSucceeded(ctx, user.ID, store.FactorTOTP); err != nil {
		return nil, err
	}
	if err := s.store.MarkSessionTOTP(ctx, sess.ID); err != nil {
		return nil, err
	}
	return s.GetSession(ctx, c, id, token)
}

// attemptFailed settles a failed reserved attempt and returns the error to report.
func (s *Service) attemptFailed(ctx context.Context, c Client, user *store.User, f store.Factor) error {
	locked, err := s.store.AttemptFailed(ctx, user.ID, f, s.cfg.MaxFailedLogins, s.cfg.LockoutDuration)
	if err != nil {
		return err
	}
	factor := "password"
	if f == store.FactorTOTP {
		factor = "totp"
	}
	s.audit(ctx, c, user, "login.failed", map[string]any{"factor": factor})
	if locked {
		s.audit(ctx, c, user, "user.locked_out", map[string]any{"duration": s.cfg.LockoutDuration.String()})
	}
	return ErrInvalidCredentials
}

// hashSlots bounds concurrent password hashing. Each argon2id run uses about
// 64 MiB, so unbounded parallel requests could exhaust memory.
var hashSlots = make(chan struct{}, max(2, runtime.NumCPU()))

func (s *Service) verify(hash, password string) (string, error) {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return s.passwords.Verify(hash, password)
}

// verifyDummy spends the time of a real check, for unknown or locked users.
func (s *Service) verifyDummy(password string) {
	if len(password) > maxPasswordLength*4 {
		password = password[:maxPasswordLength*4]
	}
	_, _ = s.verify(s.dummyHash, password)
}

func (s *Service) hash(password string) (string, error) {
	hashSlots <- struct{}{}
	defer func() { <-hashSlots }()
	return s.passwords.Hash(password)
}

func (s *Service) DeleteSession(ctx context.Context, c Client, id, token string) error {
	if _, _, err := s.loadSession(ctx, c, id, token); err != nil {
		return err
	}
	return s.store.DeleteSession(ctx, id)
}

func (s *Service) state(sess *store.Session, user *store.User) *SessionState {
	known := user != nil
	st := &SessionState{
		ID:              sess.ID,
		PasswordChecked: known && sess.PasswordCheckedAt != nil,
		TOTPChecked:     sess.TOTPCheckedAt != nil,
		PasskeyChecked:  known && sess.PasskeyCheckedAt != nil,
		IDPChecked:      known && sess.IDPCheckedAt != nil,
		ExpiresAt:       sess.ExpiresAt,
	}
	// Nothing about the user is revealed before a first factor was verified.
	if st.PasswordChecked || st.PasskeyChecked || st.IDPChecked {
		st.OrgID, st.UserID = sess.OrgID, user.ID
		st.MFARequired = user.MFARequired()
	}
	// A session is authenticated by one of: a user-verified passkey (phishing
	// resistant, counts as multi-factor), a federated login (the org's IdP is
	// responsible for its MFA), or the password plus TOTP when enrolled.
	var at *time.Time
	switch {
	case st.PasskeyChecked:
		at, st.AMR = sess.PasskeyCheckedAt, []string{"hwk", "user", "mfa"}
	case st.IDPChecked:
		at, st.AMR = sess.IDPCheckedAt, []string{"fed"}
	case st.PasswordChecked && (!st.MFARequired || st.TOTPChecked):
		at, st.AMR = sess.PasswordCheckedAt, []string{"pwd"}
		if st.TOTPChecked {
			st.AMR = append(st.AMR, "otp", "mfa")
			if sess.TOTPCheckedAt.After(*at) {
				at = sess.TOTPCheckedAt
			}
		}
	}
	if at != nil {
		t := *at
		st.Authenticated, st.AuthTime = true, &t
	}
	return st
}

func (s *Service) audit(ctx context.Context, c Client, user *store.User, action string, detail map[string]any) {
	s.store.Audit(ctx, store.AuditEvent{
		OrgID: &user.OrgID, Actor: "user:" + user.ID, Action: action,
		Target: "user:" + user.ID, IP: c.IP, Detail: detail,
	})
}

// --- OIDC auth request completion ------------------------------------------------------

// AuthRequestInfo is what a login UI needs to render the login for an auth request.
type AuthRequestInfo struct {
	ID        string   `json:"id"`
	ClientID  string   `json:"client_id"`
	AppName   string   `json:"app_name"`
	ProjectID string   `json:"project_id"`
	Scopes    []string `json:"scopes"`
	LoginHint string   `json:"login_hint,omitempty"`
	Prompt    []string `json:"prompt"`
}

// authRequestFor loads an auth request and its app. An org-scoped key only
// sees requests for apps its org can sign in to.
func (s *Service) authRequestFor(ctx context.Context, c Client, id string) (*store.AuthRequest, *store.App, error) {
	ar, err := s.store.GetAuthRequest(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	app, err := s.store.GetAppByClientID(ctx, ar.ClientID)
	if err != nil {
		return nil, nil, err
	}
	if c.OrgID != "" {
		if _, ok, err := s.store.AvailableRoles(ctx, app.ProjectID, c.OrgID); err != nil {
			return nil, nil, err
		} else if !ok {
			return nil, nil, store.ErrNotFound
		}
	}
	return ar, app, nil
}

func (s *Service) GetAuthRequest(ctx context.Context, c Client, id string) (*AuthRequestInfo, error) {
	ar, app, err := s.authRequestFor(ctx, c, id)
	if err != nil {
		return nil, err
	}
	return &AuthRequestInfo{
		ID: ar.ID, ClientID: ar.ClientID, AppName: app.Name, ProjectID: app.ProjectID,
		Scopes: ar.Scopes, LoginHint: ar.LoginHint, Prompt: ar.Prompt,
	}, nil
}

// FinalizeAuthRequest binds a fully authenticated session to a pending auth
// request. The caller then redirects the browser to the returned callback.
func (s *Service) FinalizeAuthRequest(ctx context.Context, c Client, authRequestID, sessionID, sessionToken string) error {
	sess, user, err := s.loadSession(ctx, c, sessionID, sessionToken)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrNotAuthenticated
	}
	if user.IsLocked() {
		return ErrLocked
	}
	state := s.state(sess, user)
	if !state.Authenticated {
		return ErrNotAuthenticated
	}
	ar, app, err := s.authRequestFor(ctx, c, authRequestID)
	if err != nil {
		return err
	}
	freshLoginRequired := slices.Contains(ar.Prompt, "login") || (ar.MaxAgeSeconds != nil && *ar.MaxAgeSeconds <= 0)
	if ar.MaxAgeSeconds != nil && *ar.MaxAgeSeconds > 0 &&
		time.Since(*state.AuthTime) > time.Duration(*ar.MaxAgeSeconds)*time.Second {
		return ErrNotAuthenticated
	}
	if freshLoginRequired && sess.CreatedAt.Before(ar.CreatedAt) {
		// prompt=login / max_age=0 demand a login that started after the request.
		return ErrNotAuthenticated
	}
	// B2B2C isolation: only users of the owner org or of a granted org may sign in.
	if _, ok, err := s.store.AvailableRoles(ctx, app.ProjectID, user.OrgID); err != nil {
		return err
	} else if !ok {
		s.audit(ctx, c, user, "login.denied", map[string]any{"client_id": app.ClientID, "reason": "no project grant"})
		return ErrNoAccess
	}
	amr := state.AMR
	if err := s.store.CompleteAuthRequest(ctx, ar.ID, user.ID, *state.AuthTime, amr); err != nil {
		return err
	}
	s.audit(ctx, c, user, "login.succeeded", map[string]any{"client_id": app.ClientID, "amr": amr})
	return nil
}
