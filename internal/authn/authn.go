// Package authn implements user authentication: password hashing, TOTP and
// the headless login session flow that completes OIDC auth requests.
package authn

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
	"github.com/zitadel/passwap"
	"github.com/zitadel/passwap/argon2"
	"github.com/zitadel/passwap/bcrypt"

	"github.com/aelboum/iam/internal/ratelimit"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/sizing"
	"github.com/aelboum/iam/internal/store"
)

var (
	// ErrInvalidCredentials is deliberately vague to avoid user enumeration.
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrLocked             = errors.New("user is locked")
	// ErrRateLimited is a caller- or tenant-attributable limit: a hard IP/key/
	// account limiter or the per-org password-login budget (A4). It maps to HTTP
	// 429 with a window-length Retry-After.
	ErrRateLimited = errors.New("too many attempts, try again later")
	// ErrOverloaded is a transient, server-side shed: all argon2 hashing slots
	// were busy past HashWaitTimeout. It is not caller-specific and clears in
	// sub-second to a few seconds, so it maps to HTTP 503 with a short Retry-After,
	// distinct from the caller-attributable ErrRateLimited (internal security
	// audit N12/R4). On the OIDC token endpoint it surfaces as server_error.
	ErrOverloaded       = errors.New("authentication temporarily overloaded")
	ErrSessionInvalid   = errors.New("session invalid or expired")
	ErrNotAuthenticated = errors.New("session is not fully authenticated")
	ErrNoAccess         = errors.New("user's org has no access to this application")
	ErrTOTPNotEnrolled  = errors.New("totp not enrolled")
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
	CodeKey [32]byte
	// PreviousCodeKeys are derived from IAM_MASTER_KEY_PREVIOUS, so codes issued
	// before a master key rotation keep working until they expire (audit M6).
	PreviousCodeKeys [][32]byte
	SessionLifetime  time.Duration
	MaxFailedLogins  int
	// Limits builds the rate limiters (in-memory or shared).
	Limits          ratelimit.Factory
	LockoutDuration time.Duration
	// HashWaitTimeout bounds how long a request waits for a password-hashing
	// slot before it is shed as ErrOverloaded (internal security audit N12).
	HashWaitTimeout time.Duration
	// OrgLoginLimit is the per-organization password-login budget (attempts per
	// minute, aggregated across the org's keys/accounts/IPs) (audit N12/A4).
	OrgLoginLimit int
}

type Service struct {
	store     *store.Store
	box       *secret.Box
	passwords *passwap.Swapper
	cfg       Config
	// accountLimit caps password/TOTP attempts per user, whatever the source IP.
	accountLimit ratelimit.Allower
	// orgLogin caps password-login (argon2) attempts per org, aggregated across
	// all of the org's keys, accounts and IPs (internal security audit N12/A4).
	orgLogin ratelimit.Allower
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
		// Burst a quarter of the per-minute budget, mirroring the login-key limiter.
		orgLogin:   cfg.Limits("login-org", float64(cfg.OrgLoginLimit), max(1, cfg.OrgLoginLimit/4)),
		httpClient: NewOutboundClient(cfg.DevMode),
		webauthn:   cfg.WebAuthn,
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

// VerifySecret checks a client secret against its hash. It returns (true, nil)
// on a match, (false, nil) for a genuine mismatch, and (false, err) for an
// overload (ErrOverloaded) or other error, so a hashing-overload shed is never
// reported as an invalid secret. It never returns (true, err) (internal security
// audit N12/R1). Callers must fail closed on a non-nil error (never grant) and
// should surface it as a transient/overload response, not invalid_client.
func (s *Service) VerifySecret(hash, v string) (bool, error) {
	if _, err := s.verify(hash, v); err != nil {
		if errors.Is(err, passwap.ErrPasswordMismatch) {
			return false, nil
		}
		return false, err
	}
	return true, nil
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

// maxTOTPEnrollAttempts bounds guessing of a pending enrollment code. The
// pending secret is only known to whoever started the enrollment, but the
// six-digit code itself was previously verifiable without any cap.
const maxTOTPEnrollAttempts = 5

func (s *Service) VerifyTOTPEnrollment(ctx context.Context, user *store.User, code string) error {
	reserved, err := s.store.ReserveTOTPEnrollAttempt(ctx, user.ID, maxTOTPEnrollAttempts)
	if err != nil {
		return err
	}
	if !reserved {
		return ErrRateLimited
	}
	ok, err := s.acceptTOTP(ctx, user, code)
	if err != nil {
		// The code was never evaluated: give the attempt back.
		_ = s.store.ReleaseTOTPEnrollAttempt(ctx, user.ID)
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
		if secret.Equal(hash, s.codeHash(user.ID, code)) {
			return true
		}
		for _, k := range s.cfg.PreviousCodeKeys {
			if secret.Equal(hash, secret.HMAC(k, user.ID+":"+code)) {
				return true
			}
		}
		return false
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

// StartPasswordReset issues a single-use reset token for a human user. It
// returns nil without error for unknown, machine and locked users and while
// the per-user cooldown is active, so the response never reveals whether an
// account exists (audit L1). Earlier tokens stay valid (audit L2).
//
// Trust note (audit D3): the token is handed to the calling login backend,
// which emails it. Any login-scoped key can therefore reset passwords of the
// users in its scope; login keys must only be given to backends you trust
// with account recovery.
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
			return nil, nil // same answer as an unknown user
		}
		return nil, err
	}
	s.audit(ctx, c, user, "user.password_reset_requested", nil)
	return &PasswordReset{Token: token, Email: user.Email, ExpiresAt: expires}, nil
}

// ConfirmPasswordReset sets a new password with a reset token. In one
// transaction the token is consumed, the password set, and every session,
// token and other reset token of the user ended. Locked and machine users are
// refused (audit M12). For an org-scoped key the token must belong to that org.
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
	// A manual lock (user.Locked) blocks recovery outright; a temporary lockout
	// (locked_until / mfa_locked_until) deliberately does not, so a user locked
	// out by failed logins can still recover their account. This is not a
	// lockout bypass: CompletePasswordReset leaves the temporary-lockout columns
	// intact (audit L3) and CheckPassword re-checks IsLocked()/IsMFALocked(), so
	// the new password cannot log in until the lockout expires. Guarded by
	// internal/authn/password_reset_lockout_test.go.
	if (c.OrgID != "" && c.OrgID != user.OrgID) || user.Locked || user.Kind != store.KindHuman {
		return ErrInvalidCredentials
	}
	hash, err := s.HashPassword(password, user.Username, user.Email)
	if err != nil {
		return err // the token is not used up by a rejected password
	}
	if err := s.store.CompletePasswordReset(ctx, secret.Hash(token), user.ID, hash); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrInvalidCredentials // used concurrently, or the user was locked meanwhile
		}
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
	// Per-org aggregate cap on password-login hashing, so one tenant cannot
	// monopolize the shared argon2 slots across many keys, accounts or IPs
	// (internal security audit N12/A4). Keyed on the server-resolved org id;
	// checked once per attempt, before any lockout counter or hashing, so a
	// shed attempt neither counts toward lockout nor spends a hash slot.
	if !s.orgLogin.Allow(sess.OrgID) {
		logOrgLoginLimited(sess.OrgID)
		return nil, ErrRateLimited
	}
	// Reserve the attempt before verifying, so parallel guesses cannot exceed
	// the lockout threshold. Unknown and locked users take the same path and
	// time, and get the same answer as a wrong password; a locked account's
	// password is never evaluated.
	// The password factor is blocked by a password lockout and, so a TOTP
	// lockout cannot be bypassed via the password/reset path, by a TOTP lockout
	// too (internal security audit N11). ReserveAttempt enforces the same in SQL.
	reserved := false
	if user != nil && !user.IsLocked() && !user.IsMFALocked() {
		if reserved, err = s.store.ReserveAttempt(ctx, user.ID, store.FactorPassword, s.cfg.MaxFailedLogins); err != nil {
			return nil, err
		}
	}
	if !reserved || !user.HasPassword() || utf8.RuneCountInString(password) > maxPasswordLength {
		// If hashing was shed under overload, the dummy check could not run, so
		// surface overload rather than invalid credentials — otherwise a known
		// user (503) and an unknown or locked one (401) would differ under load,
		// leaking which accounts exist (internal security audit N12).
		if errors.Is(s.verifyDummy(password), ErrOverloaded) {
			if reserved {
				s.releaseAttempt(ctx, user.ID, store.FactorPassword)
			}
			return nil, ErrOverloaded
		}
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
		if errors.Is(verr, passwap.ErrPasswordMismatch) {
			return nil, s.attemptFailed(ctx, c, user, store.FactorPassword)
		}
		// A non-mismatch error (hash overload shed, or an internal hashing error)
		// means the password was never evaluated. Release the reserved attempt so
		// a transient shed does not count as a failure and push a real user toward
		// lockout, then surface the error (internal security audit N12).
		s.releaseAttempt(ctx, user.ID, store.FactorPassword)
		return nil, verr
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
	if (sess.PasswordCheckedAt == nil && sess.IDPCheckedAt == nil) || user == nil {
		return nil, ErrNotAuthenticated // a first factor first, so TOTP cannot be probed alone
	}
	if !user.TOTPVerified {
		return nil, ErrTOTPNotEnrolled
	}
	if !s.accountLimit.Allow(attemptKey(sess)) {
		return nil, ErrRateLimited
	}
	// Only a manual lock or the TOTP-specific lockout blocks the second factor;
	// a password lockout must not, or a password-guesser could deny a valid SSO
	// user's mandatory TOTP step (internal security audit N11).
	if user.IsMFALocked() {
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
		// The code was never evaluated (e.g. an unreadable TOTP secret or a
		// transient store error), so release the reserved attempt rather than let
		// it advance the MFA lockout counter, mirroring the password path
		// (internal security audit N12).
		s.releaseAttempt(ctx, user.ID, store.FactorTOTP)
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

// hashSlots bounds concurrent password hashing across the whole process. Each
// argon2id run uses about 64 MiB, so unbounded parallel requests could exhaust
// memory. It defaults to a container-aware slot count (GOMAXPROCS, floored at 2)
// and can be resized once at startup by ConfigureHashSlots.
var hashSlots = make(chan struct{}, sizing.AutoHashSlots())

// ConfigureHashSlots sets the size of the process-wide hashing pool. It replaces
// the semaphore, so it must be called once at startup before the engine begins
// serving — the goroutine-creation that starts the HTTP server establishes the
// happens-before that makes the new value visible to request handlers. It must
// not be called while hashes are in flight: acquireHashSlot captures the channel
// at call time, so replacing it mid-flight would strand slots on the old pool. A
// count below 2 is floored at 2 so the pool is never degenerate.
func ConfigureHashSlots(slots int) {
	hashSlots = make(chan struct{}, max(2, slots))
}

// acquireHashSlot waits up to HashWaitTimeout for a hashing slot. If none frees
// in time it sheds the request as ErrOverloaded (mapped to HTTP 503) instead of
// queueing without bound, so one tenant cannot grow an unbounded hashing backlog
// for everyone else (internal security audit N12). The shed is a transient
// server condition, not a caller-attributable limit, so it is distinct from
// ErrRateLimited (N12/R4). It returns a release closure only when a slot was
// actually acquired, so a timed-out acquire leaks nothing.
func (s *Service) acquireHashSlot() (func(), error) {
	// Capture the channel so the release targets the same pool this acquire used,
	// even if ConfigureHashSlots were to replace the global meanwhile.
	ch := hashSlots
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-time.After(s.cfg.HashWaitTimeout):
		logHashShed(s.cfg.HashWaitTimeout)
		return nil, ErrOverloaded
	}
}

// hash-shed observability: count every shed but log at most once per second with
// the running total, so the warning cannot flood the logs under the very overload
// it reports (internal security audit N12/R3). No password, hash, key or token.
var (
	hashShedTotal atomic.Int64
	hashShedLogAt atomic.Int64 // unix-nanos of the last emitted warning
)

func logHashShed(wait time.Duration) {
	total := hashShedTotal.Add(1)
	now := time.Now().UnixNano()
	last := hashShedLogAt.Load()
	if now-last >= int64(time.Second) && hashShedLogAt.CompareAndSwap(last, now) {
		slog.Warn("password hashing overloaded; shedding requests", "shed_total", total, "wait", wait.String())
	}
}

// per-org login-budget observability: count every denial but log at most once
// per second with the running total, so it cannot flood the logs. The org id is
// an identifier, not a secret; no password/token is logged (audit N12/A4/R3).
var (
	orgLimitTotal atomic.Int64
	orgLimitLogAt atomic.Int64
)

func logOrgLoginLimited(orgID string) {
	total := orgLimitTotal.Add(1)
	now := time.Now().UnixNano()
	last := orgLimitLogAt.Load()
	if now-last >= int64(time.Second) && orgLimitLogAt.CompareAndSwap(last, now) {
		slog.Warn("per-org login budget exceeded; shedding", "org", orgID, "shed_total", total)
	}
}

func (s *Service) verify(hash, password string) (string, error) {
	release, err := s.acquireHashSlot()
	if err != nil {
		return "", err
	}
	defer release()
	return s.passwords.Verify(hash, password)
}

// verifyDummy spends the time of a real check, for unknown or locked users, so
// response time does not reveal them. It returns ErrOverloaded when hashing was
// shed, so the caller can report overload uniformly instead of as invalid
// credentials (internal security audit N12); a mismatch against the dummy hash
// is expected and reported as nil.
func (s *Service) verifyDummy(password string) error {
	if len(password) > maxPasswordLength*4 {
		password = password[:maxPasswordLength*4]
	}
	if _, err := s.verify(s.dummyHash, password); errors.Is(err, ErrOverloaded) {
		return ErrOverloaded
	}
	return nil
}

// releaseAttempt best-effort undoes a reserved login attempt for factor f that
// was never evaluated — because hashing was shed under overload (password) or an
// internal error prevented the factor from being checked (e.g. an unreadable
// TOTP secret). A failure here must not mask the error already being returned to
// the caller, so it is only logged.
func (s *Service) releaseAttempt(ctx context.Context, userID string, f store.Factor) {
	if err := s.store.ReleaseAttempt(ctx, userID, f); err != nil {
		slog.Warn("could not release an unevaluated login attempt", "factor", f, "error", err)
	}
}

func (s *Service) hash(password string) (string, error) {
	release, err := s.acquireHashSlot()
	if err != nil {
		return "", err
	}
	defer release()
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
	// resistant, counts as multi-factor), a federated login (plus TOTP when
	// enrolled, unless the IdP is trusted for MFA), or the password plus TOTP
	// when enrolled.
	var at *time.Time
	switch {
	case st.PasskeyChecked:
		// Synced (backup-eligible) passkeys are not bound to one device (audit L8).
		keyKind := "hwk"
		if sess.PasskeySynced {
			keyKind = "swk"
		}
		at, st.AMR = sess.PasskeyCheckedAt, []string{keyKind, "user", "mfa"}
	case st.IDPChecked && sess.IDPTrustMFA:
		// An instance admin trusts this IdP to enforce MFA (audit D1).
		at, st.AMR = sess.IDPCheckedAt, []string{"fed", "mfa"}
	case st.IDPChecked && (!st.MFARequired || st.TOTPChecked):
		// Otherwise users who enrolled TOTP must still enter it after SSO.
		at, st.AMR = sess.IDPCheckedAt, []string{"fed"}
		if st.TOTPChecked {
			st.AMR = append(st.AMR, "otp", "mfa")
			if sess.TOTPCheckedAt.After(*at) {
				at = sess.TOTPCheckedAt
			}
		}
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
	// Manual lock only, consistent with the OP storage check: a temporary
	// failed-guess lockout must not block finalizing an already-authenticated
	// session (the first factor already succeeded under its own lockout).
	if user.Locked {
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
