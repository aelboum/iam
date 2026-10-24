package authn

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
)

// Federated login ("bring your own SSO"): an org configures its own OpenID
// Connect provider. The flow is
//
//  1. the login UI backend calls StartFederatedLogin and sends the browser to
//     the returned AuthURL (the org's IdP);
//  2. the IdP returns the browser to {issuer}/idp/callback, where
//     HandleCallback verifies the ID token (signature, issuer, audience,
//     nonce, PKCE) and links or creates the local user;
//  3. the browser lands on the login UI's return URL with ?intent=&code=,
//     and the backend exchanges them for a session with RedeemFederatedLogin.

var ErrNoAccount = errors.New("no account for this identity")

const intentLifetime = 10 * time.Minute

// CallbackPath is where external IdPs redirect back to the engine.
const CallbackPath = "/idp/callback"

type FederationStart struct {
	IntentID string `json:"intent_id"`
	AuthURL  string `json:"auth_url"`
}

type nonceKey struct{}

func (s *Service) relyingParty(ctx context.Context, idp *store.IDP) (rp.RelyingParty, error) {
	clientSecret, err := s.box.Open(idp.ClientSecretEnc)
	if err != nil {
		return nil, err
	}
	return rp.NewRelyingPartyOIDC(ctx, idp.Issuer, idp.ClientID, string(clientSecret),
		s.cfg.Issuer+CallbackPath, idp.Scopes,
		rp.WithHTTPClient(s.httpClient),
		rp.WithVerifierOpts(rp.WithNonce(func(ctx context.Context) string {
			nonce, _ := ctx.Value(nonceKey{}).(string)
			return nonce
		})),
	)
}

// StartFederatedLogin creates a login intent for one of the org's IdPs.
func (s *Service) StartFederatedLogin(ctx context.Context, orgID, idpID, returnURL string) (*FederationStart, error) {
	idp, err := s.store.GetIDP(ctx, idpID)
	if err != nil || idp.OrgID != orgID {
		return nil, store.ErrNotFound
	}
	party, err := s.relyingParty(ctx, idp)
	if err != nil {
		return nil, fmt.Errorf("identity provider unavailable: %w", err)
	}
	state, nonce, verifier := secret.Token(32), secret.Token(32), secret.Token(32)
	challenge := sha256.Sum256([]byte(verifier))
	intent := &store.Intent{
		ID:              uuid.NewString(),
		IDPID:           idp.ID,
		StateHash:       secret.Hash(state),
		Nonce:           nonce,
		CodeVerifierEnc: s.box.Seal([]byte(verifier)),
		ReturnURL:       returnURL,
		ExpiresAt:       time.Now().Add(intentLifetime),
	}
	if err := s.store.CreateIntent(ctx, intent); err != nil {
		return nil, err
	}
	authURL := rp.AuthURL(state, party,
		rp.WithCodeChallenge(base64.RawURLEncoding.EncodeToString(challenge[:])),
		rp.AuthURLOpt(rp.WithURLParam("nonce", nonce)))
	return &FederationStart{IntentID: intent.ID, AuthURL: authURL}, nil
}

// HandleCallback completes the IdP round trip and returns where to send the
// browser. Errors without a matching intent mean a forged or replayed callback.
func (s *Service) HandleCallback(ctx context.Context, state, code, idpError string) (string, error) {
	intent, err := s.store.ClaimIntent(ctx, secret.Hash(state))
	if err != nil {
		return "", ErrSessionInvalid
	}
	failed := func(reason string) (string, error) {
		return withQuery(intent.ReturnURL, "intent", intent.ID, "error", reason), nil
	}
	if idpError != "" || code == "" {
		return failed("access_denied")
	}
	idp, err := s.store.GetIDP(ctx, intent.IDPID)
	if err != nil {
		return failed("idp_error")
	}
	party, err := s.relyingParty(ctx, idp)
	if err != nil {
		slog.WarnContext(ctx, "identity provider unavailable", "idp", idp.ID, "error", err)
		return failed("idp_error")
	}
	verifier, err := s.box.Open(intent.CodeVerifierEnc)
	if err != nil {
		return "", err
	}
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](context.WithValue(ctx, nonceKey{}, intent.Nonce),
		code, party, rp.WithCodeVerifier(string(verifier)))
	if err != nil || tokens.IDTokenClaims == nil {
		slog.WarnContext(ctx, "federated code exchange failed", "idp", idp.ID, "error", err)
		return failed("idp_error")
	}
	claims := tokens.IDTokenClaims
	if claims.Email == "" && tokens.AccessToken != "" {
		// Many IdPs only release profile claims at the userinfo endpoint. The
		// library checks that userinfo's subject matches the ID token's.
		if info, err := rp.Userinfo[*oidc.UserInfo](ctx, tokens.AccessToken, tokens.TokenType, claims.Subject, party); err == nil {
			claims.Email, claims.EmailVerified = info.Email, info.EmailVerified
			if claims.GivenName == "" {
				claims.GivenName, claims.FamilyName = info.GivenName, info.FamilyName
			}
		}
	}
	user, err := s.resolveFederatedUser(ctx, idp, claims)
	if err != nil {
		slog.InfoContext(ctx, "federated login refused", "idp", idp.ID, "error", err)
		if errors.Is(err, ErrLocked) {
			return failed("locked")
		}
		return failed("no_account")
	}
	redeem := secret.Token(32)
	if err := s.store.CompleteIntent(ctx, intent.ID, user.ID, secret.Hash(redeem)); err != nil {
		return "", err
	}
	s.audit(ctx, Client{}, user, "login.federated", map[string]any{"idp_id": idp.ID})
	return withQuery(intent.ReturnURL, "intent", intent.ID, "code", redeem), nil
}

// resolveFederatedUser finds the local user for an external identity: an
// existing link, else (if allowed) an existing user with the same verified
// email, else (if allowed) a new user.
func (s *Service) resolveFederatedUser(ctx context.Context, idp *store.IDP, claims *oidc.IDTokenClaims) (*store.User, error) {
	user, err := s.store.FindIdentity(ctx, idp.ID, claims.Subject)
	if err == nil {
		if user.OrgID != idp.OrgID {
			return nil, ErrNoAccount
		}
		if user.IsLocked() {
			return nil, ErrLocked
		}
		return user, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	email := strings.TrimSpace(claims.Email)
	verified := bool(claims.EmailVerified)
	if idp.LinkByEmail && email != "" && verified {
		if existing, err := s.store.FindUserForLogin(ctx, idp.OrgID, email); err == nil {
			if err := s.store.LinkIdentity(ctx, idp.ID, claims.Subject, existing.ID); err != nil {
				return nil, err
			}
			return existing, nil
		}
	}
	if !idp.AutoCreateUsers {
		return nil, ErrNoAccount
	}
	if email == "" || !strings.Contains(email, "@") {
		sum := sha256.Sum256([]byte(idp.ID + "\x00" + claims.Subject))
		email, verified = "idp-"+hex.EncodeToString(sum[:8])+"@idp.invalid", false
	}
	created, err := s.store.CreateUser(ctx, store.NewUser{
		OrgID: idp.OrgID, Username: email, Email: email, EmailVerified: verified,
		GivenName: truncate(claims.GivenName, 100), FamilyName: truncate(claims.FamilyName, 100),
	})
	if err != nil {
		// Most likely a local user already has this email; an admin must link it.
		return nil, fmt.Errorf("%w: %v", ErrNoAccount, err)
	}
	if err := s.store.LinkIdentity(ctx, idp.ID, claims.Subject, created.ID); err != nil {
		return nil, err
	}
	return created, nil
}

// RedeemFederatedLogin exchanges a completed intent for an authenticated session.
func (s *Service) RedeemFederatedLogin(ctx context.Context, c Client, intentID, code string) (*SessionState, error) {
	userID, _, err := s.store.RedeemIntent(ctx, intentID, secret.Hash(code))
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if c.OrgID != "" && c.OrgID != user.OrgID {
		return nil, ErrInvalidCredentials
	}
	if user.IsLocked() {
		return nil, ErrLocked
	}
	token := secret.Token(32)
	sess, err := s.store.CreateSession(ctx, user.OrgID, &user.ID, strings.ToLower(user.Username),
		secret.Hash(token), time.Now().Add(s.cfg.SessionLifetime))
	if err != nil {
		return nil, err
	}
	if err := s.store.MarkSessionIDP(ctx, sess.ID); err != nil {
		return nil, err
	}
	st, err := s.GetSession(ctx, c, sess.ID, token)
	if err != nil {
		return nil, err
	}
	st.Token = token
	return st, nil
}

func withQuery(raw string, kv ...string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func truncate(v string, n int) string {
	if len(v) > n {
		return v[:n]
	}
	return v
}

// NewOutboundClient returns the HTTP client used to talk to external IdPs.
// Unless allowPrivate is set (dev mode), it refuses to connect to loopback,
// private and link-local addresses: org admins choose the issuer URL, and
// must not be able to make the engine probe the internal network (SSRF).
// The check runs on the resolved address, so DNS tricks do not bypass it.
func NewOutboundClient(allowPrivate bool) *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			if allowPrivate {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
				return fmt.Errorf("refusing to connect to internal address %s", host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			MaxIdleConns:        20,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}
