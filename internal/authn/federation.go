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
	"net/netip"
	"net/url"
	"slices"
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

// ErrBadBinding means the browser binding is missing or too weak.
var ErrBadBinding = WeakPasswordError("browser_binding must be 43 to 512 characters of random data from the login UI's cookie")

// ErrUnsafeIdP means an IdP advertised an endpoint the engine refuses to use.
var ErrUnsafeIdP = errors.New("identity provider advertises an unsafe endpoint")

// StartFederatedLogin creates a login intent for one of the org's IdPs.
//
// browserBinding is a random secret (at least 256 bits, e.g. 32 random bytes
// base64url) that the login UI stores in an HttpOnly, Secure, SameSite=Lax
// cookie on its own origin before redirecting to the IdP. Redemption must
// present the same value, read from the cookie of the browser that returns,
// so a callback URL captured by an attacker cannot log a victim's browser
// into the attacker's account (login CSRF, audit M3).
func (s *Service) StartFederatedLogin(ctx context.Context, orgID, idpID, returnURL, browserBinding string) (*FederationStart, error) {
	if len(browserBinding) < 43 || len(browserBinding) > 512 {
		return nil, ErrBadBinding
	}
	idp, err := s.store.GetIDP(ctx, idpID)
	if err != nil || idp.OrgID != orgID {
		return nil, store.ErrNotFound
	}
	party, err := s.relyingParty(ctx, idp)
	if err != nil {
		return nil, fmt.Errorf("identity provider unavailable: %w", err)
	}
	// The discovery document is tenant-controlled: check every endpoint the
	// engine or the user's browser will be sent to (audit M4).
	endpoint := party.OAuthConfig().Endpoint
	for _, u := range []string{endpoint.AuthURL, endpoint.TokenURL, party.UserinfoEndpoint()} {
		if u != "" && !SafeIdPURL(u, s.cfg.DevMode) {
			return nil, fmt.Errorf("%w: %s", ErrUnsafeIdP, u)
		}
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
		BindingHash:     secret.Hash(browserBinding),
		ExpiresAt:       time.Now().Add(intentLifetime),
	}
	authURL := rp.AuthURL(state, party,
		rp.WithCodeChallenge(base64.RawURLEncoding.EncodeToString(challenge[:])),
		rp.AuthURLOpt(rp.WithURLParam("nonce", nonce)))
	if !SafeIdPURL(authURL, s.cfg.DevMode) {
		return nil, fmt.Errorf("%w: %s", ErrUnsafeIdP, authURL)
	}
	if err := s.store.CreateIntent(ctx, intent); err != nil {
		return nil, err
	}
	return &FederationStart{IntentID: intent.ID, AuthURL: authURL}, nil
}

// SafeIdPURL accepts absolute https URLs with a host and no embedded
// credentials or fragment; plain http only in dev mode. It is used for every
// endpoint taken from an IdP's discovery document and for the authorization
// URL handed to the login UI, which must never be javascript:, data: or similar.
func SafeIdPURL(raw string, devMode bool) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || len(raw) > 4096 {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return devMode
	default:
		return false
	}
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
		// Never log the raw error: a database unique-violation echoes the
		// conflicting value (e.g. the user's email) into the message. Log a
		// coarse reason, and for an unexpected error only its Go type, which
		// carries no user data.
		switch {
		case errors.Is(err, ErrLocked):
			slog.InfoContext(ctx, "federated login refused", "idp", idp.ID, "reason", "locked")
			return failed("locked")
		case errors.Is(err, ErrNoAccount):
			slog.InfoContext(ctx, "federated login refused", "idp", idp.ID, "reason", "no_account")
		default:
			slog.ErrorContext(ctx, "federated login refused", "idp", idp.ID, "reason", "internal", "error_type", fmt.Sprintf("%T", err))
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
// existing link (by IdP and subject, never by email), else (if allowed) an
// existing user with the same verified email, else (if allowed) a new user.
//
// The IdP is configured by the tenant, so its email claims are only trusted
// when an instance admin set trust_email: otherwise new users get an
// unverified email and no account is linked by email (audit M2). The email
// domain allowlist only limits who may be provisioned or linked; it is never
// treated as proof of identity (audit M11).
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

	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if !ValidEmail(email) {
		email = ""
	}
	// IdP-asserted verification, honoured only for IdPs an instance admin trusts.
	verified := email != "" && bool(claims.EmailVerified) && idp.TrustEmail
	if len(idp.AllowedEmailDomains) > 0 {
		// Only identities with an IdP-verified email in an allowed domain may
		// be provisioned or linked; the subject remains the identity.
		_, domain, _ := strings.Cut(email, "@")
		if email == "" || !bool(claims.EmailVerified) || !slices.Contains(idp.AllowedEmailDomains, domain) {
			return nil, ErrNoAccount
		}
	}
	if idp.LinkByEmail && verified {
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
	if email == "" {
		sum := sha256.Sum256([]byte(idp.ID + "\x00" + claims.Subject))
		email = "idp-" + hex.EncodeToString(sum[:8]) + "@idp.invalid"
	}
	created, err := s.store.CreateUser(ctx, store.NewUser{
		OrgID: idp.OrgID, Username: email, Email: email, EmailVerified: verified,
		GivenName: cleanName(claims.GivenName), FamilyName: cleanName(claims.FamilyName),
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

// RedeemFederatedLogin exchanges a completed intent for an authenticated
// session. browserBinding must be the value given to StartFederatedLogin,
// read from the returning browser's cookie; otherwise the intent is used up
// and refused (audit M3).
func (s *Service) RedeemFederatedLogin(ctx context.Context, c Client, intentID, code, browserBinding string) (*SessionState, error) {
	userID, idpID, bindingHash, err := s.store.RedeemIntent(ctx, intentID, secret.Hash(code))
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if bindingHash == "" || !secret.Equal(bindingHash, secret.Hash(browserBinding)) {
		return nil, ErrInvalidCredentials
	}
	idp, err := s.store.GetIDP(ctx, idpID)
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
	if err := s.store.MarkSessionIDP(ctx, sess.ID, idp.TrustMFA); err != nil {
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

// ValidEmail is a conservative syntax check for email addresses taken from
// external claims: one @, a non-empty local part, a dotted domain of DNS
// labels, no whitespace or control characters, at most 254 bytes.
func ValidEmail(email string) bool {
	if len(email) > 254 || strings.ContainsFunc(email, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return false
	}
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" || len(local) > 64 || strings.Contains(domain, "@") {
		return false
	}
	return ValidDomain(domain) && strings.Contains(domain, ".")
}

// ValidDomain checks a DNS name: 1-253 bytes, labels of 1-63 letters, digits
// and hyphens, not starting or ending with a hyphen. No wildcards.
func ValidDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

// cleanName bounds names from external claims and drops control characters.
func cleanName(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, v)
	return truncate(strings.TrimSpace(v), 100)
}

// NewOutboundClient returns the HTTP client used to talk to external IdPs.
// Unless allowPrivate is set (dev mode), it refuses to connect to loopback,
// private and link-local addresses: org admins choose the issuer URL, and
// must not be able to make the engine probe the internal network (SSRF).
// The check runs on the resolved address, so DNS tricks do not bypass it.
//
// Outside dev mode it also only speaks https (every hop, including redirects
// and endpoints taken from discovery) and caps response bodies (audit M4, L4).
func NewOutboundClient(devMode bool) *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			if devMode {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(host)
			if err != nil || !PublicAddress(addr) {
				return fmt.Errorf("refusing to connect to non-public address %s", host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &guardedTransport{
			allowHTTP: devMode,
			base: &http.Transport{
				DialContext:            dialer.DialContext,
				TLSHandshakeTimeout:    5 * time.Second,
				ResponseHeaderTimeout:  5 * time.Second,
				MaxIdleConns:           20,
				MaxResponseHeaderBytes: 64 << 10,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
}

// maxIdPResponse caps the bytes read from an IdP response (discovery, JWKS,
// token, userinfo); real responses are a few kilobytes.
const maxIdPResponse = 1 << 20

// guardedTransport refuses non-https requests (unless allowHTTP) and caps
// response bodies. Redirects pass through RoundTrip too, so they are checked.
type guardedTransport struct {
	base      http.RoundTripper
	allowHTTP bool
}

func (t *guardedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" && !(t.allowHTTP && req.URL.Scheme == "http") {
		return nil, fmt.Errorf("refusing non-https request to %s", req.URL.Host)
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, maxIdPResponse)
	return resp, nil
}

// nonPublicPrefixes are ranges that are not reachable public internet hosts,
// beyond what netip's classification already covers (audit L4).
var nonPublicPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, p := range []string{
		"0.0.0.0/8",       // "this network"
		"100.64.0.0/10",   // carrier-grade NAT; includes Alibaba Cloud metadata 100.100.100.200
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // documentation
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // documentation
		"203.0.113.0/24",  // documentation
		"240.0.0.0/4",     // reserved, includes broadcast
		"64:ff9b::/96",    // NAT64 (embeds an IPv4 address)
		"64:ff9b:1::/48",  // local NAT64
		"100::/64",        // discard
		"2001::/32",       // Teredo (embeds an IPv4 address)
		"2001:db8::/32",   // documentation
		"2002::/16",       // 6to4 (embeds an IPv4 address)
		"fc00::/7",        // unique local
	} {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}()

// PublicAddress reports whether addr is a public unicast address the engine
// may connect to for an IdP. IPv4-mapped IPv6 addresses are checked as IPv4.
func PublicAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() || addr.IsInterfaceLocalMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}
