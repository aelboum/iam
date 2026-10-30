// Package oidcop wires the engine's storage into the zitadel/oidc OpenID
// Provider, which implements the protocol (authorize, token, userinfo,
// introspection, revocation, end session, discovery, JWKS).
package oidcop

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/aelboum/iam/internal/authn"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/store"
)

const (
	// authRequestLifetime is how long a user has to finish logging in.
	authRequestLifetime = 30 * time.Minute
	// authCodeLifetime is how long an issued authorization code stays valid.
	authCodeLifetime = 5 * time.Minute
)

type TokenConfig struct {
	KeyRotation   time.Duration
	AccessToken   time.Duration
	RefreshIdle   time.Duration // refresh token expires if unused this long
	SessionMaxAge time.Duration // absolute limit since login, refresh cannot extend it
}

type Storage struct {
	store *store.Store
	authn *authn.Service
	keys  *keyStore
	cfg   TokenConfig
}

var (
	_ op.Storage                        = (*Storage)(nil)
	_ op.CanSetUserinfoFromRequest      = (*Storage)(nil)
	_ op.CanGetPrivateClaimsFromRequest = (*Storage)(nil)
)

func NewStorage(st *store.Store, an *authn.Service, box *secret.Box, cfg TokenConfig) *Storage {
	return &Storage{
		store: st,
		authn: an,
		keys:  newKeyStore(st, box, cfg.KeyRotation),
		cfg:   cfg,
	}
}

// --- auth requests --------------------------------------------------------------------

func (s *Storage) CreateAuthRequest(ctx context.Context, req *oidc.AuthRequest, userID string) (op.AuthRequest, error) {
	if slices.Contains(req.Prompt, oidc.PromptNone) {
		// The engine keeps no browser SSO session, so silent login is impossible.
		return nil, oidc.ErrLoginRequired()
	}
	// PKCE is required for every interactive client (audit L1). Only web, spa and
	// native apps reach /authorize; machine clients use client_credentials and
	// never create an auth request. For public clients (spa/native) PKCE is the
	// only protection against a stolen authorization code; for confidential web
	// clients it is defence-in-depth per OAuth 2.1, binding the code to the
	// client instance that began the flow even if the client secret leaks.
	if req.CodeChallenge == "" {
		return nil, oidc.ErrInvalidRequest().WithDescription("PKCE (code_challenge, S256) is required")
	}
	if req.CodeChallengeMethod != oidc.CodeChallengeMethodS256 {
		return nil, oidc.ErrInvalidRequest().WithDescription("code_challenge_method must be S256")
	}
	// Bound the free-form parameters an unauthenticated caller can get stored
	// via /authorize (they live 30 minutes), so a client_id + redirect_uri
	// cannot be used to inflate the database (internal security audit B2).
	const maxParam = 2048
	if len(req.State) > maxParam || len(req.Nonce) > maxParam || len(req.LoginHint) > maxParam {
		return nil, oidc.ErrInvalidRequest().WithDescription("request parameter too long")
	}
	if len(req.Scopes) > 64 {
		return nil, oidc.ErrInvalidRequest().WithDescription("too many scopes")
	}
	for _, sc := range req.Scopes {
		if len(sc) > maxParam {
			return nil, oidc.ErrInvalidRequest().WithDescription("scope too long")
		}
	}
	r := &store.AuthRequest{
		ID:          uuid.NewString(),
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		// State is the relying party's CSRF token. Per RFC 6749 §10.12 the OP
		// echoes it back to the client unchanged; binding state to the end
		// user's browser session is the relying party's responsibility, not the
		// provider's, and provider-side binding is neither required nor
		// sufficient for the client's CSRF defence. Where IAM is itself the RP
		// (federation) it does bind the browser, see internal/authn/federation.go.
		// See docs/SECURITY.md ("Integrator responsibility — OAuth state").
		State:               req.State,
		Nonce:               req.Nonce,
		Scopes:              req.Scopes,
		ResponseType:        string(req.ResponseType),
		ResponseMode:        string(req.ResponseMode),
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: string(req.CodeChallengeMethod),
		Prompt:              []string(req.Prompt),
		LoginHint:           req.LoginHint,
		ExpiresAt:           time.Now().Add(authRequestLifetime),
	}
	if r.Scopes == nil {
		r.Scopes = []string{}
	}
	if r.Prompt == nil {
		r.Prompt = []string{}
	}
	if req.MaxAge != nil {
		v := int32(min(*req.MaxAge, math.MaxInt32)) // no wrap-around on huge values
		r.MaxAgeSeconds = &v
	}
	created, err := s.store.CreateAuthRequest(ctx, r)
	if err != nil {
		return nil, err
	}
	return &authRequest{created}, nil
}

func (s *Storage) AuthRequestByID(ctx context.Context, id string) (op.AuthRequest, error) {
	r, err := s.store.GetAuthRequest(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("auth request: %w", err)
	}
	return &authRequest{r}, nil
}

// AuthRequestByCode only looks the code up. The library checks PKCE and the
// client secret after this call, so claiming the code here would let anyone
// who saw a code burn it with a wrong verifier. The code is claimed in
// claimCode, once tokens are about to be issued.
func (s *Storage) AuthRequestByCode(ctx context.Context, code string) (op.AuthRequest, error) {
	r, err := s.store.GetAuthRequestByCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("auth code: %w", err)
	}
	return &authRequest{r}, nil
}

// claimCode atomically marks the request's code used (only one of concurrent
// exchanges wins) and re-checks that the user may still use the client.
func (s *Storage) claimCode(ctx context.Context, ar *authRequest) error {
	if err := s.store.ClaimAuthCode(ctx, ar.GetID()); err != nil {
		return oidc.ErrInvalidGrant().WithDescription("authorization code already used")
	}
	if err := s.checkUserCanUseClient(ctx, ar.GetSubject(), ar.GetClientID()); err != nil {
		return oidc.ErrInvalidGrant().WithDescription("%s", err.Error())
	}
	return nil
}

func (s *Storage) SaveAuthCode(ctx context.Context, id, code string) error {
	return s.store.SetAuthCode(ctx, id, code, authCodeLifetime)
}

func (s *Storage) DeleteAuthRequest(ctx context.Context, id string) error {
	return s.store.DeleteAuthRequest(ctx, id)
}

// --- tokens ------------------------------------------------------------------------------

func (s *Storage) CreateAccessToken(ctx context.Context, req op.TokenRequest) (string, time.Time, error) {
	if jr, ok := req.(*oidc.JWTTokenRequest); ok {
		return s.machineAccessToken(ctx, jr) // client credentials grant
	}
	ar, ok := req.(*authRequest)
	if !ok {
		return "", time.Time{}, fmt.Errorf("unsupported token request %T", req)
	}
	if err := s.claimCode(ctx, ar); err != nil {
		return "", time.Time{}, err
	}
	at := &store.AccessToken{
		ID:        uuid.NewString(),
		ClientID:  ar.GetClientID(),
		Subject:   ar.GetSubject(),
		Audience:  ar.GetAudience(),
		Scopes:    ar.GetScopes(),
		ExpiresAt: time.Now().Add(s.cfg.AccessToken),
	}
	if err := s.store.CreateTokens(ctx, at, nil); err != nil {
		return "", time.Time{}, err
	}
	return at.ID, at.ExpiresAt, nil
}

func (s *Storage) CreateAccessAndRefreshTokens(ctx context.Context, req op.TokenRequest, currentRefreshToken string) (string, string, time.Time, error) {
	var clientID string
	var amr []string
	var authTime time.Time
	switch r := req.(type) {
	case *authRequest:
		if err := s.claimCode(ctx, r); err != nil {
			return "", "", time.Time{}, err
		}
		clientID, amr, authTime = r.GetClientID(), r.GetAMR(), r.GetAuthTime()
	case *refreshTokenRequest:
		clientID, amr, authTime = r.GetClientID(), r.GetAMR(), r.GetAuthTime()
	default:
		return "", "", time.Time{}, fmt.Errorf("unsupported token request %T", req)
	}

	now := time.Now()
	// Idle expiry slides with each refresh, but never past the absolute
	// session limit counted from the original login.
	refreshExpiry := now.Add(s.cfg.RefreshIdle)
	if limit := authTime.Add(s.cfg.SessionMaxAge); limit.Before(refreshExpiry) {
		refreshExpiry = limit
	}
	if !refreshExpiry.After(now) {
		return "", "", time.Time{}, oidc.ErrInvalidGrant().WithDescription("session expired, sign in again")
	}
	refreshValue := secret.Token(32)
	at := &store.AccessToken{
		ID:        uuid.NewString(),
		ClientID:  clientID,
		Subject:   req.GetSubject(),
		Audience:  req.GetAudience(),
		Scopes:    req.GetScopes(),
		ExpiresAt: now.Add(s.cfg.AccessToken),
	}
	if at.ExpiresAt.After(refreshExpiry) {
		at.ExpiresAt = refreshExpiry
	}
	rt := &store.RefreshToken{
		ID:            uuid.NewString(),
		TokenHash:     secret.Hash(refreshValue),
		ClientID:      clientID,
		Subject:       req.GetSubject(),
		Audience:      req.GetAudience(),
		Scopes:        req.GetScopes(),
		AMR:           amr,
		AuthTime:      authTime,
		AccessTokenID: &at.ID,
		ExpiresAt:     refreshExpiry,
	}
	rt.FamilyID = rt.ID // a new login starts a family; rotation overwrites it
	at.RefreshTokenID = &rt.ID
	if rt.AMR == nil {
		rt.AMR = []string{}
	}

	var err error
	if currentRefreshToken == "" {
		err = s.store.CreateTokens(ctx, at, rt)
	} else {
		// Rotation: the presented refresh token is consumed and can never be reused.
		err = s.store.RotateRefreshToken(ctx, secret.Hash(currentRefreshToken), at, rt)
		if errors.Is(err, store.ErrNotFound) {
			err = oidc.ErrInvalidGrant().WithDescription("refresh token invalid or already used")
		}
	}
	if err != nil {
		return "", "", time.Time{}, err
	}
	return at.ID, refreshValue, at.ExpiresAt, nil
}

func (s *Storage) TokenRequestByRefreshToken(ctx context.Context, refreshToken string) (op.RefreshTokenRequest, error) {
	t, err := s.store.GetRefreshTokenByHash(ctx, secret.Hash(refreshToken))
	if err != nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("invalid refresh token")
	}
	if t.UsedAt != nil {
		// A rotated-out token came back: either the client or an attacker holds
		// a stolen copy. Revoke the whole login so neither can continue.
		if err := s.store.RevokeRefreshFamily(ctx, t.FamilyID); err != nil {
			return nil, err
		}
		s.auditToken(ctx, t, "token.refresh_reuse_detected")
		return nil, oidc.ErrInvalidGrant().WithDescription("refresh token reuse detected; session revoked")
	}
	// Refuse to refresh for users who were locked, deleted or lost access.
	if err := s.checkUserCanUseClient(ctx, t.Subject, t.ClientID); err != nil {
		return nil, oidc.ErrInvalidGrant().WithDescription("%s", err.Error())
	}
	return &refreshTokenRequest{t}, nil
}

func (s *Storage) checkUserCanUseClient(ctx context.Context, userID, clientID string) error {
	app, err := s.store.GetAppByClientID(ctx, clientID)
	if err != nil {
		return errors.New("client not found")
	}
	return s.checkUserCanUseProject(ctx, userID, app.ProjectID)
}

func (s *Storage) checkUserCanUseProject(ctx context.Context, userID, projectID string) error {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}
	// Only the manual lock ends existing sessions. A temporary lockout from
	// failed logins does not, or anyone could log a user out by guessing.
	if user.Locked {
		return authn.ErrLocked
	}
	if projectID == "" {
		return nil // machine token without a project: org claims only
	}
	if _, ok, err := s.store.AvailableRoles(ctx, projectID, user.OrgID); err != nil {
		return err
	} else if !ok {
		return authn.ErrNoAccess
	}
	return nil
}

func (s *Storage) TerminateSession(ctx context.Context, userID, clientID string) error {
	return s.store.TerminateTokens(ctx, userID, clientID)
}

// TerminateSessionFromRequest handles an RP-initiated logout (`end_session`).
// The library calls this in place of TerminateSession because Storage satisfies
// op.CanTerminateSessionFromRequest.
//
// A verified id_token_hint is required to revoke anything. Without one the
// request carries no user identity (req.UserID is empty, since the library only
// populates it from a validated id_token_hint), so there is nothing to revoke
// by — and revoking by client_id alone would let any unauthenticated caller end
// every user's session for that client, a logout CSRF / denial of service.
// Returning an invalid_request error here makes the endpoint reject hint-less
// logout with a clear 400 instead of redirecting to a false "signed out" while
// the access and refresh tokens keep working (audit L-01).
func (s *Storage) TerminateSessionFromRequest(ctx context.Context, req *op.EndSessionRequest) (string, error) {
	if req.UserID == "" {
		return "", oidc.ErrInvalidRequest().WithDescription("id_token_hint is required to end the session")
	}
	if err := s.store.TerminateTokens(ctx, req.UserID, req.ClientID); err != nil {
		return "", err
	}
	return req.RedirectURI, nil
}

// RevokeToken is called by the library in three shapes:
//   - a refresh token resolved by GetRefreshTokenInfo: tokenOrTokenID is the
//     refresh token's row id and userID is set;
//   - an access token: tokenOrTokenID is the access token id and userID is set;
//   - anything unresolved (e.g. an already used refresh token): the raw value
//     and an empty userID.
//
// Revoking a refresh token revokes its whole family (the login).
func (s *Storage) RevokeToken(ctx context.Context, tokenOrTokenID, userID, clientID string) *oidc.Error {
	var rt *store.RefreshToken
	if userID != "" {
		if t, err := s.store.GetRefreshTokenByID(ctx, tokenOrTokenID); err == nil {
			rt = t
		} else if at, err := s.store.GetAccessToken(ctx, tokenOrTokenID); err == nil {
			if at.ClientID != clientID {
				return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
			}
			if err := s.store.DeleteAccessToken(ctx, at.ID); err != nil {
				return oidc.ErrServerError().WithParent(err)
			}
			return nil
		}
	} else if t, err := s.store.GetRefreshTokenByHash(ctx, secret.Hash(tokenOrTokenID)); err == nil {
		rt = t
	}
	if rt == nil {
		return nil // unknown or already invalid: revocation is idempotent (RFC 7009)
	}
	if rt.ClientID != clientID {
		return oidc.ErrInvalidClient().WithDescription("token was not issued for this client")
	}
	if err := s.store.RevokeRefreshFamily(ctx, rt.FamilyID); err != nil {
		return oidc.ErrServerError().WithParent(err)
	}
	return nil
}

func (s *Storage) GetRefreshTokenInfo(ctx context.Context, clientID, token string) (string, string, error) {
	t, err := s.store.GetRefreshTokenByHash(ctx, secret.Hash(token))
	if err != nil || t.ClientID != clientID || t.UsedAt != nil {
		return "", "", op.ErrInvalidRefreshToken
	}
	return t.Subject, t.ID, nil
}

// --- keys -----------------------------------------------------------------------------------

func (s *Storage) SigningKey(ctx context.Context) (op.SigningKey, error) {
	return s.keys.SigningKey(ctx)
}

func (s *Storage) SignatureAlgorithms(context.Context) ([]jose.SignatureAlgorithm, error) {
	return []jose.SignatureAlgorithm{jose.RS256}, nil
}

func (s *Storage) KeySet(ctx context.Context) ([]op.Key, error) {
	return s.keys.KeySet(ctx)
}

// --- clients ---------------------------------------------------------------------------------

func (s *Storage) GetClientByClientID(ctx context.Context, clientID string) (op.Client, error) {
	app, err := s.store.GetAppByClientID(ctx, clientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient().WithDescription("client not found")
	}
	return &client{app}, nil
}

// AuthorizeClientIDSecret authenticates apps, and machine users so they can
// revoke their own tokens (audit L6). A machine user gains nothing else from
// it: the code and refresh grants look the client up with GetClientByClientID,
// which only knows apps, and introspection only answers apps.
func (s *Storage) AuthorizeClientIDSecret(ctx context.Context, clientID, clientSecret string) error {
	if app, err := s.store.GetAppByClientID(ctx, clientID); err == nil {
		if app.ClientSecretHash != nil {
			ok, verr := s.authn.VerifySecret(*app.ClientSecretHash, clientSecret)
			if verr != nil { // overload etc.: do not claim the secret is invalid
				return oidc.ErrServerError().WithDescription("authentication temporarily unavailable")
			}
			if ok {
				return nil
			}
		}
		return oidc.ErrInvalidClient().WithDescription("invalid client credentials")
	}
	if m, err := s.store.GetMachineUserByClientID(ctx, clientID); err == nil && !m.Locked && m.ClientSecretHash != nil {
		ok, verr := s.authn.VerifySecret(*m.ClientSecretHash, clientSecret)
		if verr != nil {
			return oidc.ErrServerError().WithDescription("authentication temporarily unavailable")
		}
		if ok {
			return nil
		}
	}
	return oidc.ErrInvalidClient().WithDescription("invalid client credentials")
}

// --- claims ----------------------------------------------------------------------------------

// SetUserinfoFromScopes is deprecated in the library; SetUserinfoFromRequest is used instead.
func (s *Storage) SetUserinfoFromScopes(context.Context, *oidc.UserInfo, string, string, []string) error {
	return nil
}

func (s *Storage) SetUserinfoFromRequest(ctx context.Context, userinfo *oidc.UserInfo, req op.IDTokenRequest, scopes []string) error {
	return s.setUserinfo(ctx, userinfo, req.GetSubject(), req.GetClientID(), scopes)
}

func (s *Storage) SetUserinfoFromToken(ctx context.Context, userinfo *oidc.UserInfo, tokenID, subject, origin string) error {
	t, err := s.store.GetAccessToken(ctx, tokenID)
	if err != nil {
		return errors.New("token is invalid or has expired")
	}
	if err := s.checkUserCanUseClient(ctx, t.Subject, t.ClientID); err != nil {
		return err
	}
	return s.setUserinfo(ctx, userinfo, t.Subject, t.ClientID, t.Scopes)
}

func (s *Storage) auditToken(ctx context.Context, t *store.RefreshToken, action string) {
	e := store.AuditEvent{Actor: "system", Action: action, Target: "user:" + t.Subject,
		Detail: map[string]any{"client_id": t.ClientID, "family_id": t.FamilyID}}
	if user, err := s.store.GetUser(ctx, t.Subject); err == nil {
		e.OrgID = &user.OrgID
	}
	s.store.Audit(ctx, e)
}

// SetIntrospectionFromToken lets any app of the same project (typically the
// SaaS's API backend) introspect tokens issued to that project's apps.
func (s *Storage) SetIntrospectionFromToken(ctx context.Context, resp *oidc.IntrospectionResponse, tokenID, subject, clientID string) error {
	t, err := s.store.GetAccessToken(ctx, tokenID)
	if err != nil {
		return errors.New("token is invalid or has expired")
	}
	caller, err := s.store.GetAppByClientID(ctx, clientID)
	if err != nil {
		return errors.New("client not found")
	}
	tokenProject, err := s.tokenProject(ctx, t.ClientID, t.Scopes)
	if err != nil || tokenProject != caller.ProjectID {
		return errors.New("token is not valid for this client")
	}
	// Report locked users and revoked grants as inactive immediately.
	if err := s.checkUserCanUseProject(ctx, t.Subject, tokenProject); err != nil {
		return err
	}
	info := new(oidc.UserInfo)
	if err := s.setUserinfo(ctx, info, t.Subject, t.ClientID, t.Scopes); err != nil {
		return err
	}
	resp.SetUserInfo(info)
	resp.Scope = t.Scopes
	resp.ClientID = t.ClientID
	resp.Expiration = oidc.FromTime(t.ExpiresAt)
	return nil
}

// GetPrivateClaimsFromScopes adds the tenant claims to JWT access tokens.
func (s *Storage) GetPrivateClaimsFromScopes(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	return s.tenantClaims(ctx, userID, clientID, scopes)
}

func (s *Storage) GetPrivateClaimsFromRequest(ctx context.Context, req op.TokenRequest, restrictedScopes []string) (map[string]any, error) {
	clientID := ""
	switch r := req.(type) {
	case *authRequest:
		clientID = r.GetClientID()
	case *refreshTokenRequest:
		clientID = r.GetClientID()
	case *oidc.JWTTokenRequest:
		if len(r.Audience) > 0 {
			clientID = r.Audience[0]
		}
	}
	return s.tenantClaims(ctx, req.GetSubject(), clientID, req.GetScopes())
}

func (s *Storage) GetKeyByIDAndClientID(context.Context, string, string) (*jose.JSONWebKey, error) {
	return nil, errors.New("jwt profile grant is not supported")
}

func (s *Storage) ValidateJWTProfileScopes(context.Context, string, []string) ([]string, error) {
	return nil, errors.New("jwt profile grant is not supported")
}

func (s *Storage) Health(ctx context.Context) error {
	return s.store.Ping(ctx)
}

func (s *Storage) setUserinfo(ctx context.Context, info *oidc.UserInfo, userID, clientID string, scopes []string) error {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return errors.New("user not found")
	}
	for _, scope := range scopes {
		switch scope {
		case oidc.ScopeOpenID:
			info.Subject = user.ID
		case oidc.ScopeEmail:
			info.Email = user.Email
			info.EmailVerified = oidc.Bool(user.EmailVerified)
		case oidc.ScopeProfile:
			info.PreferredUsername = user.Username
			info.GivenName = user.GivenName
			info.FamilyName = user.FamilyName
			info.Name = joinName(user.GivenName, user.FamilyName)
			info.UpdatedAt = oidc.FromTime(user.UpdatedAt)
		}
	}
	claims, err := s.tenantClaims(ctx, userID, clientID, scopes)
	if err != nil {
		return err
	}
	for k, v := range claims {
		info.AppendClaims(k, v)
	}
	return nil
}

// tenantClaims are the B2B2C claims a SaaS needs to authorize a request:
// which org the user belongs to and which roles they hold in this project.
func (s *Storage) tenantClaims(ctx context.Context, userID, clientID string, scopes []string) (map[string]any, error) {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}
	org, err := s.store.GetOrg(ctx, user.OrgID)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{
		"org_id":   org.ID,
		"org_slug": org.Slug,
	}
	if clientID == "" {
		return claims, nil
	}
	projectID, err := s.tokenProject(ctx, clientID, scopes)
	if err != nil {
		return nil, err
	}
	if projectID == "" {
		return claims, nil // machine token without a project scope
	}
	roles, err := s.store.EffectiveRoles(ctx, user, projectID)
	if err != nil {
		return nil, err
	}
	claims["project_id"] = projectID
	claims["roles"] = roles
	return claims, nil
}

func joinName(given, family string) string {
	switch {
	case given == "":
		return family
	case family == "":
		return given
	default:
		return given + " " + family
	}
}

// --- machine users (client credentials grant) ----------------------------------------------------

var _ op.ClientCredentialsStorage = (*Storage)(nil)

// ClientCredentials authenticates a machine user by client id and secret.
func (s *Storage) ClientCredentials(ctx context.Context, clientID, clientSecret string) (op.Client, error) {
	user, err := s.store.GetMachineUserByClientID(ctx, clientID)
	if err != nil || user.ClientSecretHash == nil {
		return nil, oidc.ErrInvalidClient().WithDescription("invalid client credentials")
	}
	ok, verr := s.authn.VerifySecret(*user.ClientSecretHash, clientSecret)
	if verr != nil { // overload etc.: do not claim the secret is invalid
		return nil, oidc.ErrServerError().WithDescription("authentication temporarily unavailable")
	}
	if !ok {
		return nil, oidc.ErrInvalidClient().WithDescription("invalid client credentials")
	}
	if user.Locked {
		return nil, oidc.ErrInvalidClient().WithDescription("machine user is locked")
	}
	return &machineClient{user}, nil
}

func (s *Storage) ClientCredentialsTokenRequest(ctx context.Context, clientID string, scopes []string) (op.TokenRequest, error) {
	user, err := s.store.GetMachineUserByClientID(ctx, clientID)
	if err != nil {
		return nil, oidc.ErrInvalidClient()
	}
	granted, err := MachineScopes(scopes)
	if err != nil {
		return nil, oidc.ErrInvalidScope().WithDescription("%s", err.Error())
	}
	// A project scope is only honoured if the machine user's org can use the project.
	if projectID := projectFromScopes(granted); projectID != "" {
		if _, allowed, err := s.store.AvailableRoles(ctx, projectID, user.OrgID); err != nil || !allowed {
			return nil, oidc.ErrInvalidScope().WithDescription("no access to the requested project")
		}
	}
	return &oidc.JWTTokenRequest{
		Subject:  user.ID,
		Audience: []string{clientID},
		Scopes:   granted, // only what was validated is stored, issued and introspected
		IssuedAt: oidc.FromTime(time.Now()),
	}, nil
}

// MachineScopes validates the scopes of a client credentials request (audit
// M1): the only supported scope is one project scope "urn:iam:project:<uuid>".
// Anything else, a second project scope or a malformed id is refused, so a
// token never carries a scope that was not authorized.
func MachineScopes(requested []string) ([]string, error) {
	granted := []string{}
	for _, scope := range requested {
		if scope == "" {
			continue
		}
		projectID, ok := strings.CutPrefix(scope, ProjectScopePrefix)
		if !ok {
			return nil, fmt.Errorf("unsupported scope %q: machine users may only request %s<project id>", scope, ProjectScopePrefix)
		}
		id, err := uuid.Parse(projectID)
		if err != nil || id.String() != projectID {
			return nil, fmt.Errorf("invalid project id in scope %q", scope)
		}
		if len(granted) > 0 {
			return nil, errors.New("at most one project scope may be requested")
		}
		granted = append(granted, scope)
	}
	return granted, nil
}

// machineAccessToken stores the access token for a client credentials request.
func (s *Storage) machineAccessToken(ctx context.Context, req *oidc.JWTTokenRequest) (string, time.Time, error) {
	if len(req.Audience) == 0 {
		return "", time.Time{}, errors.New("missing audience")
	}
	at := &store.AccessToken{
		ID:        uuid.NewString(),
		ClientID:  req.Audience[0],
		Subject:   req.Subject,
		Audience:  req.Audience,
		Scopes:    req.Scopes,
		ExpiresAt: time.Now().Add(s.cfg.AccessToken),
	}
	if at.Scopes == nil {
		at.Scopes = []string{}
	}
	if err := s.store.CreateTokens(ctx, at, nil); err != nil {
		return "", time.Time{}, err
	}
	return at.ID, at.ExpiresAt, nil
}

// tokenProject resolves which project a token is for: the app's project for
// app tokens, or the project scope of a machine token.
func (s *Storage) tokenProject(ctx context.Context, clientID string, scopes []string) (string, error) {
	if app, err := s.store.GetAppByClientID(ctx, clientID); err == nil {
		return app.ProjectID, nil
	}
	if _, err := s.store.GetMachineUserByClientID(ctx, clientID); err == nil {
		return projectFromScopes(scopes), nil
	}
	return "", errors.New("client not found")
}
