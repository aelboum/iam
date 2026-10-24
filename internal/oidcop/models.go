package oidcop

import (
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/aelboum/iam/internal/store"
)

// client adapts a store.App to op.Client.
type client struct {
	app *store.App
}

var _ op.Client = (*client)(nil)

func (c *client) GetID() string                    { return c.app.ClientID }
func (c *client) RedirectURIs() []string           { return c.app.RedirectURIs }
func (c *client) PostLogoutRedirectURIs() []string { return c.app.PostLogoutRedirectURIs }

func (c *client) ApplicationType() op.ApplicationType {
	switch c.app.AppType {
	case "spa":
		return op.ApplicationTypeUserAgent
	case "native":
		return op.ApplicationTypeNative
	default:
		return op.ApplicationTypeWeb
	}
}

func (c *client) AuthMethod() oidc.AuthMethod { return oidc.AuthMethod(c.app.AuthMethod) }

func (c *client) ResponseTypes() []oidc.ResponseType {
	return []oidc.ResponseType{oidc.ResponseTypeCode}
}

func (c *client) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeCode, oidc.GrantTypeRefreshToken}
}

// LoginURL sends the browser to the SaaS's own login UI with the auth request id.
func (c *client) LoginURL(authRequestID string) string {
	sep := "?"
	if strings.Contains(c.app.LoginURL, "?") {
		sep = "&"
	}
	return c.app.LoginURL + sep + "authRequest=" + authRequestID
}

func (c *client) AccessTokenType() op.AccessTokenType {
	if c.app.AccessTokenType == "bearer" {
		return op.AccessTokenTypeBearer
	}
	return op.AccessTokenTypeJWT
}

func (c *client) IDTokenLifetime() time.Duration { return time.Hour }
func (c *client) DevMode() bool                  { return c.app.DevMode }

func (c *client) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *client) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}

func (c *client) IsScopeAllowed(string) bool           { return false }
func (c *client) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *client) ClockSkew() time.Duration             { return 0 }

// authRequest adapts a store.AuthRequest to op.AuthRequest.
type authRequest struct {
	r *store.AuthRequest
}

var _ op.AuthRequest = (*authRequest)(nil)

func (a *authRequest) GetID() string    { return a.r.ID }
func (a *authRequest) GetACR() string   { return "" }
func (a *authRequest) GetAMR() []string { return a.r.AMR }

func (a *authRequest) GetAudience() []string { return []string{a.r.ClientID} }

func (a *authRequest) GetAuthTime() time.Time {
	if a.r.AuthTime == nil {
		return time.Time{}
	}
	return *a.r.AuthTime
}

func (a *authRequest) GetClientID() string { return a.r.ClientID }

func (a *authRequest) GetCodeChallenge() *oidc.CodeChallenge {
	if a.r.CodeChallenge == "" {
		return nil
	}
	return &oidc.CodeChallenge{
		Challenge: a.r.CodeChallenge,
		Method:    oidc.CodeChallengeMethod(a.r.CodeChallengeMethod),
	}
}

func (a *authRequest) GetNonce() string                   { return a.r.Nonce }
func (a *authRequest) GetRedirectURI() string             { return a.r.RedirectURI }
func (a *authRequest) GetResponseType() oidc.ResponseType { return oidc.ResponseType(a.r.ResponseType) }
func (a *authRequest) GetResponseMode() oidc.ResponseMode { return oidc.ResponseMode(a.r.ResponseMode) }
func (a *authRequest) GetScopes() []string                { return a.r.Scopes }
func (a *authRequest) GetState() string                   { return a.r.State }

func (a *authRequest) GetSubject() string {
	if a.r.UserID == nil {
		return ""
	}
	return *a.r.UserID
}

func (a *authRequest) Done() bool { return a.r.Done }

// refreshTokenRequest adapts a store.RefreshToken to op.RefreshTokenRequest.
type refreshTokenRequest struct {
	t *store.RefreshToken
}

var _ op.RefreshTokenRequest = (*refreshTokenRequest)(nil)

func (r *refreshTokenRequest) GetAMR() []string                 { return r.t.AMR }
func (r *refreshTokenRequest) GetAudience() []string            { return r.t.Audience }
func (r *refreshTokenRequest) GetAuthTime() time.Time           { return r.t.AuthTime }
func (r *refreshTokenRequest) GetClientID() string              { return r.t.ClientID }
func (r *refreshTokenRequest) GetScopes() []string              { return r.t.Scopes }
func (r *refreshTokenRequest) GetSubject() string               { return r.t.Subject }
func (r *refreshTokenRequest) SetCurrentScopes(scopes []string) { r.t.Scopes = scopes }

// ProjectScopePrefix selects the project whose roles a machine token carries:
// scope "urn:iam:project:<project id>".
const ProjectScopePrefix = "urn:iam:project:"

// machineClient adapts a machine user to op.Client for the client
// credentials grant.
type machineClient struct {
	user *store.User
}

var _ op.Client = (*machineClient)(nil)

func (c *machineClient) GetID() string                       { return *c.user.ClientID }
func (c *machineClient) RedirectURIs() []string              { return nil }
func (c *machineClient) PostLogoutRedirectURIs() []string    { return nil }
func (c *machineClient) ApplicationType() op.ApplicationType { return op.ApplicationTypeWeb }
func (c *machineClient) AuthMethod() oidc.AuthMethod         { return oidc.AuthMethodBasic }
func (c *machineClient) ResponseTypes() []oidc.ResponseType  { return nil }
func (c *machineClient) GrantTypes() []oidc.GrantType {
	return []oidc.GrantType{oidc.GrantTypeClientCredentials}
}
func (c *machineClient) LoginURL(string) string              { return "" }
func (c *machineClient) AccessTokenType() op.AccessTokenType { return op.AccessTokenTypeJWT }
func (c *machineClient) IDTokenLifetime() time.Duration      { return time.Hour }
func (c *machineClient) DevMode() bool                       { return false }
func (c *machineClient) RestrictAdditionalIdTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *machineClient) RestrictAdditionalAccessTokenScopes() func([]string) []string {
	return func(scopes []string) []string { return scopes }
}
func (c *machineClient) IsScopeAllowed(scope string) bool {
	return strings.HasPrefix(scope, ProjectScopePrefix)
}
func (c *machineClient) IDTokenUserinfoClaimsAssertion() bool { return false }
func (c *machineClient) ClockSkew() time.Duration             { return 0 }

// projectFromScopes returns the project selected with ProjectScopePrefix, if any.
func projectFromScopes(scopes []string) string {
	for _, scope := range scopes {
		if projectID, ok := strings.CutPrefix(scope, ProjectScopePrefix); ok {
			return projectID
		}
	}
	return ""
}
