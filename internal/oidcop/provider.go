package oidcop

import (
	"context"

	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/aelboum/iam/internal/secret"
)

// LoggedOutPath is where end_session redirects when no post_logout_redirect_uri is given.
const LoggedOutPath = "/logged-out"

// NewProvider creates the OpenID Provider. Mount it at the root of the issuer URL.
func NewProvider(issuer string, masterKey [32]byte, devMode bool, storage *Storage) (*op.Provider, error) {
	config := &op.Config{
		// Encrypts opaque (bearer) access tokens.
		CryptoKey:                secret.Derive(masterKey, "oidc-op-crypto"),
		CryptoKeyId:              "op-crypto-1",
		DefaultLogoutRedirectURI: LoggedOutPath,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		GrantTypeRefreshToken:    true,
		SupportedUILocales:       []language.Tag{language.English},
	}
	var opts []op.Option
	if devMode {
		opts = append(opts, op.WithAllowInsecure())
	}
	return op.NewProvider(config, storage, op.StaticIssuer(issuer), opts...)
}

// CallbackURL is where the login UI sends the browser after finalizing an auth request.
func CallbackURL(provider *op.Provider, issuer, authRequestID string) string {
	ctx := op.ContextWithIssuer(context.Background(), issuer)
	return op.AuthCallbackURL(provider)(ctx, authRequestID)
}
