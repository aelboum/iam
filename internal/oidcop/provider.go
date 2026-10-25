package oidcop

import (
	"context"

	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/aelboum/iam/internal/secret"
)

// LoggedOutPath is where end_session redirects when no post_logout_redirect_uri is given.
const LoggedOutPath = "/logged-out"

// cryptoKeyID labels the provider's token encryption key.
const cryptoKeyID = "op-crypto-1"

// rotatingCrypto encrypts with the current key and decrypts with the current
// or a previous one (audit M6). The provider uses it for authorization codes
// and opaque (bearer) access tokens, so those survive the restart that
// introduces a new master key. AES-256-GCM is authenticated, so trying each
// key in turn cannot confuse them.
type rotatingCrypto struct {
	keys []op.Crypto
}

func (c rotatingCrypto) Encrypt(s string) (string, error) { return c.keys[0].Encrypt(s) }

func (c rotatingCrypto) Decrypt(s string) (string, error) {
	var err error
	for _, k := range c.keys {
		var out string
		if out, err = k.Decrypt(s); err == nil {
			return out, nil
		}
	}
	return "", err
}

// NewProvider creates the OpenID Provider. Mount it at the root of the issuer URL.
// previousKeys are older master keys still accepted for decryption.
func NewProvider(issuer string, masterKey [32]byte, previousKeys [][32]byte, devMode bool, storage *Storage) (*op.Provider, error) {
	crypto := rotatingCrypto{keys: []op.Crypto{op.NewAES256GCMCrypto(secret.Derive(masterKey, "oidc-op-crypto"), cryptoKeyID)}}
	for _, k := range previousKeys {
		crypto.keys = append(crypto.keys, op.NewAES256GCMCrypto(secret.Derive(k, "oidc-op-crypto"), cryptoKeyID))
	}
	config := &op.Config{
		// Overridden by rotatingCrypto below; kept so the config is complete.
		CryptoKey:                secret.Derive(masterKey, "oidc-op-crypto"),
		CryptoKeyId:              cryptoKeyID,
		DefaultLogoutRedirectURI: LoggedOutPath,
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		GrantTypeRefreshToken:    true,
		SupportedUILocales:       []language.Tag{language.English},
	}
	opts := []op.Option{op.WithCrypto(crypto)}
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
