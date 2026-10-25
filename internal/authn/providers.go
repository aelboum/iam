package authn

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Provider presets for Google and Microsoft login.
//
// Google, Microsoft personal accounts, and Microsoft Entra ID are all ordinary
// OpenID Connect providers, so they run through the same federation flow as a
// generic ("oidc") IdP: discovery, strict issuer and audience checks, JWKS
// signature verification, nonce, PKCE, browser binding and the SSRF-guarded
// outbound client. The only provider-specific concern is the issuer.
//
// The engine computes the issuer from the provider type (and, for Entra, the
// tenant) instead of trusting an issuer typed by an org admin. Because the
// federation verifier requires the discovered issuer to equal the configured
// issuer and then uses that exact string as the expected `iss`, pinning the
// issuer here is what:
//
//   - stops an org admin pointing a "google" or "entra" provider at an
//     attacker-controlled issuer, and
//   - makes an Entra provider reject tokens from any directory other than the
//     configured tenant (their `iss` differs), preventing tenant confusion.
const (
	// ProviderOIDC is a generic OpenID Connect provider; the admin supplies the issuer.
	ProviderOIDC = "oidc"
	// ProviderGoogle is Google accounts.
	ProviderGoogle = "google"
	// ProviderMicrosoft is Microsoft personal accounts (MSA) only.
	ProviderMicrosoft = "microsoft"
	// ProviderEntra is one Microsoft Entra ID directory (single tenant).
	ProviderEntra = "entra"
)

const (
	googleIssuer = "https://accounts.google.com"
	// microsoftConsumersIssuer is the fixed issuer of the Microsoft personal
	// account (MSA) tenant. Discovery at this issuer returns this same value,
	// so the strict issuer check accepts personal accounts and nothing else.
	// Using the `/consumers` authority instead would make discovery return
	// this GUID issuer and fail the equality check, so the GUID is pinned here.
	microsoftConsumersIssuer = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
)

// defaultProviderScopes is the scope set requested when the caller gives none.
var defaultProviderScopes = []string{"openid", "profile", "email"}

// tenantGUID matches a Microsoft directory (tenant) ID. Entra is pinned to a
// GUID, not a domain: discovery for a domain returns the GUID-based issuer and
// would fail the equality check, and a GUID is an unambiguous directory key.
var tenantGUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ErrProviderConfig means a provider preset was configured incorrectly.
var ErrProviderConfig = errors.New("invalid identity provider configuration")

// KnownProviderType reports whether t is a supported provider type.
func KnownProviderType(t string) bool {
	switch t {
	case ProviderOIDC, ProviderGoogle, ProviderMicrosoft, ProviderEntra:
		return true
	default:
		return false
	}
}

// ValidTenantGUID reports whether s is a Microsoft directory (tenant) GUID.
func ValidTenantGUID(s string) bool { return tenantGUID.MatchString(s) }

// ProviderIssuer returns the OIDC issuer the engine pins for a preset provider,
// given its type and (for Entra) tenant. It returns ErrProviderConfig for a
// generic "oidc" provider (whose issuer is admin-supplied), for an unknown
// type, for a tenant on a non-Entra provider, or for a missing or malformed
// Entra tenant. The issuer is always an https URL under a provider-owned host.
func ProviderIssuer(providerType, tenant string) (string, error) {
	tenant = strings.TrimSpace(tenant)
	switch providerType {
	case ProviderGoogle:
		if tenant != "" {
			return "", fmt.Errorf("%w: tenant is not allowed for google", ErrProviderConfig)
		}
		return googleIssuer, nil
	case ProviderMicrosoft:
		if tenant != "" {
			return "", fmt.Errorf("%w: tenant is not allowed for microsoft personal accounts; use provider_type=entra for a directory", ErrProviderConfig)
		}
		return microsoftConsumersIssuer, nil
	case ProviderEntra:
		if !ValidTenantGUID(tenant) {
			return "", fmt.Errorf("%w: entra requires tenant to be the directory (tenant) GUID", ErrProviderConfig)
		}
		return "https://login.microsoftonline.com/" + strings.ToLower(tenant) + "/v2.0", nil
	default:
		return "", fmt.Errorf("%w: %q has no preset issuer", ErrProviderConfig, providerType)
	}
}

// ProviderScopes returns the scopes to request, using the caller's list when
// it is non-empty and the provider default otherwise.
func ProviderScopes(requested []string) []string {
	if len(requested) > 0 {
		return requested
	}
	return append([]string(nil), defaultProviderScopes...)
}
