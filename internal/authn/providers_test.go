package authn

import (
	"slices"
	"strings"
	"testing"
)

// TestProviderIssuer checks the issuer the engine pins for each preset, which
// is the control that stops an org admin pointing a provider at an arbitrary
// issuer and that binds Entra to a single directory.
func TestProviderIssuer(t *testing.T) {
	const guid = "11112222-3333-4444-5555-666677778888"
	ok := []struct {
		ptype, tenant, want string
	}{
		{ProviderGoogle, "", "https://accounts.google.com"},
		{ProviderMicrosoft, "", "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"},
		{ProviderEntra, guid, "https://login.microsoftonline.com/" + guid + "/v2.0"},
		{ProviderEntra, strings.ToUpper(guid), "https://login.microsoftonline.com/" + guid + "/v2.0"}, // lowercased
	}
	for _, tc := range ok {
		got, err := ProviderIssuer(tc.ptype, tc.tenant)
		if err != nil || got != tc.want {
			t.Errorf("ProviderIssuer(%q,%q) = %q,%v; want %q", tc.ptype, tc.tenant, got, err, tc.want)
		}
		if !strings.HasPrefix(got, "https://") {
			t.Errorf("issuer %q is not https", got)
		}
	}
	bad := []struct{ ptype, tenant string }{
		{ProviderOIDC, ""},               // generic: issuer is admin-supplied
		{ProviderGoogle, "some-tenant"},  // tenant not allowed
		{ProviderMicrosoft, "contoso"},   // tenant not allowed on personal
		{ProviderEntra, ""},              // tenant required
		{ProviderEntra, "contoso.com"},   // must be a GUID, not a domain
		{ProviderEntra, "not-a-guid"},    //
		{ProviderEntra, guid + "-extra"}, //
		{"saml", ""},                     // unknown type
		{"", guid},                       // unknown type
	}
	for _, tc := range bad {
		if got, err := ProviderIssuer(tc.ptype, tc.tenant); err == nil {
			t.Errorf("ProviderIssuer(%q,%q) = %q, want error", tc.ptype, tc.tenant, got)
		}
	}
}

func TestKnownProviderType(t *testing.T) {
	for _, ok := range []string{"oidc", "google", "microsoft", "entra"} {
		if !KnownProviderType(ok) {
			t.Errorf("KnownProviderType(%q) = false", ok)
		}
	}
	for _, bad := range []string{"", "OIDC", "saml", "azure", "google "} {
		if KnownProviderType(bad) {
			t.Errorf("KnownProviderType(%q) = true", bad)
		}
	}
}

func TestValidTenantGUID(t *testing.T) {
	if !ValidTenantGUID("11112222-3333-4444-5555-666677778888") {
		t.Error("valid GUID rejected")
	}
	for _, bad := range []string{"", "contoso.onmicrosoft.com", "common", "organizations",
		"11112222-3333-4444-5555-66667777888", "11112222333344445555666677778888"} {
		if ValidTenantGUID(bad) {
			t.Errorf("ValidTenantGUID(%q) = true", bad)
		}
	}
}

func TestProviderScopes(t *testing.T) {
	if got := ProviderScopes(nil); !slices.Equal(got, []string{"openid", "profile", "email"}) {
		t.Errorf("default scopes = %v", got)
	}
	custom := []string{"openid", "email"}
	if got := ProviderScopes(custom); !slices.Equal(got, custom) {
		t.Errorf("custom scopes = %v", got)
	}
}
