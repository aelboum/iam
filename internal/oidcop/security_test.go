package oidcop

import (
	"slices"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// Audit M1: machine users only get validated scopes.
func TestMachineScopes(t *testing.T) {
	const p1 = "urn:iam:project:3f2b8c1e-6a4d-4b9e-9c2f-1a2b3c4d5e6f"
	const p2 = "urn:iam:project:9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b"
	ok := []struct {
		in, want []string
	}{
		{nil, []string{}},
		{[]string{p1}, []string{p1}},
		{[]string{"", p1}, []string{p1}},
	}
	for _, tc := range ok {
		got, err := MachineScopes(tc.in)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("MachineScopes(%v) = %v, %v; want %v", tc.in, got, err, tc.want)
		}
	}
	bad := map[string][]string{
		"admin scope":      {"admin"},
		"openid":           {"openid"},
		"offline":          {"offline_access"},
		"two projects":     {p1, p2},
		"same twice":       {p1, p1},
		"not a uuid":       {"urn:iam:project:not-a-uuid"},
		"uppercase uuid":   {"urn:iam:project:3F2B8C1E-6A4D-4B9E-9C2F-1A2B3C4D5E6F"},
		"braced uuid":      {"urn:iam:project:{3f2b8c1e-6a4d-4b9e-9c2f-1a2b3c4d5e6f}"},
		"empty project":    {"urn:iam:project:"},
		"project + extra":  {p1, "urn:iam:org:x"},
		"prefix lookalike": {"urn:iam:projects:3f2b8c1e-6a4d-4b9e-9c2f-1a2b3c4d5e6f"},
	}
	for name, in := range bad {
		if got, err := MachineScopes(in); err == nil {
			t.Errorf("%s: %v accepted as %v", name, in, got)
		}
	}
}

// Audit M6: tokens and codes sealed before a master key rotation still open.
func TestRotatingCrypto(t *testing.T) {
	var oldKey, newKey, otherKey [32]byte
	oldKey[0], newKey[0], otherKey[0] = 1, 2, 3
	before := rotatingCrypto{keys: []op.Crypto{op.NewAES256GCMCrypto(oldKey, cryptoKeyID)}}
	after := rotatingCrypto{keys: []op.Crypto{
		op.NewAES256GCMCrypto(newKey, cryptoKeyID), op.NewAES256GCMCrypto(oldKey, cryptoKeyID),
	}}
	sealed, err := before.Encrypt("code-123")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := after.Decrypt(sealed); err != nil || got != "code-123" {
		t.Fatalf("after rotation: %q, %v", got, err)
	}
	fresh, _ := after.Encrypt("token-456")
	if _, err := before.Decrypt(fresh); err == nil {
		t.Fatal("new values must be sealed with the new key")
	}
	wrong := rotatingCrypto{keys: []op.Crypto{op.NewAES256GCMCrypto(otherKey, cryptoKeyID)}}
	if _, err := wrong.Decrypt(sealed); err == nil {
		t.Fatal("decrypted with an unrelated key")
	}
}
