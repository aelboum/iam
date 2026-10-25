package config

import "testing"

// Audit L10: passkey relying party settings are checked at startup.
func TestValidateWebAuthn(t *testing.T) {
	cases := []struct {
		rpID    string
		origins []string
		devMode bool
		ok      bool
	}{
		{"example.com", []string{"https://login.example.com"}, false, true},
		{"example.com", []string{"https://example.com", "https://a.b.example.com:8443"}, false, true},
		{"login.example.com", []string{"https://login.example.com"}, false, true},
		{"login.example.com", []string{"https://login.example.com/"}, false, false},
		{"localhost", []string{"http://localhost:3000"}, true, true},
		{"localhost", []string{"http://localhost:3000"}, false, false},
		{"example.com", []string{"http://login.example.com"}, false, false},
		{"example.com", []string{"https://login.example.org"}, false, false},
		{"example.com", []string{"https://badexample.com"}, false, false},
		{"login.example.com", []string{"https://example.com"}, false, false},
		{"example.com", []string{"https://login.example.com/path"}, false, false},
		{"example.com", []string{"https://u:p@login.example.com"}, false, false},
		{"example.com", []string{"login.example.com"}, false, false},
		{"example.com", nil, false, false},
		{"", []string{"https://example.com"}, false, false},
		{"https://example.com", []string{"https://example.com"}, false, false},
	}
	for _, tc := range cases {
		err := ValidateWebAuthn(tc.rpID, tc.origins, tc.devMode)
		if (err == nil) != tc.ok {
			t.Errorf("ValidateWebAuthn(%q, %v, dev=%v) = %v, want ok=%v", tc.rpID, tc.origins, tc.devMode, err, tc.ok)
		}
	}
}
