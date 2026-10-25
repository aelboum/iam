package api

import "testing"

func TestRedirectURLAllowed(t *testing.T) {
	cases := []struct {
		url     string
		native  bool
		devMode bool
		want    bool
	}{
		{"https://app.example.com/callback", false, false, true},
		{"http://app.example.com/callback", false, false, false},
		{"http://app.example.com/callback", false, true, true},
		{"http://127.0.0.1:8123/callback", true, false, true},
		{"http://localhost/callback", true, false, true},
		{"http://localhost/callback", false, false, false},
		{"com.example.app:/callback", true, false, true},
		{"com.example.app:/callback", false, false, false},
		{"javascript:alert(1)", true, true, false},
		{"data:text/html,hi", true, true, false},
		{"https://app.example.com/callback#frag", false, false, false},
		{"https://user:pass@app.example.com/callback", false, false, false},
		{"/relative/callback", false, true, false},
		{"https:///no-host", false, false, false},
	}
	for _, tc := range cases {
		if got := redirectURLAllowed(tc.url, tc.native, tc.devMode); got != tc.want {
			t.Errorf("redirectURLAllowed(%q, native=%v, dev=%v) = %v, want %v", tc.url, tc.native, tc.devMode, got, tc.want)
		}
	}
}

// Audit M11: email domain allowlists are exact, validated domains.
func TestNormalizeDomains(t *testing.T) {
	got, err := normalizeDomains([]string{" Example.COM ", "sub.example.org"})
	if err != nil || len(got) != 2 || got[0] != "example.com" || got[1] != "sub.example.org" {
		t.Fatalf("normalizeDomains = %v, %v", got, err)
	}
	if got, err := normalizeDomains(nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("normalizeDomains(nil) = %v, %v; want empty list", got, err)
	}
	for _, bad := range []string{"*.example.com", "localhost", "example..com", "exa mple.com", "@example.com", ""} {
		if _, err := normalizeDomains([]string{bad}); err == nil {
			t.Errorf("normalizeDomains(%q) accepted", bad)
		}
	}
}
