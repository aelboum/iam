package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Every POST session route must accept the session token in the X-Session-Token
// header (consistent with GET/DELETE), preferring it over the JSON body field
// while still accepting the body for compatibility (audit L-05).
func TestSessionTokenPrefersHeader(t *testing.T) {
	cases := []struct {
		name   string
		header string
		body   string
		want   string
	}{
		{"header only", "tok-header", "", "tok-header"},
		{"body only", "", "tok-body", "tok-body"},
		{"header wins over body", "tok-header", "tok-body", "tok-header"},
		{"neither", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/v1/sessions/s1/password", nil)
			if c.header != "" {
				r.Header.Set(sessionTokenHeader, c.header)
			}
			if got := sessionToken(r, c.body); got != c.want {
				t.Errorf("sessionToken(header=%q, body=%q) = %q, want %q", c.header, c.body, got, c.want)
			}
		})
	}
}
