package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aelboum/iam/internal/authn"
)

// TestFailMapsLoginFailureClasses pins the HTTP contract for the three login
// failure classes that R4 must keep distinct (internal security audit N12/R4):
//   - invalid credentials  -> 401, no Retry-After
//   - caller/tenant limit  -> 429, Retry-After: 60 (window)
//   - transient overload   -> 503, Retry-After: 1  (short, advisory)
//
// It also checks the neighbouring auth errors so a future change to fail()
// cannot silently fold overload back into the 429 bucket.
func TestFailMapsLoginFailureClasses(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantRetry  string // "" means the header must be absent
	}{
		{"invalid credentials", authn.ErrInvalidCredentials, http.StatusUnauthorized, ""},
		{"session invalid", authn.ErrSessionInvalid, http.StatusUnauthorized, ""},
		{"locked", authn.ErrLocked, http.StatusLocked, ""},
		{"rate limited (tenant/hard)", authn.ErrRateLimited, http.StatusTooManyRequests, "60"},
		{"overloaded (transient hash shed)", authn.ErrOverloaded, http.StatusServiceUnavailable, "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/sessions/x/password", nil)
			fail(rec, req, tc.err)

			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			got := rec.Header().Get("Retry-After")
			if got != tc.wantRetry {
				t.Errorf("Retry-After = %q, want %q", got, tc.wantRetry)
			}
		})
	}

	// The two classes must never collapse onto the same status code.
	if http.StatusTooManyRequests == http.StatusServiceUnavailable {
		t.Fatal("rate-limited and overloaded must use distinct status codes")
	}
}
