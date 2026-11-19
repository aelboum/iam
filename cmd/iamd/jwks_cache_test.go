package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// jwksCacheControl must set an explicit, bounded Cache-Control on the JWKS
// endpoint (CRYPTO-05 test 15 / plan AC8), and only there, so the external
// JWKS-trust window after a revocation is bounded rather than uncontrolled. The
// header is set before the wrapped handler runs, so it survives a handler that
// writes without touching Cache-Control (as the zitadel op /keys handler does).
func TestJWKSCacheControlOnKeysOnly(t *testing.T) {
	// Records the Cache-Control the wrapped handler observed at entry, per request.
	var seenAtEntry string
	wrapped := jwksCacheControl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mimic op.Keys: write a body and 200, set no Cache-Control.
		seenAtEntry = w.Header().Get("Cache-Control")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))

	want := fmt.Sprintf("public, max-age=%d", keysCacheMaxAge)

	cases := []struct {
		method, path, wantCC string
	}{
		{http.MethodGet, "/keys", want},
		{http.MethodGet, "/keys/", want}, // trailing slash normalised
		{http.MethodHead, "/keys", want}, // HEAD caches like GET
		{http.MethodPost, "/keys", ""},   // non-GET/HEAD gets nothing
		{http.MethodGet, "/oauth/token", ""},
		{http.MethodGet, "/.well-known/openid-configuration", ""},
	}
	for _, c := range cases {
		seenAtEntry = "<unset>"
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, nil))
		if got := rec.Header().Get("Cache-Control"); got != c.wantCC {
			t.Errorf("%s %s: Cache-Control = %q, want %q", c.method, c.path, got, c.wantCC)
		}
		// For the GET /keys cases, the header must already be set when the handler
		// runs, so a handler that only writes a body cannot lose it.
		if c.method == http.MethodGet && c.wantCC == want && seenAtEntry != want {
			t.Errorf("%s %s: Cache-Control at handler entry = %q, want %q (must be set before the handler writes)", c.method, c.path, seenAtEntry, want)
		}
	}
}
