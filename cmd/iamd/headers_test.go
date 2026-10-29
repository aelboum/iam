package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aelboum/iam/internal/ratelimit"
)

// securityHeaders must set the defensive header set on every response, and the
// /docs handler must be able to override the restrictive API CSP with the one
// its CDN assets need (independent security assessment, 2026-10-29).
func TestSecurityHeaders(t *testing.T) {
	var seen http.Header
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = w.Header().Clone()
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/v1/orgs", nil))

	for _, name := range []string{
		"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
		"Content-Security-Policy", "Cross-Origin-Resource-Policy",
		"Cross-Origin-Opener-Policy", "Permissions-Policy",
	} {
		if seen.Get(name) == "" {
			t.Errorf("%s is not set", name)
		}
	}
	if got := seen.Get("Content-Security-Policy"); got != "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" {
		t.Errorf("CSP = %q, want the restrictive API policy", got)
	}
	if seen.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be set for a plain-http request")
	}

	// A handler that sets its own CSP (docs) wins.
	rec := httptest.NewRecorder()
	securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "docs-policy")
	})).ServeHTTP(rec, httptest.NewRequest("GET", "/docs", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got != "docs-policy" {
		t.Errorf("CSP = %q, want the handler's own policy to survive", got)
	}
}

// Token-bearing responses must be uncacheable (RFC 6749 §5.1); everything else
// must not gain the header.
func TestNoStoreOnlyOnTokenPaths(t *testing.T) {
	h := noStore(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	for _, p := range []string{"/oauth/token", "/oauth/introspect", "/revoke", "/userinfo", "/authorize/callback", "/oauth/token/", "/userinfo/"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", p, nil))
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
			t.Errorf("%s: Cache-Control=%q Pragma=%q, want no-store/no-cache",
				p, rec.Header().Get("Cache-Control"), rec.Header().Get("Pragma"))
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/keys", nil))
	if rec.Header().Get("Cache-Control") != "" {
		t.Errorf("/keys gained Cache-Control %q, want none", rec.Header().Get("Cache-Control"))
	}
}

// CORS is opt-in and exact: an unlisted origin gets no allow header, a listed
// one is echoed, and a preflight is answered with 204 instead of chi's 405.
func TestCORS(t *testing.T) {
	h := cors([]string{"https://app.example.com"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/v1/orgs", nil)
	req.Header.Set("Origin", "https://evil.test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("unlisted origin allowed: %q", got)
	}

	req = httptest.NewRequest("GET", "/v1/orgs", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("listed origin not echoed: %q", got)
	}

	req = httptest.NewRequest("OPTIONS", "/v1/orgs", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("preflight is missing Access-Control-Allow-Methods")
	}

	// A provider path (not /v1) must pass through untouched, not be answered 204
	// here: the mounted OIDC provider owns its own CORS, so OPTIONS reaches the
	// next handler (which writes 200) instead of this middleware short-circuiting.
	req = httptest.NewRequest("OPTIONS", "/oauth/token", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("provider preflight short-circuited: status = %d, want the next handler's 200", rec.Code)
	}

	// Case and an explicit default port must still match the listed origin; the
	// browser-sent Origin is echoed verbatim.
	req = httptest.NewRequest("GET", "/v1/orgs", nil)
	req.Header.Set("Origin", "https://App.Example.com:443")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://App.Example.com:443" {
		t.Errorf("normalized-equal origin not echoed: %q", got)
	}
}

// A trailing slash must still hit the rate limiter (the provider 404s on it,
// but it must not become an unthrottled path).
func TestOAuthLimiterIgnoresTrailingSlash(t *testing.T) {
	mw := limitOAuthEndpoints(ratelimit.Memory)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	limited := false
	for i := 0; i < 200; i++ {
		r := httptest.NewRequest("POST", "/oauth/token/", nil)
		r.RemoteAddr = "198.51.100.9:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("/oauth/token/ was never rate limited")
	}
}
