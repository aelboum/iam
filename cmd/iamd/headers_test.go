package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

// M-01: the OIDC form_post auto-submit page must receive a CSP that lets it
// function (inline auto-submit + the single cross-origin POST to the validated
// redirect_uri) while every other response keeps the strict API policy and the
// relaxation never widens to arbitrary destinations.
func TestFormPostCSP(t *testing.T) {
	const strict = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

	// A stand-in for the zitadel form_post page: the fixed auto-submit handler
	// plus the single cross-origin form targeting the validated redirect_uri.
	formPostBody := func(action string) string {
		return `<!doctype html><html><head><meta charset="UTF-8" /></head>` +
			`<body onload="javascript:document.forms[0].submit()">` +
			`<form method="post" action="` + action + `">` +
			`<input type="hidden" name="code" value="abc"/></form></body></html>`
	}

	// The production chain: securityHeaders sets the strict CSP, relaxCSPForFormPost
	// narrows it only for the form_post page.
	chain := func(h http.HandlerFunc) http.Handler {
		return securityHeaders(relaxCSPForFormPost(h))
	}

	// 1. A valid form_post response on the callback path gets the scoped policy:
	// inline auto-submit allowed, cross-origin POST allowed only to the exact
	// redirect origin, nothing else relaxed.
	rec := httptest.NewRecorder()
	chain(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(formPostBody("https://app.example.test/cb?x=1")))
	}).ServeHTTP(rec, httptest.NewRequest("GET", "/authorize/callback?id=42", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	want := "default-src 'none'; script-src 'unsafe-inline'; form-action https://app.example.test; base-uri 'none'; frame-ancestors 'none'"
	if csp != want {
		t.Fatalf("form_post CSP = %q, want %q", csp, want)
	}
	// Must actually unblock the two things the strict policy broke.
	if !strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Error("form_post CSP does not permit the inline auto-submit")
	}
	if !strings.Contains(csp, "form-action https://app.example.test") || strings.Contains(csp, "form-action 'self'") {
		t.Error("form_post CSP does not permit the cross-origin POST to the redirect origin")
	}
	// Must not widen beyond what is needed.
	for _, bad := range []string{"'unsafe-eval'", "https: ", "form-action *", "default-src 'self'", "default-src *"} {
		if strings.Contains(csp, bad) {
			t.Errorf("form_post CSP unexpectedly widened with %q: %q", bad, csp)
		}
	}
	// The form target is pinned to the exact origin, so a different origin is not
	// an allowed destination (only app.example.test is listed, no path leaked).
	if strings.Contains(csp, "evil.test") || strings.Contains(csp, "/cb") {
		t.Errorf("form_post CSP leaked path or foreign origin: %q", csp)
	}
	// Body and status pass through unchanged, and handler headers survive.
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "document.forms[0].submit()") {
		t.Error("form_post body was altered")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("handler Cache-Control header did not survive buffering")
	}

	// 2. The normal query response mode (a 302 redirect, no form_post body) on the
	// same authorization path keeps the strict policy — the relaxation is not
	// applied to anything but the form_post page.
	rec = httptest.NewRecorder()
	chain(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://app.example.test/cb?code=abc&state=xyz")
		w.WriteHeader(http.StatusFound)
	}).ServeHTTP(rec, httptest.NewRequest("GET", "/authorize/callback?id=42", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got != strict {
		t.Errorf("query-mode CSP = %q, want the strict policy", got)
	}
	if rec.Code != http.StatusFound || rec.Header().Get("Location") == "" {
		t.Errorf("query-mode redirect not preserved: status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}

	// 3. A non-authorization path with an identical body is never relaxed.
	rec = httptest.NewRecorder()
	chain(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(formPostBody("https://app.example.test/cb")))
	}).ServeHTTP(rec, httptest.NewRequest("GET", "/v1/orgs", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got != strict {
		t.Errorf("non-authorize path CSP = %q, want the strict policy", got)
	}

	// 4. Fail closed: a form_post page whose action origin cannot be parsed keeps
	// the strict policy rather than emitting a looser one.
	rec = httptest.NewRecorder()
	chain(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(formPostBody("not a url")))
	}).ServeHTTP(rec, httptest.NewRequest("GET", "/authorize/callback?id=42", nil))
	if got := rec.Header().Get("Content-Security-Policy"); got != strict {
		t.Errorf("unparseable-action CSP = %q, want the strict policy (fail closed)", got)
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
