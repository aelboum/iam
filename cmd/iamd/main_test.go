package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aelboum/iam/internal/authn"
	"github.com/aelboum/iam/internal/ratelimit"
)

// The public, unauthenticated federated-login callback must be per-IP rate
// limited like the other public OAuth endpoints, so it cannot be flooded as a
// DB-load vector (internal security audit N12 follow-up). A path not in the
// limiter's allowlist must pass through untouched.
func TestOAuthLimiterCoversIDPCallback(t *testing.T) {
	const peer = "198.51.100.7:4444"
	mw := limitOAuthEndpoints(ratelimit.Memory)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	fire := func(path string) (statuses []int, retryAfter string) {
		for i := 0; i < 80; i++ {
			r := httptest.NewRequest("GET", path, nil)
			r.RemoteAddr = peer
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			statuses = append(statuses, rec.Code)
			if rec.Code == http.StatusTooManyRequests {
				retryAfter = rec.Header().Get("Retry-After")
			}
		}
		return
	}

	// The callback is now limited: a sustained single-IP flood must eventually 429.
	codes, ra := fire(authn.CallbackPath)
	got429 := false
	for _, c := range codes {
		if c == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatalf("%s was never rate limited under an 80-request single-IP flood", authn.CallbackPath)
	}
	if ra != "60" {
		t.Fatalf("429 on %s had Retry-After=%q, want \"60\"", authn.CallbackPath, ra)
	}

	// A path outside the allowlist must never be throttled by this middleware.
	for i, c := range func() []int { s, _ := fire("/healthz-not-listed"); return s }() {
		if c != http.StatusOK {
			t.Fatalf("unlisted path request %d got %d, want 200 (must not be limited)", i, c)
		}
	}
}

// Every public provider endpoint must be rate limited, not just the token,
// introspection, revocation and authorize endpoints. A single-IP flood on each
// covered path must eventually 429, and a path outside the allowlist must pass
// through untouched (audit I-05).
func TestOAuthLimiterCoversAllProviderEndpoints(t *testing.T) {
	const peer = "198.51.100.9:5555"
	mw := limitOAuthEndpoints(ratelimit.Memory)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	flood := func(path string, n int) bool {
		for i := 0; i < n; i++ {
			r := httptest.NewRequest("GET", path, nil)
			r.RemoteAddr = peer
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)
			if rec.Code == http.StatusTooManyRequests {
				return true
			}
		}
		return false
	}

	// The metadata endpoints carry a wider burst (120), so they need more
	// requests to trip than the OAuth endpoints (burst 60).
	covered := map[string]int{
		"/oauth/token": 80, "/oauth/introspect": 80, "/revoke": 80, "/userinfo": 80,
		"/end_session": 80, "/device_authorization": 80,
		"/keys": 200, discoveryPath: 200,
	}
	for path, n := range covered {
		if !flood(path, n) {
			t.Errorf("%s was never rate limited under a %d-request single-IP flood", path, n)
		}
	}

	// An unlisted path must never be throttled by this middleware.
	for i := 0; i < 200; i++ {
		r := httptest.NewRequest("GET", "/not-a-provider-endpoint", nil)
		r.RemoteAddr = peer
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusOK {
			t.Fatalf("unlisted path request %d got %d, want 200 (must not be limited)", i, rec.Code)
		}
	}
}

// limiterKey collapses an IPv6 source to its /64 prefix so an attacker cannot
// defeat per-IP limits by rotating through the 2^64 addresses of one assignment,
// while IPv4 and unparseable inputs are kept whole (audit N10).
func TestLimiterKeyCollapsesIPv6To64(t *testing.T) {
	cases := []struct{ in, want string }{
		{"203.0.113.9:4444", "203.0.113.9"},
		{"203.0.113.9", "203.0.113.9"},
		{"[2001:db8:1:2::1]:443", "2001:db8:1:2::/64"},
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2:ffff:ffff:ffff:ffff]:80", "2001:db8:1:2::/64"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tc := range cases {
		if got := limiterKey(tc.in); got != tc.want {
			t.Errorf("limiterKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// Two different IPv6 addresses inside one /64 must share a rate-limit bucket,
// while an address in a different /64 is unaffected (audit N10).
func TestOAuthLimiterSharesIPv6Slash64Bucket(t *testing.T) {
	mw := limitOAuthEndpoints(ratelimit.Memory)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	hit := func(remoteAddr string) int {
		r := httptest.NewRequest("GET", "/oauth/token", nil)
		r.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}

	// Exhaust the oauth burst from one address in 2001:db8:1:2::/64.
	for i := 0; i < 80; i++ {
		hit("[2001:db8:1:2::1]:1000")
	}
	// A different address in the SAME /64 must already be throttled.
	if code := hit("[2001:db8:1:2::abcd]:2000"); code != http.StatusTooManyRequests {
		t.Errorf("same-/64 address got %d, want 429 (shared bucket)", code)
	}
	// An address in a DIFFERENT /64 must still be allowed.
	if code := hit("[2001:db8:9:9::1]:3000"); code != http.StatusOK {
		t.Errorf("different-/64 address got %d, want 200 (separate bucket)", code)
	}
}

func TestForwardedForUsesRightmostTrustedHop(t *testing.T) {
	const peer = "192.0.2.1:5555"
	cases := []struct {
		name string
		hops int
		xff  []string
		want string
	}{
		{"single proxy", 1, []string{"203.0.113.9"}, "203.0.113.9:0"},
		{"client spoofs left entries", 1, []string{"6.6.6.6, 7.7.7.7, 203.0.113.9"}, "203.0.113.9:0"},
		{"two proxies", 2, []string{"6.6.6.6, 203.0.113.9, 10.0.0.2"}, "203.0.113.9:0"},
		{"split across headers", 1, []string{"6.6.6.6", "203.0.113.9"}, "203.0.113.9:0"},
		{"too few entries keeps peer", 2, []string{"203.0.113.9"}, peer},
		{"garbage keeps peer", 1, []string{"not-an-ip"}, peer},
		{"no header keeps peer", 1, nil, peer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			h := forwardedFor(tc.hops)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.RemoteAddr
			}))
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = peer
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			r.Header.Set("X-Real-IP", "6.6.6.6") // never trusted
			h.ServeHTTP(httptest.NewRecorder(), r)
			if got != tc.want {
				t.Fatalf("RemoteAddr = %q, want %q", got, tc.want)
			}
		})
	}
}
