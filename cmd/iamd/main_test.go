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
