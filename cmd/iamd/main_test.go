package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

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
