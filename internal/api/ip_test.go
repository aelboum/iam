package api

import (
	"context"
	"net/http"
	"testing"
)

// TestClientIPCanonical checks that a trusted X-End-User-IP is reduced to its
// canonical form, so one address is exactly one rate-limit and audit key and
// cannot be multiplied by spelling it differently (internal security audit
// B10). An untrusted request ignores the header and uses the connection
// address.
func TestClientIPCanonical(t *testing.T) {
	trusted := map[string]string{
		"::ffff:1.2.3.4": "1.2.3.4",      // IPv4-mapped IPv6 unmaps to the v4 form
		"2001:0db8::1":   "2001:db8::1",  // leading zeros compressed
		"1.2.3.4":        "1.2.3.4",      // already canonical
		"not-an-ip":      "198.51.100.9", // invalid header falls back to the connection address
	}
	for header, want := range trusted {
		r := &http.Request{Header: http.Header{}, RemoteAddr: "198.51.100.9:443"}
		r.Header.Set(endUserIPHeader, header)
		r = r.WithContext(context.WithValue(context.Background(), endUserIPKey{}, true))
		if got := clientIP(r); got != want {
			t.Errorf("clientIP(trusted, %q) = %q, want %q", header, got, want)
		}
	}
	// Without the trusted flag the header is ignored entirely.
	r := &http.Request{Header: http.Header{}, RemoteAddr: "198.51.100.9:443"}
	r.Header.Set(endUserIPHeader, "1.2.3.4")
	if got := clientIP(r); got != "198.51.100.9" {
		t.Errorf("clientIP(untrusted) = %q, want the connection address", got)
	}
}
