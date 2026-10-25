package authn

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// Audit M4: endpoints from a tenant-controlled discovery document.
func TestSafeIdPURL(t *testing.T) {
	cases := []struct {
		url     string
		devMode bool
		want    bool
	}{
		{"https://idp.example.com/authorize?x=1", false, true},
		{"http://idp.example.com/authorize", false, false},
		{"http://localhost:9000/authorize", true, true},
		{"javascript:alert(1)", true, false},
		{"data:text/html,hi", true, false},
		{"file:///etc/passwd", true, false},
		{"https://user:pw@idp.example.com/authorize", false, false},
		{"https://idp.example.com/authorize#frag", false, false},
		{"//idp.example.com/authorize", false, false},
		{"/authorize", false, false},
		{"https://idp.example.com/" + strings.Repeat("a", 5000), false, false},
	}
	for _, tc := range cases {
		if got := SafeIdPURL(tc.url, tc.devMode); got != tc.want {
			t.Errorf("SafeIdPURL(%q, dev=%v) = %v, want %v", tc.url, tc.devMode, got, tc.want)
		}
	}
}

// Audit L4: address ranges the previous net.IP checks let through.
func TestPublicAddress(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0",
		"100.64.0.1", "100.100.100.200", "198.18.0.1", "192.0.0.170", "192.0.2.1", "198.51.100.7",
		"203.0.113.9", "240.0.0.1", "255.255.255.255", "224.0.0.1",
		"::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
		"::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "2002:7f00:1::", "2001:0:4136::1",
		"2001:db8::1", "ff02::1",
	}
	for _, s := range blocked {
		if PublicAddress(netip.MustParseAddr(s)) {
			t.Errorf("PublicAddress(%s) = true, want false", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"}
	for _, s := range allowed {
		if !PublicAddress(netip.MustParseAddr(s)) {
			t.Errorf("PublicAddress(%s) = false, want true", s)
		}
	}
}

// Audit M4/L4: non-https requests are refused and large bodies are cut off.
func TestGuardedTransport(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("x", maxIdPResponse+10)))
	}))
	defer big.Close()

	prod := &guardedTransport{base: http.DefaultTransport}
	req, _ := http.NewRequest(http.MethodGet, big.URL, nil)
	if _, err := prod.RoundTrip(req); err == nil {
		t.Fatal("plain http request allowed outside dev mode")
	}

	dev := &http.Client{Transport: &guardedTransport{base: http.DefaultTransport, allowHTTP: true}}
	resp, err := dev.Get(big.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err == nil || n > maxIdPResponse {
		t.Fatalf("read %d bytes without error, want a cap at %d", n, maxIdPResponse)
	}
}

// Audit M4: the outbound client refuses internal addresses at connect time.
func TestOutboundClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	if _, err := NewOutboundClient(false).Get(srv.URL); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("connection to %s: err = %v, want a non-public address refusal", srv.URL, err)
	}
}

// Audit M2: email and domain inputs from external claims and the API.
func TestValidEmailAndDomain(t *testing.T) {
	emails := map[string]bool{
		"alice@example.com":                         true,
		"a.b+c@sub.example.co":                      true,
		"alice@localhost":                           false,
		"alice@@example.com":                        false,
		"@example.com":                              false,
		"alice@":                                    false,
		"ali ce@example.com":                        false,
		"alice@example.com\n":                       false,
		"alice@-bad.example.com":                    false,
		"alice@exa_mple.com":                        false,
		strings.Repeat("a", 65) + "@x.io":           false,
		"alice@" + strings.Repeat("a.", 130) + "io": false,
	}
	for e, want := range emails {
		if got := ValidEmail(e); got != want {
			t.Errorf("ValidEmail(%q) = %v, want %v", e, got, want)
		}
	}
	domains := map[string]bool{
		"example.com": true, "a-b.example.com": true,
		"*.example.com": false, "Example.com": false, "example..com": false, "": false, "-x.com": false,
	}
	for d, want := range domains {
		if got := ValidDomain(d); got != want {
			t.Errorf("ValidDomain(%q) = %v, want %v", d, got, want)
		}
	}
}

func TestCleanName(t *testing.T) {
	if got := cleanName(" Al\x00ice\n "); got != "Alice" {
		t.Errorf("cleanName = %q", got)
	}
	if got := cleanName(strings.Repeat("x", 300)); len(got) != 100 {
		t.Errorf("cleanName length = %d, want 100", len(got))
	}
}
