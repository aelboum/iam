package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"
)

// A representative discovery document as zitadel/oidc emits it: response_types
// and grant_types carry capabilities the engine does not implement (implicit
// flow, the implicit grant, the JWT bearer grant), alongside the ones it does.
const sampleDiscovery = `{
	"issuer": "https://iam.test",
	"authorization_endpoint": "https://iam.test/authorize",
	"token_endpoint": "https://iam.test/oauth/token",
	"response_types_supported": ["code", "id_token", "id_token token"],
	"grant_types_supported": ["authorization_code", "implicit", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
	"code_challenge_methods_supported": ["S256"]
}`

// honestDiscovery must advertise only the response types and grant types the
// engine actually accepts: the implicit response types, the implicit grant and
// the JWT bearer grant are stripped, code / authorization_code / refresh_token
// are kept, and every unrelated field is preserved unchanged (audit L-04).
func TestHonestDiscovery(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(sampleDiscovery)))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(sampleDiscovery))
	})

	t.Run("rewrites the discovery document", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, discoveryPath, nil)
		honestDiscovery(next).ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		var doc map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
			t.Fatalf("response is not JSON: %v", err)
		}
		rts := toStrings(t, doc["response_types_supported"])
		if !slices.Equal(rts, []string{"code"}) {
			t.Errorf("response_types_supported = %v, want [code]", rts)
		}
		grants := toStrings(t, doc["grant_types_supported"])
		want := []string{"authorization_code", "refresh_token"}
		if !slices.Equal(grants, want) {
			t.Errorf("grant_types_supported = %v, want %v", grants, want)
		}
		// Unrelated fields survive untouched.
		if doc["issuer"] != "https://iam.test" {
			t.Errorf("issuer changed: %v", doc["issuer"])
		}
		if cc := toStrings(t, doc["code_challenge_methods_supported"]); !slices.Equal(cc, []string{"S256"}) {
			t.Errorf("code_challenge_methods_supported changed: %v", cc)
		}
		// The Content-Length must match the rewritten (shorter) body, or the
		// client would truncate or hang.
		if cl := rr.Header().Get("Content-Length"); cl != strconv.Itoa(rr.Body.Len()) {
			t.Errorf("Content-Length = %q, want %d", cl, rr.Body.Len())
		}
	})

	t.Run("passes other paths through untouched", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/authorize", nil)
		honestDiscovery(next).ServeHTTP(rr, req)
		if rr.Body.String() != sampleDiscovery {
			t.Error("non-discovery path must pass the body through unchanged")
		}
	})
}

// rewriteDiscovery only ever removes capabilities. A document that advertises
// nothing unsupported is left alone (ok=false), and a non-JSON body is refused
// so the caller serves the original verbatim.
func TestRewriteDiscoveryIsConservative(t *testing.T) {
	clean := `{"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"]}`
	if _, ok := rewriteDiscovery([]byte(clean)); ok {
		t.Error("a document with nothing to strip must report no change")
	}
	if _, ok := rewriteDiscovery([]byte("not json")); ok {
		t.Error("a non-JSON body must not be rewritten")
	}
}

func toStrings(t *testing.T, v any) []string {
	t.Helper()
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("value %v is not an array", v)
	}
	out := make([]string, len(arr))
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("element %v is not a string", e)
		}
		out[i] = s
	}
	return out
}
