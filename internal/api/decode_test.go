package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type body struct {
	Name string `json:"name"`
}

// decode must accept exactly one JSON value and refuse anything else: a
// truncated or concatenated body used to be silently half-applied (independent
// security assessment, 2026-10-29).
func TestDecodeRejectsTrailingData(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"clean object", `{"name":"a"}`, http.StatusOK},
		{"trailing garbage", `{"name":"a"}GARBAGE`, http.StatusBadRequest},
		{"second object", `{"name":"a"}{"name":"b"}`, http.StatusBadRequest},
		{"empty body", ``, http.StatusBadRequest},
		{"unknown field", `{"nope":1}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/orgs", strings.NewReader(tc.body))
			var v body
			ok := decode(rec, req, &v)
			if tc.want == http.StatusOK {
				if !ok {
					t.Fatalf("decode refused a valid body: %s", rec.Body.String())
				}
				return
			}
			if ok {
				t.Fatal("decode accepted an invalid body")
			}
			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// A declared oversize body must be refused with 413, not truncated into a
// confusing "unexpected EOF" 400.
func TestDecodeRejectsOversizeBody(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/orgs", strings.NewReader(`{"name":"a"}`))
	req.ContentLength = maxBodyBytes + 1
	if decode(rec, req, &body{}) {
		t.Fatal("decode accepted an oversize body")
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// The API and the federation path must agree on what an email is: a dotless
// "a@b" is now refused by both.
func TestValidEmailRequiresDottedDomain(t *testing.T) {
	ok := []string{"a@b.co", "first.last@sub.example.com", "x+tag@example.org"}
	bad := []string{"a@b", "a@", "@b.co", "a b@c.co", "a@b.co\nx", strings.Repeat("a", 250) + "@b.co"}
	for _, e := range ok {
		if err := validEmail(e); err != nil {
			t.Errorf("%q refused: %v", e, err)
		}
	}
	for _, e := range bad {
		if err := validEmail(e); err == nil {
			t.Errorf("%q accepted", e)
		}
	}
}
