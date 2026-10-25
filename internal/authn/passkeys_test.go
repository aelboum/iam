package authn

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// TestChallengeExpired exercises the engine's own server-side expiry gate for
// passkey login challenges (audit L7), without waiting for a real timeout and
// without relying on the WebAuthn library's client-facing Timeouts.Enforce.
// FinishPasskeyLogin rejects with ErrInvalidCredentials whenever this returns
// true, before the assertion is validated, so an expired challenge can never
// establish a session and replaying it fails the same way.
func TestChallengeExpired(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		expires time.Time
		want    bool
	}{
		{"expired one second ago", now.Add(-time.Second), true},
		{"expired long ago", now.Add(-10 * time.Minute), true},
		{"still valid", now.Add(time.Minute), false},
		{"exactly now is not yet past", now, false},
		{"zero means no deadline", time.Time{}, false},
	}
	for _, tc := range cases {
		session := webauthn.SessionData{Expires: tc.expires}
		if got := challengeExpired(session, now); got != tc.want {
			t.Errorf("%s: challengeExpired = %v, want %v", tc.name, got, tc.want)
		}
	}
}
