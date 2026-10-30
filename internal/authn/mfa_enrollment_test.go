package authn

import (
	"testing"
	"time"

	"github.com/aelboum/iam/internal/store"
)

// state() must enforce an org-level MFA policy: a user who verified a first
// factor but has no second factor enrolled is not authenticated and is flagged
// for enrollment; a user with a factor is handled as before.
func TestStateOrgMFAEnrollment(t *testing.T) {
	now := time.Now()
	passwordOnly := func() *store.Session {
		return &store.Session{ID: "s1", OrgID: "o1", PasswordCheckedAt: &now, ExpiresAt: now.Add(time.Hour)}
	}
	var svc Service

	cases := []struct {
		name              string
		sess              *store.Session
		user              *store.User
		orgMFA            bool
		hasFactor         bool
		wantAuth          bool
		wantEnrollPending bool
		wantMFARequired   bool
	}{
		{
			name: "org requires MFA, password only, no factor -> blocked for enrollment",
			sess: passwordOnly(), user: &store.User{ID: "u1"},
			orgMFA: true, hasFactor: false,
			wantAuth: false, wantEnrollPending: true, wantMFARequired: true,
		},
		{
			name: "org requires MFA, factor enrolled but not used -> blocked, no enrollment",
			sess: passwordOnly(), user: &store.User{ID: "u1", TOTPVerified: true},
			orgMFA: true, hasFactor: true,
			wantAuth: false, wantEnrollPending: false, wantMFARequired: true,
		},
		{
			name:   "org requires MFA, passkey used -> authenticated",
			sess:   &store.Session{ID: "s2", OrgID: "o1", PasskeyCheckedAt: &now, ExpiresAt: now.Add(time.Hour)},
			user:   &store.User{ID: "u1"},
			orgMFA: true, hasFactor: true,
			wantAuth: true, wantEnrollPending: false, wantMFARequired: true,
		},
		{
			name: "no org policy, password only, no factor -> authenticated (unchanged)",
			sess: passwordOnly(), user: &store.User{ID: "u1"},
			orgMFA: false, hasFactor: false,
			wantAuth: true, wantEnrollPending: false, wantMFARequired: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := svc.state(tc.sess, tc.user, tc.orgMFA, tc.hasFactor)
			if st.Authenticated != tc.wantAuth {
				t.Errorf("Authenticated = %v, want %v", st.Authenticated, tc.wantAuth)
			}
			if st.MFAEnrollmentRequired != tc.wantEnrollPending {
				t.Errorf("MFAEnrollmentRequired = %v, want %v", st.MFAEnrollmentRequired, tc.wantEnrollPending)
			}
			if st.MFARequired != tc.wantMFARequired {
				t.Errorf("MFARequired = %v, want %v", st.MFARequired, tc.wantMFARequired)
			}
		})
	}
}
