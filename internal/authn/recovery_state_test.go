package authn

import (
	"slices"
	"testing"
	"time"

	"github.com/aelboum/iam/internal/store"
)

// A recovery code accepted in a session satisfies the second factor for an
// MFA-required user, just like TOTP (security follow-up #3).
func TestStateRecoveryCodeSatisfiesMFA(t *testing.T) {
	now := time.Now()
	var svc Service
	user := &store.User{ID: "u", TOTPVerified: true} // MFA required

	// Password + a recovery code authenticates, with rc/mfa in the AMR.
	withRecovery := &store.Session{
		ID: "s1", OrgID: "o1", PasswordCheckedAt: &now, RecoveryCheckedAt: &now, ExpiresAt: now.Add(time.Hour),
	}
	// orgMFARequired=false (the user's enrolled TOTP already makes MFA required),
	// hasEnrolledFactor=true.
	st := svc.state(withRecovery, user, false, true)
	if !st.Authenticated {
		t.Fatal("a recovery code should authenticate an MFA-required user")
	}
	if !slices.Contains(st.AMR, "rc") || !slices.Contains(st.AMR, "mfa") {
		t.Errorf("AMR = %v, want it to contain rc and mfa", st.AMR)
	}

	// Password alone (MFA required, no second factor) does not authenticate.
	passwordOnly := &store.Session{ID: "s2", OrgID: "o1", PasswordCheckedAt: &now, ExpiresAt: now.Add(time.Hour)}
	if svc.state(passwordOnly, user, false, true).Authenticated {
		t.Error("password alone must not authenticate an MFA-required user")
	}
}
