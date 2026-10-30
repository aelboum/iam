package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Recovery codes are single-use, counted, and a fresh set replaces (invalidates)
// the old one (security follow-up #3).
func TestRecoveryCodes(t *testing.T) {
	_, st := testPool(t)
	ctx := context.Background()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	org, err := st.CreateOrg(ctx, "RC Co", "rc-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, NewUser{OrgID: org.ID, Username: "u-" + sfx, Email: "u-" + sfx + "@rc.test"})
	if err != nil {
		t.Fatal(err)
	}

	if err := st.ReplaceRecoveryCodes(ctx, user.ID, []string{"h1", "h2", "h3"}); err != nil {
		t.Fatalf("ReplaceRecoveryCodes: %v", err)
	}
	if n, _ := st.CountUnusedRecoveryCodes(ctx, user.ID); n != 3 {
		t.Fatalf("unused count = %d, want 3", n)
	}

	// A matching code is consumed exactly once.
	if ok, err := st.ConsumeRecoveryCode(ctx, user.ID, "h2"); err != nil || !ok {
		t.Fatalf("first consume of h2: ok=%v err=%v, want true/nil", ok, err)
	}
	if ok, _ := st.ConsumeRecoveryCode(ctx, user.ID, "h2"); ok {
		t.Error("second consume of h2 should fail (already used)")
	}
	if ok, _ := st.ConsumeRecoveryCode(ctx, user.ID, "nope"); ok {
		t.Error("consume of an unknown code should fail")
	}
	if n, _ := st.CountUnusedRecoveryCodes(ctx, user.ID); n != 2 {
		t.Fatalf("unused count after one use = %d, want 2", n)
	}

	// Regenerating replaces the set: the old codes no longer work.
	if err := st.ReplaceRecoveryCodes(ctx, user.ID, []string{"new1"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountUnusedRecoveryCodes(ctx, user.ID); n != 1 {
		t.Fatalf("unused count after replace = %d, want 1", n)
	}
	if ok, _ := st.ConsumeRecoveryCode(ctx, user.ID, "h1"); ok {
		t.Error("an old code must not work after the set is replaced")
	}
	if ok, err := st.ConsumeRecoveryCode(ctx, user.ID, "new1"); err != nil || !ok {
		t.Fatalf("consume new1: ok=%v err=%v, want true/nil", ok, err)
	}
}
