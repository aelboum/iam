package store

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// A new org defaults to MFA not required; SetOrgMFARequired toggles the policy
// and GetOrg/GetOrgByRef reflect it (security follow-up #2).
func TestOrgMFAPolicy(t *testing.T) {
	_, st := testPool(t)
	ctx := context.Background()

	slug := fmt.Sprintf("mfa-%d", time.Now().UnixNano())
	org, err := st.CreateOrg(ctx, "MFA Co", slug)
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if org.MFARequired {
		t.Error("new org should default to mfa_required = false")
	}

	if err := st.SetOrgMFARequired(ctx, org.ID, true); err != nil {
		t.Fatalf("SetOrgMFARequired(true): %v", err)
	}
	got, err := st.GetOrg(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.MFARequired {
		t.Error("GetOrg: mfa_required = false after enabling, want true")
	}
	byRef, err := st.GetOrgByRef(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	if !byRef.MFARequired {
		t.Error("GetOrgByRef: mfa_required = false after enabling, want true")
	}

	if err := st.SetOrgMFARequired(ctx, org.ID, false); err != nil {
		t.Fatalf("SetOrgMFARequired(false): %v", err)
	}
	got2, err := st.GetOrg(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got2.MFARequired {
		t.Error("GetOrg: mfa_required = true after disabling, want false")
	}
}
