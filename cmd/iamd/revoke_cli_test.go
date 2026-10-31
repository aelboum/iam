package main

import (
	"strings"
	"testing"
)

// These cover the iamd revoke-key preconditions enforced before any database or
// authority access (CRYPTO-05 D6): a key id is required and a reason is
// mandatory. The operator-credential requirement is covered at the store layer
// by the AuthorizeKeyRevoker tests. They do not touch a database.

func TestRevokeKeyRequiresKeyID(t *testing.T) {
	if err := revokeSigningKey([]string{"--reason", "leak"}); err == nil {
		t.Fatal("revoke-key with no key id must error")
	}
}

func TestRevokeKeyRequiresReason(t *testing.T) {
	// No --reason and no IAM_REVOKE_REASON: must be rejected before DB access.
	t.Setenv("IAM_REVOKE_REASON", "")
	err := revokeSigningKey([]string{"some-key-id"})
	if err == nil || !strings.Contains(err.Error(), "reason is required") {
		t.Fatalf("revoke-key without a reason = %v; want a 'reason is required' error", err)
	}
}
