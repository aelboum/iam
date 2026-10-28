package store

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// TestDeleteAccessTokenOnlyTargetKeepsRefresh pins the dangling-token contract
// of DeleteAccessToken. The schema stores access_tokens.refresh_token_id and
// refresh_tokens.access_token_id as plain uuid columns with no foreign key, and
// subject/client_id as plain text, so deleting an access token neither
// cascades to nor is blocked by any other row: it removes exactly that one
// access token, leaves the linked refresh token (and its family) alive, and
// touches no other user's or client's tokens. Deleting an unknown id is a
// no-op (plain Exec, not execOne). Needs IAM_TEST_DATABASE_URL.
func TestDeleteAccessTokenOnlyTargetKeepsRefresh(t *testing.T) {
	st, pool := lifecycleStore(t)
	ctx := context.Background()

	u1 := lifecycleUser(t, st, pool)
	u2 := lifecycleUser(t, st, pool)

	at1, rt1, _ := lifecycleTokens(t, st, "c1", u1.ID, "")
	at2, rt2, _ := lifecycleTokens(t, st, "c1", u1.ID, "") // same user+client, other family
	atB, rtB, _ := lifecycleTokens(t, st, "c2", u2.ID, "") // other user + client

	if err := st.DeleteAccessToken(ctx, at1); err != nil {
		t.Fatalf("DeleteAccessToken: %v", err)
	}
	if accessAlive(t, st, at1) {
		t.Error("DeleteAccessToken must remove the targeted access token")
	}
	// Contract: an access-token delete is narrow. The linked refresh token has
	// no FK to the access token and stays alive (its family is not revoked).
	if !refreshAlive(t, st, rt1) {
		t.Error("DeleteAccessToken must leave the linked refresh token alive (no cascade)")
	}
	// Every other token is untouched.
	if !(accessAlive(t, st, at2) && refreshAlive(t, st, rt2)) {
		t.Error("another family of the same user+client must be untouched")
	}
	if !(accessAlive(t, st, atB) && refreshAlive(t, st, rtB)) {
		t.Error("another user's/client's tokens must be untouched")
	}

	// Deleting an unknown id affects nothing and returns no error.
	if err := st.DeleteAccessToken(ctx, uuid.NewString()); err != nil {
		t.Errorf("DeleteAccessToken on an unknown id must be a no-op, got %v", err)
	}
	if !(refreshAlive(t, st, rt1) && accessAlive(t, st, at2) && refreshAlive(t, st, rt2) &&
		accessAlive(t, st, atB) && refreshAlive(t, st, rtB)) {
		t.Error("a no-op delete of an unknown id must not touch any token")
	}
}
