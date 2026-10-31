package store

import (
	"context"
	"errors"
	"testing"

	"github.com/aelboum/iam/internal/secret"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests cover the CRYPTO-05 D6 authorization boundary for signing-key
// revocation: only an API key explicitly granted the revoker capability, or a
// valid break-glass credential, may revoke; every denial leaves audit evidence;
// and the recorded identity comes from the verified credential, never a
// caller-supplied string. They reuse openRevokeTestStore/insertTestKey from the
// durable-revocation test file and are isolation-safe (scoped to created ids).

func denialCount(t *testing.T, pool *pgxpool.Pool, ctx context.Context, target string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE action='signing_key.revoke.denied' AND target=$1`, target,
	).Scan(&n); err != nil {
		t.Fatalf("count denials: %v", err)
	}
	return n
}

func mkAPIKey(t *testing.T, st *Store, ctx context.Context, scope string, canRevoke bool) (id, raw string) {
	t.Helper()
	raw = "optok-" + uuid.NewString()
	k, err := st.CreateAPIKey(ctx, "op-"+uuid.NewString(), nil, scope, nil, secret.Hash(raw), nil)
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if canRevoke {
		if err := st.SetKeyRevoker(ctx, k.ID, true); err != nil {
			t.Fatalf("grant revoker: %v", err)
		}
	}
	return k.ID, raw
}

// E1/E3/E15: an authenticated key without the capability (including an ordinary
// admin key, and a compromised login key) is denied, with audit evidence.
func TestAuthorizeKeyRevokerDeniesWithoutCapability(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	target := uuid.NewString()
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, target)

	for _, scope := range []string{ScopeAdmin, ScopeLogin} {
		_, raw := mkAPIKey(t, st, ctx, scope, false)
		if _, err := st.AuthorizeKeyRevoker(ctx, secret.Hash(raw), target); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("scope %q without capability: err = %v; want ErrUnauthorized", scope, err)
		}
	}
	if denialCount(t, pool, ctx, target) < 2 {
		t.Error("authorization denials were not audited")
	}
}

// E1 (unknown credential): an unrecognized key is denied and audited as unknown.
func TestAuthorizeKeyRevokerDeniesUnknownCredential(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	target := uuid.NewString()
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, target)

	if _, err := st.AuthorizeKeyRevoker(ctx, secret.Hash("not-a-real-key-"+uuid.NewString()), target); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown credential: err = %v; want ErrUnauthorized", err)
	}
	if denialCount(t, pool, ctx, target) != 1 {
		t.Error("unknown-credential denial not audited exactly once")
	}
}

// E4/E5/E6/E7: a granted key is authorized; the identity is derived from the key
// id (never a caller string); the revocation records that operator identity.
func TestAuthorizedRevokeRecordsOperatorIdentity(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	keyID, raw := mkAPIKey(t, st, ctx, ScopeAdmin, true)
	target := insertTestKey(t, st, ctx)
	defer pool.Exec(ctx, `DELETE FROM signing_keys WHERE id=$1`, target)
	defer pool.Exec(ctx, `DELETE FROM revoked_signing_keys WHERE id=$1`, target)
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, target)

	ident, err := st.AuthorizeKeyRevoker(ctx, secret.Hash(raw), target)
	if err != nil {
		t.Fatalf("authorize granted key: %v", err)
	}
	want := "api_key:" + keyID
	if ident.Actor != want || ident.Role != "signing_key_revoker" || ident.BreakGlass {
		t.Fatalf("identity = %+v; want actor=%s role=signing_key_revoker breakglass=false", ident, want)
	}

	if err := st.RevokeSigningKeyWithDetail(ctx, target, ident.Actor, "leak", map[string]any{
		"authorized": true, "authorized_role": ident.Role, "break_glass": false,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// revoked_by and the audit actor must both be the verified operator identity.
	var revokedBy, auditActor string
	pool.QueryRow(ctx, `SELECT revoked_by FROM revoked_signing_keys WHERE id=$1`, target).Scan(&revokedBy)
	pool.QueryRow(ctx, `SELECT actor FROM audit_events WHERE action='signing_key.revoke' AND target=$1`, target).Scan(&auditActor)
	if revokedBy != want {
		t.Errorf("revoked_by = %q; want %q", revokedBy, want)
	}
	if auditActor != want {
		t.Errorf("audit actor = %q; want %q", auditActor, want)
	}
}

// E9/E10: break-glass requires a valid credential (denied + audited otherwise)
// and, when valid, yields an attributed emergency identity.
func TestBreakGlassAuthorization(t *testing.T) {
	st, pool, ctx := openRevokeTestStore(t)
	defer pool.Close()
	target := uuid.NewString()
	defer pool.Exec(ctx, `DELETE FROM audit_events WHERE target=$1`, target)

	bg := "breakglass-secret-" + uuid.NewString()
	// Unknown secret is denied and audited.
	if _, err := st.AuthorizeBreakGlass(ctx, secret.Hash(bg), "oncall-alice", target); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown break-glass: err = %v; want ErrUnauthorized", err)
	}
	if denialCount(t, pool, ctx, target) != 1 {
		t.Error("break-glass denial not audited")
	}
	// Register the credential; now it authorizes, attributed to the operator.
	label := "oncall-" + uuid.NewString()
	if err := st.AddBreakGlassKey(ctx, secret.Hash(bg), label); err != nil {
		t.Fatalf("add break-glass: %v", err)
	}
	ident, err := st.AuthorizeBreakGlass(ctx, secret.Hash(bg), "oncall-alice", target)
	if err != nil {
		t.Fatalf("authorize break-glass: %v", err)
	}
	if !ident.BreakGlass || ident.Role != "break_glass" || ident.Actor != "break_glass:oncall-alice" {
		t.Errorf("identity = %+v; want break_glass role, actor break_glass:oncall-alice", ident)
	}
}
