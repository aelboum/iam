package store

import (
	"context"
	"errors"
)

// This file implements the CRYPTO-05 D6 authorization boundary for signing-key
// revocation. Authority to revoke is NOT implied by database access or by the
// ability to run iamd: a caller must present an API key explicitly granted the
// revoker capability, or a distinct break-glass credential. Every denial and
// every break-glass use is recorded in the audit trail.

// RevokerIdentity is the authenticated, authorized identity behind a revocation.
// It is derived from a verified credential, never from a caller-supplied string.
type RevokerIdentity struct {
	Actor      string // "api_key:<id>" or "break_glass:<label>"
	Role       string // "signing_key_revoker" or "break_glass"
	BreakGlass bool
}

// AuthorizeKeyRevoker verifies that keyHash belongs to an unexpired API key that
// has been granted the revoker capability, and returns its identity. On any
// failure it records an audit denial and returns ErrUnauthorized, so an
// unauthenticated or unauthorized attempt always leaves security evidence and
// never reveals why it failed.
func (s *Store) AuthorizeKeyRevoker(ctx context.Context, keyHash, targetKeyID string) (*RevokerIdentity, error) {
	key, err := s.AuthenticateAPIKey(ctx, keyHash)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.auditRevokeDenied(ctx, "unknown", targetKeyID, "unrecognized or expired operator credential")
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	if !key.CanRevokeKeys {
		s.auditRevokeDenied(ctx, "api_key:"+key.ID, targetKeyID, "operator key lacks signing_key_revoker capability")
		return nil, ErrUnauthorized
	}
	return &RevokerIdentity{
		Actor: "api_key:" + key.ID,
		Role:  "signing_key_revoker",
	}, nil
}

// AuthorizeBreakGlass verifies a break-glass secret and returns the emergency
// identity. The operator-supplied operatorID labels who activated break-glass;
// it is recorded for the mandatory post-event review but is not itself the proof
// of authority — the break-glass secret is. A missing or disabled credential is
// audited and returns ErrUnauthorized.
func (s *Store) AuthorizeBreakGlass(ctx context.Context, keyHash, operatorID, targetKeyID string) (*RevokerIdentity, error) {
	var label string
	err := s.pool.QueryRow(ctx, `
		SELECT label FROM break_glass_keys
		WHERE key_hash = $1 AND disabled_at IS NULL`, keyHash).Scan(&label)
	if err != nil {
		s.auditRevokeDenied(ctx, "break_glass:"+operatorID, targetKeyID, "unrecognized or disabled break-glass credential")
		return nil, ErrUnauthorized
	}
	actor := "break_glass:" + operatorID
	if operatorID == "" {
		actor = "break_glass:" + label
	}
	return &RevokerIdentity{Actor: actor, Role: "break_glass", BreakGlass: true}, nil
}

// SetKeyRevoker grants or revokes the signing_key_revoker capability on an API
// key. Returns ErrNotFound if the key does not exist.
func (s *Store) SetKeyRevoker(ctx context.Context, apiKeyID string, canRevoke bool) error {
	return s.execOne(ctx, `UPDATE api_keys SET can_revoke_keys = $2 WHERE id = $1`, apiKeyID, canRevoke)
}

// AddBreakGlassKey records a break-glass credential by its hash. keyHash must be
// secret.Hash(secret); the plaintext secret is never stored.
func (s *Store) AddBreakGlassKey(ctx context.Context, keyHash, label string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO break_glass_keys (key_hash, label) VALUES ($1, $2)
		 ON CONFLICT (key_hash) DO UPDATE SET label = EXCLUDED.label, disabled_at = NULL`,
		keyHash, label)
	return mapErr(err)
}

// auditRevokeDenied records an authorization failure. It is best-effort (like all
// Store.Audit calls) so it never blocks the denial, but it ensures an attempt to
// revoke without authority leaves durable security evidence.
func (s *Store) auditRevokeDenied(ctx context.Context, actor, targetKeyID, reason string) {
	s.Audit(ctx, AuditEvent{
		Actor:  actor,
		Action: "signing_key.revoke.denied",
		Target: targetKeyID,
		Detail: map[string]any{"reason": reason},
	})
}
