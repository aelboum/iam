package store

import (
	"context"

	"github.com/google/uuid"
)

// ReplaceRecoveryCodes deletes any existing recovery codes for the user and
// stores the given hashes as the new, unused set, atomically. Generating a new
// set therefore invalidates the old one.
func (s *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, codeHashes []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return mapErr(err)
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(ctx,
			`INSERT INTO mfa_recovery_codes (id, user_id, code_hash) VALUES ($1, $2, $3)`,
			uuid.NewString(), userID, h); err != nil {
			return mapErr(err)
		}
	}
	return mapErr(tx.Commit(ctx))
}

// ConsumeRecoveryCode marks the user's matching unused code as used and reports
// whether exactly one was consumed. The UPDATE is atomic, so a code redeems at
// most once even under concurrent attempts.
func (s *Store) ConsumeRecoveryCode(ctx context.Context, userID, codeHash string) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE mfa_recovery_codes SET used_at = now()
		 WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`, userID, codeHash)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

// CountUnusedRecoveryCodes returns how many unused recovery codes the user has.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID).Scan(&n)
	return n, mapErr(err)
}
