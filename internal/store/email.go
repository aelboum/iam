package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// MaxEmailCodeAttempts bounds guessing of email verification codes.
const MaxEmailCodeAttempts = 5

// ErrTooSoon is returned when a new code is requested within the cooldown.
var ErrTooSoon = errors.New("a code was requested too recently")

// emailCodeCooldown is the minimum time between codes. A new code resets the
// attempt counter, so without it the 5-attempt cap could be bypassed.
const emailCodeCooldown = time.Minute

// SetEmailVerification replaces the pending verification code of a user.
func (s *Store) SetEmailVerification(ctx context.Context, userID, email, codeHash string, expiresAt time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO email_verifications (user_id, email, code_hash, expires_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id) DO UPDATE SET email = $2, code_hash = $3, attempts = 0, expires_at = $4, created_at = now()
		WHERE email_verifications.created_at < now() - make_interval(secs => $5)`,
		userID, email, codeHash, expiresAt, emailCodeCooldown.Seconds())
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrTooSoon
	}
	return nil
}

// ConsumeEmailVerification checks a code. On success the email is marked
// verified (if it still matches the user's email) and the code is deleted.
// Every attempt counts; the code is burned after MaxEmailCodeAttempts.
func (s *Store) ConsumeEmailVerification(ctx context.Context, userID string, check func(codeHash string) bool) (bool, error) {
	ok := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var email, codeHash string
		var attempts int
		err := tx.QueryRow(ctx, `
			SELECT email, code_hash, attempts FROM email_verifications
			WHERE user_id = $1 AND expires_at > now() FOR UPDATE`, userID).Scan(&email, &codeHash, &attempts)
		if err != nil {
			return mapErr(err)
		}
		if attempts >= MaxEmailCodeAttempts {
			return ErrNotFound
		}
		if !check(codeHash) {
			_, err := tx.Exec(ctx, `UPDATE email_verifications SET attempts = attempts + 1 WHERE user_id = $1`, userID)
			return mapErr(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM email_verifications WHERE user_id = $1`, userID); err != nil {
			return mapErr(err)
		}
		tag, err := tx.Exec(ctx,
			`UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1 AND lower(email) = lower($2)`,
			userID, email)
		if err != nil {
			return mapErr(err)
		}
		ok = tag.RowsAffected() == 1
		return nil
	})
	return ok, err
}

// --- password reset ---------------------------------------------------------------------

// maxOutstandingResets bounds how many unexpired reset tokens a user can hold.
// A new request does not invalidate the token already emailed (audit L2).
const maxOutstandingResets = 3

// CreatePasswordReset stores a new reset token. It returns ErrTooSoon if the
// user received one within the cooldown; callers must then answer exactly as
// for an unknown user, so the cooldown reveals nothing (audit L1).
// rowQuerier is the QueryRow method shared by the pool and a transaction, so a
// read can run either locked (inside a tx) or lock-free (on the pool).
type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// recentReset reports whether userID has a reset token created within the
// cooldown window. Indexed by password_resets_user_idx.
func (s *Store) recentReset(ctx context.Context, q rowQuerier, userID string) (bool, error) {
	var recent int
	if err := q.QueryRow(ctx, `
		SELECT count(*) FROM password_resets
		WHERE user_id = $1 AND created_at > now() - make_interval(secs => $2)`,
		userID, emailCodeCooldown.Seconds()).Scan(&recent); err != nil {
		return false, mapErr(err)
	}
	return recent > 0, nil
}

func (s *Store) CreatePasswordReset(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	// Fast path: reject a request made during the cooldown with a single
	// indexed read, no lock and no transaction. This keeps the cost of a
	// rejected request close to that of an unknown-user lookup, so a holder of
	// a login key learns little about account state from response timing
	// (audit L1). It is only a fast path: the lock-held re-check below still
	// enforces the cooldown and the outstanding-token cap exactly, so a burst
	// of concurrent requests still yields at most one new token.
	if tooSoon, err := s.recentReset(ctx, s.pool, userID); err != nil {
		return err
	} else if tooSoon {
		return ErrTooSoon
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Serialize requests for the same user.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, userID); err != nil {
			return mapErr(err)
		}
		if tooSoon, err := s.recentReset(ctx, tx, userID); err != nil {
			return err
		} else if tooSoon {
			return ErrTooSoon
		}
		// Keep at most maxOutstandingResets-1 older unexpired tokens.
		if _, err := tx.Exec(ctx, `
			DELETE FROM password_resets WHERE user_id = $1 AND token_hash NOT IN (
				SELECT token_hash FROM password_resets WHERE user_id = $1 AND expires_at > now()
				ORDER BY created_at DESC LIMIT $2)`, userID, maxOutstandingResets-1); err != nil {
			return mapErr(err)
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO password_resets (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
			tokenHash, userID, expiresAt)
		return mapErr(err)
	})
}

// PeekPasswordReset returns the user of an unexpired reset token without using it.
func (s *Store) PeekPasswordReset(ctx context.Context, tokenHash string) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx,
		`SELECT user_id FROM password_resets WHERE token_hash = $1 AND expires_at > now()`, tokenHash).Scan(&userID)
	return userID, mapErr(err)
}

// CompletePasswordReset atomically consumes the token, sets the new password
// hash and ends every session, token and outstanding reset of the user. It
// fails with ErrNotFound and changes nothing if the token is unknown, used or
// expired, or if the user is locked or not a human user (audit M12).
// Only the password failure counter is cleared: TOTP failures and an active
// lockout stay in force (audit L3).
func (s *Store) CompletePasswordReset(ctx context.Context, tokenHash, userID, passwordHash string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM password_resets WHERE token_hash = $1 AND user_id = $2 AND expires_at > now()`,
			tokenHash, userID)
		if err != nil {
			return mapErr(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		// NOT locked rejects a manually locked account only. An active temporary
		// lockout (locked_until / mfa_locked_until) is left untouched on purpose
		// so it keeps blocking at login (audit L3); only the password failure
		// counter is cleared here. Guarded by password_reset_lockout_test.go.
		tag, err = tx.Exec(ctx, `
			UPDATE users SET password_hash = $2, failed_logins = 0, updated_at = now()
			WHERE id = $1 AND NOT locked AND kind = $3`, userID, passwordHash, KindHuman)
		if err != nil {
			return mapErr(err)
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return revokeUserCredentialsTx(ctx, tx, userID)
	})
}

// DeletePasswordResets invalidates every outstanding reset token of a user.
func (s *Store) DeletePasswordResets(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM password_resets WHERE user_id = $1`, userID)
	return mapErr(err)
}

// revokeUserCredentialsTx ends a user's tokens, sessions and reset tokens.
// The uuid columns are compared as uuid ($1::uuid), not as text, so the
// sessions_user_idx / password_resets_user_expires_idx indexes are used
// instead of a sequential scan on every credential change.
func revokeUserCredentialsTx(ctx context.Context, tx pgx.Tx, userID string) error {
	for _, stmt := range []string{
		`DELETE FROM access_tokens WHERE subject = $1`,
		`DELETE FROM refresh_tokens WHERE subject = $1`,
		`DELETE FROM sessions WHERE user_id = $1::uuid`,
		`DELETE FROM password_resets WHERE user_id = $1::uuid`,
	} {
		if _, err := tx.Exec(ctx, stmt, userID); err != nil {
			return mapErr(err)
		}
	}
	return nil
}
