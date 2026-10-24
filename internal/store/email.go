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

// CreatePasswordReset stores a reset token for a user, replacing an older one
// unless that was issued within the cooldown (then ErrTooSoon).
func (s *Store) CreatePasswordReset(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET token_hash = $2, expires_at = $3, created_at = now()
		WHERE password_resets.created_at < now() - make_interval(secs => $4)`,
		userID, tokenHash, expiresAt, emailCodeCooldown.Seconds())
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrTooSoon
	}
	return nil
}

// PeekPasswordReset returns the user of an unexpired reset token without using it.
func (s *Store) PeekPasswordReset(ctx context.Context, tokenHash string) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx,
		`SELECT user_id FROM password_resets WHERE token_hash = $1 AND expires_at > now()`, tokenHash).Scan(&userID)
	return userID, mapErr(err)
}

// ConsumePasswordReset removes an unexpired reset token and returns its user.
// A token works exactly once.
func (s *Store) ConsumePasswordReset(ctx context.Context, tokenHash string) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx,
		`DELETE FROM password_resets WHERE token_hash = $1 AND expires_at > now() RETURNING user_id`, tokenHash).Scan(&userID)
	return userID, mapErr(err)
}

// ClearTemporaryLockout ends a failed-login lockout (not a manual lock).
func (s *Store) ClearTemporaryLockout(ctx context.Context, userID string) error {
	return s.execOne(ctx, `UPDATE users SET locked_until = NULL, failed_logins = 0, mfa_failed_logins = 0 WHERE id = $1`, userID)
}
