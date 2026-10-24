package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Session tracks a login in progress (or completed) through the session API.
type Session struct {
	ID        string
	TokenHash string
	OrgID     string
	// UserID is nil when the login name matched no user.
	UserID            *string
	LoginName         string
	PasswordCheckedAt *time.Time
	TOTPCheckedAt     *time.Time
	PasskeyCheckedAt  *time.Time
	IDPCheckedAt      *time.Time
	// WebAuthnSession holds a pending passkey challenge (library session data).
	WebAuthnSession []byte
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

const sessionColumns = `id, token_hash, org_id, user_id, login_name, password_checked_at, totp_checked_at,
	passkey_checked_at, idp_checked_at, webauthn_session, created_at, expires_at`

func scanSession(row interface{ Scan(...any) error }) (*Session, error) {
	var s Session
	if err := row.Scan(&s.ID, &s.TokenHash, &s.OrgID, &s.UserID, &s.LoginName, &s.PasswordCheckedAt,
		&s.TOTPCheckedAt, &s.PasskeyCheckedAt, &s.IDPCheckedAt, &s.WebAuthnSession, &s.CreatedAt, &s.ExpiresAt); err != nil {
		return nil, mapErr(err)
	}
	return &s, nil
}

func (s *Store) CreateSession(ctx context.Context, orgID string, userID *string, loginName, tokenHash string, expiresAt time.Time) (*Session, error) {
	return scanSession(s.pool.QueryRow(ctx, `
		INSERT INTO sessions (id, token_hash, org_id, user_id, login_name, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+sessionColumns,
		uuid.NewString(), tokenHash, orgID, userID, loginName, expiresAt))
}

// GetSession returns a session that has not expired.
func (s *Store) GetSession(ctx context.Context, id string) (*Session, error) {
	return scanSession(s.pool.QueryRow(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE id = $1 AND expires_at > now()`, id))
}

// MarkSessionPassword records a verified password. It clears any earlier
// TOTP check, so a re-authentication (e.g. for max_age) needs a fresh code.
func (s *Store) MarkSessionPassword(ctx context.Context, id string) error {
	return s.execOne(ctx, `UPDATE sessions SET password_checked_at = now(), totp_checked_at = NULL WHERE id = $1`, id)
}

func (s *Store) MarkSessionTOTP(ctx context.Context, id string) error {
	return s.execOne(ctx, `UPDATE sessions SET totp_checked_at = now() WHERE id = $1`, id)
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM sessions WHERE id = $1`, id)
}

// SetSessionChallenge stores (or with nil clears) a pending passkey challenge.
func (s *Store) SetSessionChallenge(ctx context.Context, id string, challenge []byte) error {
	return s.execOne(ctx, `UPDATE sessions SET webauthn_session = $2 WHERE id = $1`, id, challenge)
}

// MarkSessionPasskey records a verified passkey and consumes the challenge.
func (s *Store) MarkSessionPasskey(ctx context.Context, id string) error {
	return s.execOne(ctx, `UPDATE sessions SET passkey_checked_at = now(), webauthn_session = NULL WHERE id = $1`, id)
}
