package store

import (
	"context"
	"time"
)

// Passkey is a stored WebAuthn credential. Credential is the WebAuthn
// library's credential struct as JSON (public key, sign count, flags).
type Passkey struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	Name       string     `json:"name"`
	Credential []byte     `json:"-"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

func (s *Store) ListPasskeys(ctx context.Context, userID string) ([]*Passkey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, user_id, name, credential, created_at, last_used_at FROM webauthn_credentials
		WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	keys := []*Passkey{}
	for rows.Next() {
		var p Passkey
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.Credential, &p.CreatedAt, &p.LastUsedAt); err != nil {
			return nil, mapErr(err)
		}
		keys = append(keys, &p)
	}
	return keys, mapErr(rows.Err())
}

func (s *Store) AddPasskey(ctx context.Context, id, userID, name string, credential []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO webauthn_credentials (id, user_id, name, credential) VALUES ($1, $2, $3, $4)`,
		id, userID, name, credential)
	return mapErr(err)
}

// UpdatePasskeyUse stores the credential after a login (new sign counter).
func (s *Store) UpdatePasskeyUse(ctx context.Context, id string, credential []byte) error {
	return s.execOne(ctx,
		`UPDATE webauthn_credentials SET credential = $2, last_used_at = now() WHERE id = $1`, id, credential)
}

func (s *Store) DeletePasskey(ctx context.Context, userID, id string) error {
	return s.execOne(ctx, `DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2`, id, userID)
}

// SetPasskeyRegistration stores a pending registration challenge.
func (s *Store) SetPasskeyRegistration(ctx context.Context, userID string, session []byte, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO webauthn_registrations (user_id, session, expires_at) VALUES ($1, $2, $3)
		ON CONFLICT (user_id) DO UPDATE SET session = $2, expires_at = $3`, userID, session, expiresAt)
	return mapErr(err)
}

// TakePasskeyRegistration consumes a pending, unexpired registration challenge.
func (s *Store) TakePasskeyRegistration(ctx context.Context, userID string) ([]byte, error) {
	var session []byte
	err := s.pool.QueryRow(ctx, `
		DELETE FROM webauthn_registrations WHERE user_id = $1 AND expires_at > now() RETURNING session`,
		userID).Scan(&session)
	return session, mapErr(err)
}
