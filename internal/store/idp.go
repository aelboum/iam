package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// IDP is an external OpenID Connect provider an org signs in with.
type IDP struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"org_id"`
	Name            string    `json:"name"`
	Issuer          string    `json:"issuer"`
	ClientID        string    `json:"client_id"`
	ClientSecretEnc []byte    `json:"-"`
	Scopes          []string  `json:"scopes"`
	AutoCreateUsers bool      `json:"auto_create_users"`
	LinkByEmail     bool      `json:"link_by_email"`
	CreatedAt       time.Time `json:"created_at"`
}

const idpColumns = `id, org_id, name, issuer, client_id, client_secret_enc, scopes, auto_create_users, link_by_email, created_at`

func scanIDP(row interface{ Scan(...any) error }) (*IDP, error) {
	var p IDP
	if err := row.Scan(&p.ID, &p.OrgID, &p.Name, &p.Issuer, &p.ClientID, &p.ClientSecretEnc, &p.Scopes,
		&p.AutoCreateUsers, &p.LinkByEmail, &p.CreatedAt); err != nil {
		return nil, mapErr(err)
	}
	return &p, nil
}

func (s *Store) CreateIDP(ctx context.Context, p IDP) (*IDP, error) {
	return scanIDP(s.pool.QueryRow(ctx, `
		INSERT INTO identity_providers (id, org_id, name, issuer, client_id, client_secret_enc, scopes,
			auto_create_users, link_by_email)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+idpColumns,
		uuid.NewString(), p.OrgID, p.Name, p.Issuer, p.ClientID, p.ClientSecretEnc, p.Scopes,
		p.AutoCreateUsers, p.LinkByEmail))
}

func (s *Store) GetIDP(ctx context.Context, id string) (*IDP, error) {
	return scanIDP(s.pool.QueryRow(ctx, `SELECT `+idpColumns+` FROM identity_providers WHERE id = $1`, id))
}

func (s *Store) ListIDPs(ctx context.Context, orgID string) ([]*IDP, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+idpColumns+` FROM identity_providers WHERE org_id = $1 ORDER BY created_at, id`, orgID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	idps := []*IDP{}
	for rows.Next() {
		p, err := scanIDP(rows)
		if err != nil {
			return nil, err
		}
		idps = append(idps, p)
	}
	return idps, mapErr(rows.Err())
}

func (s *Store) DeleteIDP(ctx context.Context, orgID, id string) error {
	return s.execOne(ctx, `DELETE FROM identity_providers WHERE id = $1 AND org_id = $2`, id, orgID)
}

// --- identities -------------------------------------------------------------------------------

// FindIdentity returns the local user linked to an external identity.
func (s *Store) FindIdentity(ctx context.Context, idpID, subject string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT `+userColumns+` FROM users
		WHERE id = (SELECT user_id FROM user_identities WHERE idp_id = $1 AND subject = $2)`, idpID, subject))
}

func (s *Store) LinkIdentity(ctx context.Context, idpID, subject, userID string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO user_identities (idp_id, subject, user_id) VALUES ($1, $2, $3)`, idpID, subject, userID)
	return mapErr(err)
}

// --- login intents --------------------------------------------------------------------------------

// Intent is one federated login attempt.
type Intent struct {
	ID              string
	IDPID           string
	StateHash       string
	Nonce           string
	CodeVerifierEnc []byte
	ReturnURL       string
	UserID          *string
	ExpiresAt       time.Time
}

const intentColumns = `id, idp_id, state_hash, nonce, code_verifier_enc, return_url, user_id, expires_at`

func scanIntent(row interface{ Scan(...any) error }) (*Intent, error) {
	var i Intent
	if err := row.Scan(&i.ID, &i.IDPID, &i.StateHash, &i.Nonce, &i.CodeVerifierEnc, &i.ReturnURL,
		&i.UserID, &i.ExpiresAt); err != nil {
		return nil, mapErr(err)
	}
	return &i, nil
}

func (s *Store) CreateIntent(ctx context.Context, i *Intent) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO idp_intents (id, idp_id, state_hash, nonce, code_verifier_enc, return_url, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		i.ID, i.IDPID, i.StateHash, i.Nonce, i.CodeVerifierEnc, i.ReturnURL, i.ExpiresAt)
	return mapErr(err)
}

// ClaimIntent returns a pending intent by its state and marks the state used,
// so a callback can be processed only once.
func (s *Store) ClaimIntent(ctx context.Context, stateHash string) (*Intent, error) {
	return scanIntent(s.pool.QueryRow(ctx, `
		UPDATE idp_intents SET state_hash = 'used:' || id::text
		WHERE state_hash = $1 AND user_id IS NULL AND expires_at > now()
		RETURNING `+intentColumns, stateHash))
}

// CompleteIntent records the authenticated user and the one-time redeem code.
func (s *Store) CompleteIntent(ctx context.Context, id, userID, redeemHash string) error {
	return s.execOne(ctx, `
		UPDATE idp_intents SET user_id = $2, redeem_hash = $3, expires_at = least(expires_at, now() + make_interval(secs => 300))
		WHERE id = $1 AND user_id IS NULL`, id, userID, redeemHash)
}

// RedeemIntent consumes a completed intent and returns its user and IdP.
func (s *Store) RedeemIntent(ctx context.Context, id, redeemHash string) (userID, idpID string, err error) {
	err = s.pool.QueryRow(ctx, `
		DELETE FROM idp_intents WHERE id = $1 AND redeem_hash = $2 AND user_id IS NOT NULL AND expires_at > now()
		RETURNING user_id, idp_id`, id, redeemHash).Scan(&userID, &idpID)
	return userID, idpID, mapErr(err)
}

// MarkSessionIDP records a completed federated login on a session.
func (s *Store) MarkSessionIDP(ctx context.Context, id string) error {
	return s.execOne(ctx, `UPDATE sessions SET idp_checked_at = now() WHERE id = $1`, id)
}
