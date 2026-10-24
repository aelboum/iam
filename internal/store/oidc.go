package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AuthRequest is a pending OIDC authorization request.
type AuthRequest struct {
	ID                  string
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scopes              []string
	ResponseType        string
	ResponseMode        string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              []string
	LoginHint           string
	MaxAgeSeconds       *int32
	UserID              *string
	AuthTime            *time.Time
	AMR                 []string
	Done                bool
	CreatedAt           time.Time
	ExpiresAt           time.Time
}

const authRequestColumns = `id, client_id, redirect_uri, state, nonce, scopes, response_type, response_mode,
	code_challenge, code_challenge_method, prompt, login_hint, max_age_seconds, user_id, auth_time, amr,
	done, created_at, expires_at`

func scanAuthRequest(row interface{ Scan(...any) error }) (*AuthRequest, error) {
	var a AuthRequest
	if err := row.Scan(&a.ID, &a.ClientID, &a.RedirectURI, &a.State, &a.Nonce, &a.Scopes,
		&a.ResponseType, &a.ResponseMode, &a.CodeChallenge, &a.CodeChallengeMethod, &a.Prompt,
		&a.LoginHint, &a.MaxAgeSeconds, &a.UserID, &a.AuthTime, &a.AMR, &a.Done, &a.CreatedAt,
		&a.ExpiresAt); err != nil {
		return nil, mapErr(err)
	}
	return &a, nil
}

func (s *Store) CreateAuthRequest(ctx context.Context, a *AuthRequest) (*AuthRequest, error) {
	return scanAuthRequest(s.pool.QueryRow(ctx, `
		INSERT INTO auth_requests (id, client_id, redirect_uri, state, nonce, scopes, response_type,
			response_mode, code_challenge, code_challenge_method, prompt, login_hint, max_age_seconds,
			user_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING `+authRequestColumns,
		a.ID, a.ClientID, a.RedirectURI, a.State, a.Nonce, a.Scopes, a.ResponseType, a.ResponseMode,
		a.CodeChallenge, a.CodeChallengeMethod, a.Prompt, a.LoginHint, a.MaxAgeSeconds, a.UserID,
		a.ExpiresAt))
}

func (s *Store) GetAuthRequest(ctx context.Context, id string) (*AuthRequest, error) {
	return scanAuthRequest(s.pool.QueryRow(ctx,
		`SELECT `+authRequestColumns+` FROM auth_requests WHERE id = $1 AND expires_at > now()`, id))
}

// GetAuthRequestByCode looks up an unused, unexpired authorization code
// without consuming it.
func (s *Store) GetAuthRequestByCode(ctx context.Context, code string) (*AuthRequest, error) {
	return scanAuthRequest(s.pool.QueryRow(ctx, `
		SELECT `+authRequestColumns+` FROM auth_requests
		WHERE code = $1 AND code_used_at IS NULL AND expires_at > now() AND code_expires_at > now()`, code))
}

// ClaimAuthCode atomically marks a request's code used. Only the first of
// concurrent exchanges succeeds; the others get ErrNotFound.
func (s *Store) ClaimAuthCode(ctx context.Context, authRequestID string) error {
	return s.execOne(ctx, `
		UPDATE auth_requests SET code_used_at = now()
		WHERE id = $1 AND code IS NOT NULL AND code_used_at IS NULL AND code_expires_at > now()`, authRequestID)
}

// SetAuthCode stores the authorization code, valid for ttl. Only a completed
// request gets a code, and exactly one: repeated callbacks cannot replace it.
func (s *Store) SetAuthCode(ctx context.Context, id, code string, ttl time.Duration) error {
	return s.execOne(ctx, `
		UPDATE auth_requests SET code = $2, code_expires_at = now() + make_interval(secs => $3)
		WHERE id = $1 AND done AND code IS NULL`,
		id, code, ttl.Seconds())
}

// CompleteAuthRequest binds an authenticated user to a pending request.
func (s *Store) CompleteAuthRequest(ctx context.Context, id, userID string, authTime time.Time, amr []string) error {
	return s.execOne(ctx, `
		UPDATE auth_requests SET user_id = $2, auth_time = $3, amr = $4, done = true
		WHERE id = $1 AND NOT done AND expires_at > now()`, id, userID, authTime, amr)
}

func (s *Store) DeleteAuthRequest(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM auth_requests WHERE id = $1`, id)
	return mapErr(err)
}

// --- tokens -------------------------------------------------------------------------

type AccessToken struct {
	ID             string
	ClientID       string
	Subject        string
	Audience       []string
	Scopes         []string
	RefreshTokenID *string
	ExpiresAt      time.Time
}

type RefreshToken struct {
	ID            string
	TokenHash     string
	ClientID      string
	Subject       string
	Audience      []string
	Scopes        []string
	AMR           []string
	AuthTime      time.Time
	AccessTokenID *string
	ExpiresAt     time.Time
	// FamilyID is shared by all tokens rotated from the same login.
	FamilyID string
	// UsedAt is set once the token was exchanged; presenting it again is theft.
	UsedAt *time.Time
}

func (s *Store) CreateAccessToken(ctx context.Context, t *AccessToken) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO access_tokens (id, client_id, subject, audience, scopes, refresh_token_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		t.ID, t.ClientID, t.Subject, t.Audience, t.Scopes, t.RefreshTokenID, t.ExpiresAt)
	return mapErr(err)
}

// GetAccessToken returns an access token that has not expired.
func (s *Store) GetAccessToken(ctx context.Context, id string) (*AccessToken, error) {
	var t AccessToken
	err := s.pool.QueryRow(ctx, `
		SELECT id, client_id, subject, audience, scopes, refresh_token_id, expires_at
		FROM access_tokens WHERE id = $1 AND expires_at > now()`, id,
	).Scan(&t.ID, &t.ClientID, &t.Subject, &t.Audience, &t.Scopes, &t.RefreshTokenID, &t.ExpiresAt)
	if err != nil {
		return nil, mapErr(err)
	}
	return &t, nil
}

func (s *Store) DeleteAccessToken(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM access_tokens WHERE id = $1`, id)
	return mapErr(err)
}

// CreateTokens stores an access token and, if rt is non-nil, its refresh token.
func (s *Store) CreateTokens(ctx context.Context, at *AccessToken, rt *RefreshToken) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO access_tokens (id, client_id, subject, audience, scopes, refresh_token_id, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			at.ID, at.ClientID, at.Subject, at.Audience, at.Scopes, at.RefreshTokenID, at.ExpiresAt); err != nil {
			return mapErr(err)
		}
		if rt == nil {
			return nil
		}
		return insertRefreshToken(ctx, tx, rt)
	})
}

func insertRefreshToken(ctx context.Context, tx pgx.Tx, rt *RefreshToken) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO refresh_tokens (id, token_hash, client_id, subject, audience, scopes, amr,
			auth_time, access_token_id, expires_at, family_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		rt.ID, rt.TokenHash, rt.ClientID, rt.Subject, rt.Audience, rt.Scopes, rt.AMR,
		rt.AuthTime, rt.AccessTokenID, rt.ExpiresAt, rt.FamilyID)
	return mapErr(err)
}

const refreshTokenColumns = `id, token_hash, client_id, subject, audience, scopes, amr, auth_time,
	access_token_id, expires_at, family_id, used_at`

func scanRefreshToken(row interface{ Scan(...any) error }) (*RefreshToken, error) {
	var t RefreshToken
	if err := row.Scan(&t.ID, &t.TokenHash, &t.ClientID, &t.Subject, &t.Audience, &t.Scopes,
		&t.AMR, &t.AuthTime, &t.AccessTokenID, &t.ExpiresAt, &t.FamilyID, &t.UsedAt); err != nil {
		return nil, mapErr(err)
	}
	return &t, nil
}

// GetRefreshTokenByHash returns an unexpired refresh token, including used
// ones so the caller can detect replay.
func (s *Store) GetRefreshTokenByHash(ctx context.Context, hash string) (*RefreshToken, error) {
	return scanRefreshToken(s.pool.QueryRow(ctx,
		`SELECT `+refreshTokenColumns+` FROM refresh_tokens WHERE token_hash = $1 AND expires_at > now()`, hash))
}

// GetRefreshTokenByID returns an unexpired refresh token by its row id.
func (s *Store) GetRefreshTokenByID(ctx context.Context, id string) (*RefreshToken, error) {
	return scanRefreshToken(s.pool.QueryRow(ctx,
		`SELECT `+refreshTokenColumns+` FROM refresh_tokens WHERE id = $1 AND expires_at > now()`, id))
}

// revokeTokensWhere deletes access and refresh tokens matching a condition on
// (subject, client_id). cond is a fixed SQL fragment, never user input.
func (s *Store) revokeTokensWhere(ctx context.Context, cond string, args ...any) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM access_tokens WHERE `+cond, args...); err != nil {
			return mapErr(err)
		}
		_, err := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE `+cond, args...)
		return mapErr(err)
	})
}

// RevokeOrgTokens revokes all tokens held by users of an org.
func (s *Store) RevokeOrgTokens(ctx context.Context, orgID string) error {
	return s.revokeTokensWhere(ctx, `subject IN (SELECT id::text FROM users WHERE org_id = $1)`, orgID)
}

// RevokeAppTokens revokes all tokens issued to one app.
func (s *Store) RevokeAppTokens(ctx context.Context, appID string) error {
	return s.revokeTokensWhere(ctx, `client_id IN (SELECT client_id FROM apps WHERE id = $1)`, appID)
}

// RevokeProjectTokens revokes tokens issued by a project's apps, optionally
// only those held by users of one org (orgID "" means all users).
func (s *Store) RevokeProjectTokens(ctx context.Context, projectID, orgID string) error {
	return s.revokeTokensWhere(ctx, `
		client_id IN (SELECT client_id FROM apps WHERE project_id = $1)
		AND ($2 = '' OR subject IN (SELECT id::text FROM users WHERE org_id::text = $2))`, projectID, orgID)
}

// RevokeUserProjectTokens revokes one user's tokens for a project's apps.
func (s *Store) RevokeUserProjectTokens(ctx context.Context, projectID, userID string) error {
	return s.revokeTokensWhere(ctx,
		`client_id IN (SELECT client_id FROM apps WHERE project_id = $1) AND subject = $2`, projectID, userID)
}

// RotateRefreshToken atomically marks the old refresh token used, deletes its
// access token and stores the new pair in the same family. It fails with
// ErrNotFound if the old token was already used.
func (s *Store) RotateRefreshToken(ctx context.Context, oldHash string, at *AccessToken, rt *RefreshToken) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var oldAccessID *string
		err := tx.QueryRow(ctx, `
			UPDATE refresh_tokens SET used_at = now()
			WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
			RETURNING access_token_id, family_id`, oldHash).Scan(&oldAccessID, &rt.FamilyID)
		if err != nil {
			return mapErr(err)
		}
		if oldAccessID != nil {
			if _, err := tx.Exec(ctx, `DELETE FROM access_tokens WHERE id = $1`, *oldAccessID); err != nil {
				return mapErr(err)
			}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO access_tokens (id, client_id, subject, audience, scopes, refresh_token_id, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			at.ID, at.ClientID, at.Subject, at.Audience, at.Scopes, at.RefreshTokenID, at.ExpiresAt); err != nil {
			return mapErr(err)
		}
		return insertRefreshToken(ctx, tx, rt)
	})
}

// RevokeRefreshFamily revokes every refresh token of a login and the access
// tokens issued from them.
func (s *Store) RevokeRefreshFamily(ctx context.Context, familyID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			DELETE FROM access_tokens WHERE refresh_token_id IN
				(SELECT id FROM refresh_tokens WHERE family_id = $1)`, familyID); err != nil {
			return mapErr(err)
		}
		_, err := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE family_id = $1`, familyID)
		return mapErr(err)
	})
}

// TerminateTokens revokes every token a user holds for a client.
func (s *Store) TerminateTokens(ctx context.Context, subject, clientID string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM access_tokens WHERE subject = $1 AND client_id = $2`, subject, clientID); err != nil {
			return mapErr(err)
		}
		_, err := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE subject = $1 AND client_id = $2`, subject, clientID)
		return mapErr(err)
	})
}

// RevokeUserTokens revokes every token a user holds, across clients.
func (s *Store) RevokeUserTokens(ctx context.Context, subject string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM access_tokens WHERE subject = $1`, subject); err != nil {
			return mapErr(err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE subject = $1`, subject); err != nil {
			return mapErr(err)
		}
		_, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id::text = $1`, subject)
		return mapErr(err)
	})
}

// PurgeExpired removes expired protocol state.
func (s *Store) PurgeExpired(ctx context.Context) error {
	for _, table := range []string{"auth_requests", "access_tokens", "refresh_tokens", "sessions", "signing_keys", "email_verifications"} {
		if _, err := s.pool.Exec(ctx, `DELETE FROM `+table+` WHERE expires_at < now()`); err != nil {
			return mapErr(err)
		}
	}
	return nil
}

// --- signing keys ----------------------------------------------------------------------

type SigningKey struct {
	ID            string
	Algorithm     string
	PrivateKeyEnc []byte
	CreatedAt     time.Time
	RotateAt      time.Time
	ExpiresAt     time.Time
}

func (s *Store) InsertSigningKey(ctx context.Context, k *SigningKey) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO signing_keys (id, algorithm, private_key_enc, rotate_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`, k.ID, k.Algorithm, k.PrivateKeyEnc, k.RotateAt, k.ExpiresAt)
	return mapErr(err)
}

// ListSigningKeys returns keys that are still published, newest first.
func (s *Store) ListSigningKeys(ctx context.Context) ([]*SigningKey, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, algorithm, private_key_enc, created_at, rotate_at, expires_at
		FROM signing_keys WHERE expires_at > now() ORDER BY created_at DESC`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	keys := []*SigningKey{}
	for rows.Next() {
		var k SigningKey
		if err := rows.Scan(&k.ID, &k.Algorithm, &k.PrivateKeyEnc, &k.CreatedAt, &k.RotateAt, &k.ExpiresAt); err != nil {
			return nil, mapErr(err)
		}
		keys = append(keys, &k)
	}
	return keys, mapErr(rows.Err())
}

// LockSigningKeys takes a transaction-scoped advisory lock so only one
// instance generates a new key at a time, then runs fn.
func (s *Store) LockSigningKeys(ctx context.Context, fn func(ctx context.Context) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(727274)`); err != nil {
			return err
		}
		return fn(ctx)
	})
}

// --- master key rotation -------------------------------------------------------------------

// encryptedColumns lists every column holding data sealed with the master key.
var encryptedColumns = []struct{ table, key, column string }{
	{"signing_keys", "id", "private_key_enc"},
	{"users", "id", "totp_secret_enc"},
	{"identity_providers", "id", "client_secret_enc"},
	{"idp_intents", "id", "code_verifier_enc"},
}

// Reencrypt rewrites every encrypted value for which reseal returns changed,
// in one transaction. It returns how many values were rewritten.
func (s *Store) Reencrypt(ctx context.Context, reseal func(sealed []byte) (out []byte, changed bool, err error)) (int, error) {
	n := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, c := range encryptedColumns { // fixed identifiers, never user input
			rows, err := tx.Query(ctx, `SELECT `+c.key+`::text, `+c.column+` FROM `+c.table+` WHERE `+c.column+` IS NOT NULL FOR UPDATE`)
			if err != nil {
				return mapErr(err)
			}
			type item struct {
				id  string
				val []byte
			}
			var items []item
			for rows.Next() {
				var it item
				if err := rows.Scan(&it.id, &it.val); err != nil {
					rows.Close()
					return mapErr(err)
				}
				items = append(items, it)
			}
			rows.Close()
			for _, it := range items {
				out, changed, err := reseal(it.val)
				if err != nil {
					return fmt.Errorf("%s %s: %w", c.table, it.id, err)
				}
				if !changed {
					continue
				}
				if _, err := tx.Exec(ctx, `UPDATE `+c.table+` SET `+c.column+` = $2 WHERE `+c.key+`::text = $1`, it.id, out); err != nil {
					return mapErr(err)
				}
				n++
			}
		}
		return nil
	})
	return n, err
}
