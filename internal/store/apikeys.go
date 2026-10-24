package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	// ScopeAdmin keys use the management API.
	ScopeAdmin = "admin"
	// ScopeLogin keys only use the session and auth request API (login UI backends).
	ScopeLogin = "login"
)

// APIKey authenticates management API callers. OrgID nil means instance-wide.
type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	OrgID      *string    `json:"org_id"`
	Scope      string     `json:"scope"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

const apiKeyColumns = `id, name, org_id, scope, expires_at, created_at, last_used_at`

func scanAPIKey(row interface{ Scan(...any) error }) (*APIKey, error) {
	var k APIKey
	if err := row.Scan(&k.ID, &k.Name, &k.OrgID, &k.Scope, &k.ExpiresAt, &k.CreatedAt, &k.LastUsedAt); err != nil {
		return nil, mapErr(err)
	}
	return &k, nil
}

// createdBy is the key that minted this one; deleting it deletes this key too.
func (s *Store) CreateAPIKey(ctx context.Context, name string, orgID *string, scope string, expiresAt *time.Time, keyHash string, createdBy *string) (*APIKey, error) {
	return scanAPIKey(s.pool.QueryRow(ctx, `
		INSERT INTO api_keys (id, name, org_id, scope, expires_at, key_hash, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+apiKeyColumns,
		uuid.NewString(), name, orgID, scope, expiresAt, keyHash, createdBy))
}

// BootstrapAPIKey creates the instance admin key on the very first start only.
// Once created, deleting or rotating it through the API is permanent: it is
// not recreated from the environment on restart.
func (s *Store) BootstrapAPIKey(ctx context.Context, name, keyHash string) (created bool, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO instance_state (key) VALUES ('bootstrap_admin_key') ON CONFLICT DO NOTHING`)
		if err != nil || tag.RowsAffected() == 0 {
			return mapErr(err)
		}
		tag, err = tx.Exec(ctx,
			`INSERT INTO api_keys (id, name, key_hash) VALUES ($1, $2, $3) ON CONFLICT (key_hash) DO NOTHING`,
			uuid.NewString(), name, keyHash)
		created = err == nil && tag.RowsAffected() == 1
		return mapErr(err)
	})
	return created, err
}

// AuthenticateAPIKey looks up an unexpired key by hash and records its use.
func (s *Store) AuthenticateAPIKey(ctx context.Context, keyHash string) (*APIKey, error) {
	return scanAPIKey(s.pool.QueryRow(ctx, `
		UPDATE api_keys SET last_used_at = now()
		WHERE key_hash = $1 AND (expires_at IS NULL OR expires_at > now())
		RETURNING `+apiKeyColumns, keyHash))
}

// ListAPIKeys lists the keys of an org, or the instance keys when orgID is nil.
func (s *Store) ListAPIKeys(ctx context.Context, orgID *string, p Page) ([]*APIKey, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+apiKeyColumns+` FROM api_keys WHERE org_id IS NOT DISTINCT FROM $1 ORDER BY created_at, id`+p.sql(), orgID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	keys := []*APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, mapErr(rows.Err())
}

func (s *Store) DeleteAPIKey(ctx context.Context, orgID *string, id string) error {
	return s.execOne(ctx, `DELETE FROM api_keys WHERE id = $1 AND org_id IS NOT DISTINCT FROM $2`, id, orgID)
}
