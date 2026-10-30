package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Org struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	// MFARequired, when true, forces every user of this org to have and use a
	// second factor to complete a login (security follow-up #2).
	MFARequired bool `json:"mfa_required"`
}

const orgColumns = `id, name, slug, created_at, mfa_required`

func scanOrg(row interface{ Scan(...any) error }) (*Org, error) {
	var o Org
	if err := row.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.MFARequired); err != nil {
		return nil, mapErr(err)
	}
	return &o, nil
}

// SetOrgMFARequired sets the org-level MFA enforcement policy.
func (s *Store) SetOrgMFARequired(ctx context.Context, id string, required bool) error {
	return s.execOne(ctx, `UPDATE orgs SET mfa_required = $2 WHERE id = $1`, id, required)
}

func (s *Store) CreateOrg(ctx context.Context, name, slug string) (*Org, error) {
	return scanOrg(s.pool.QueryRow(ctx,
		`INSERT INTO orgs (id, name, slug) VALUES ($1, $2, $3) RETURNING `+orgColumns,
		uuid.NewString(), name, slug))
}

func (s *Store) GetOrg(ctx context.Context, id string) (*Org, error) {
	return scanOrg(s.pool.QueryRow(ctx, `SELECT `+orgColumns+` FROM orgs WHERE id = $1`, id))
}

// GetOrgByRef resolves an org by id or slug.
func (s *Store) GetOrgByRef(ctx context.Context, ref string) (*Org, error) {
	if _, err := uuid.Parse(ref); err == nil {
		return s.GetOrg(ctx, ref)
	}
	return scanOrg(s.pool.QueryRow(ctx, `SELECT `+orgColumns+` FROM orgs WHERE slug = $1`, ref))
}

func (s *Store) ListOrgs(ctx context.Context, p Page) ([]*Org, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+orgColumns+` FROM orgs ORDER BY created_at, id`+p.sql())
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	orgs := []*Org{}
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, mapErr(rows.Err())
}

func (s *Store) DeleteOrg(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM orgs WHERE id = $1`, id)
}
