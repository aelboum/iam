package store

import (
	"context"
	"strconv"
)

// Page selects a slice of a list. Lists are ordered oldest first.
type Page struct {
	Limit  int
	Offset int
}

const (
	DefaultPageSize = 100
	MaxPageSize     = 1000
)

// sql renders LIMIT/OFFSET. Values are clamped integers, never user strings.
func (p Page) sql() string {
	limit := p.Limit
	if limit <= 0 || limit > MaxPageSize {
		limit = DefaultPageSize
	}
	offset := max(p.Offset, 0)
	return " LIMIT " + strconv.Itoa(limit) + " OFFSET " + strconv.Itoa(offset)
}

// Count returns how many rows of a quota-limited resource exist for owner.
// table and column are fixed identifiers from the quota list, never user input.
func (s *Store) Count(ctx context.Context, q Quota, ownerID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM `+q.table+` WHERE `+q.column+` = $1`, ownerID).Scan(&n)
	return n, mapErr(err)
}

// Quota identifies a resource whose count per owner is limited.
type Quota struct {
	Name   string
	table  string
	column string
}

var (
	QuotaUsersPerOrg     = Quota{"users per org", "users", "org_id"}
	QuotaProjectsPerOrg  = Quota{"projects per org", "projects", "owner_org_id"}
	QuotaKeysPerOrg      = Quota{"API keys per org", "api_keys", "org_id"}
	QuotaAppsPerProject  = Quota{"apps per project", "apps", "project_id"}
	QuotaRolesPerProject = Quota{"roles per project", "project_roles", "project_id"}
)
