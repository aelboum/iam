package store

import (
	"context"
	"log/slog"
	"strconv"
	"time"
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

// PGLimiter is a rate limiter shared by every engine instance, counting hits
// per key in fixed one-minute windows in Postgres.
type PGLimiter struct {
	store *Store
	name  string
	limit int
}

// NewPGLimiter matches ratelimit.Factory. A window allows max(perMinute, burst) hits.
func (s *Store) NewPGLimiter(name string, perMinute float64, burst int) *PGLimiter {
	return &PGLimiter{store: s, name: name, limit: max(int(perMinute), burst)}
}

// Allow counts a hit. If the database is unreachable it allows the event:
// the engine cannot serve requests without its database anyway, and failing
// closed would turn a database hiccup into a full outage.
func (l *PGLimiter) Allow(key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var hits int
	err := l.store.pool.QueryRow(ctx, `
		INSERT INTO rate_limit_windows (key, window_start, hits)
		VALUES ($1, date_trunc('minute', now()), 1)
		ON CONFLICT (key, window_start) DO UPDATE SET hits = rate_limit_windows.hits + 1
		RETURNING hits`, l.name+":"+key).Scan(&hits)
	if err != nil {
		slog.Error("shared rate limiter unavailable; allowing", "limiter", l.name, "error", err)
		return true
	}
	return hits <= l.limit
}

// PurgeRateLimits drops finished windows.
func (s *Store) PurgeRateLimits(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM rate_limit_windows WHERE window_start < now() - make_interval(secs => 120)`)
	return mapErr(err)
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
	QuotaIDPsPerOrg      = Quota{"identity providers per org", "identity_providers", "org_id"}
)
