package store

import (
	"context"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aelboum/iam/internal/ratelimit"
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

// PGLimiter is a rate limiter shared by every engine instance (audit M10, L11).
//
//   - A local in-memory limiter with the same limits runs first. It caps what
//     one instance can be made to do and rejects floods without touching the
//     database, so rejected requests cost no database write.
//   - The shared count lives in Postgres, reached through a small dedicated
//     connection pool, so saturating the application's pool cannot disable it.
//   - It uses a sliding window (the previous minute weighted by how much of it
//     still overlaps), which avoids the 2x burst at fixed window boundaries.
//   - If the database is slow or unreachable, the decision falls back to the
//     local limiter: limits degrade to per-instance limits, never to "allow
//     everything" and never to "deny everything" (which would be an easy DoS).
//
// The counters live in an UNLOGGED table: after a database crash or a
// failover to a replica they start from zero, and the local limiters still apply.
type PGLimiter struct {
	pool  *pgxpool.Pool
	name  string
	limit float64
	local *ratelimit.Limiter
}

// limiterTimeout bounds how long a request waits for the shared count.
const limiterTimeout = 300 * time.Millisecond

var limiterErrorLog atomic.Int64 // unix time of the last logged limiter error

// NewPGLimiter matches ratelimit.Factory. The shared limit is
// max(perMinute, burst) per sliding minute. Call SetLimiterPool first.
func (s *Store) NewPGLimiter(name string, perMinute float64, burst int) *PGLimiter {
	pool := s.limiterPool
	if pool == nil {
		pool = s.pool
	}
	return &PGLimiter{pool: pool, name: name, limit: max(perMinute, float64(burst)), local: ratelimit.New(perMinute, burst)}
}

// SetLimiterPool sets the dedicated connection pool for shared rate limits.
func (s *Store) SetLimiterPool(pool *pgxpool.Pool) { s.limiterPool = pool }

func (l *PGLimiter) Allow(key string) bool {
	if !l.local.Allow(key) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), limiterTimeout)
	defer cancel()
	var current, previous, elapsed float64
	err := l.pool.QueryRow(ctx, `
		WITH cur AS (
			INSERT INTO rate_limit_windows (key, window_start, hits)
			VALUES ($1, date_trunc('minute', now()), 1)
			ON CONFLICT (key, window_start) DO UPDATE SET hits = rate_limit_windows.hits + 1
			RETURNING hits, window_start)
		SELECT cur.hits,
			coalesce((SELECT hits FROM rate_limit_windows p
				WHERE p.key = $1 AND p.window_start = cur.window_start - make_interval(mins => 1)), 0),
			extract(epoch FROM now() - cur.window_start)
		FROM cur`, l.name+":"+key).Scan(&current, &previous, &elapsed)
	if err != nil {
		// Log at most every 10 seconds so a database outage cannot flood the logs.
		if now := time.Now().Unix(); now-limiterErrorLog.Load() >= 10 {
			limiterErrorLog.Store(now)
			slog.Error("shared rate limiter unavailable; using per-instance limits", "limiter", l.name, "error", err)
		}
		return true // the local limiter above already allowed this event
	}
	weight := max(0, 1-elapsed/60)
	return previous*weight+current <= l.limit
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
