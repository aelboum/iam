// Package db opens the Postgres pool and applies embedded schema migrations.
package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"sort"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Open connects to Postgres and verifies the connection.
func Open(ctx context.Context, url string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

// OpenLimited opens a small pool of at most maxConns connections, for work
// that must not compete with the main pool (shared rate limits).
func OpenLimited(ctx context.Context, url string, maxConns int32) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	config.MaxConns = maxConns
	config.MinConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}

// migrateAdvisoryLockKey is a fixed, arbitrary key identifying the schema
// migration critical section. Every caller uses the same key, so Postgres
// serializes them cluster-wide.
const migrateAdvisoryLockKey int64 = 0x49414D5F4D4947 // "IAM_MIG"

// Migrate applies every migration file not yet recorded in schema_migrations,
// in lexical order, each inside its own transaction.
//
// The whole run is serialized by a session-level Postgres advisory lock held on
// a dedicated connection. Without it, concurrent callers — every replica of a
// scaled deployment starting at once, or parallel `go test` packages sharing one
// database — collide: catalog DDL (including CREATE TABLE IF NOT EXISTS) is not
// concurrency-safe and raises duplicate-key errors, and two callers can both see
// a migration as unapplied and then both insert its schema_migrations row. Later
// callers block on the lock, and by the time they acquire it every migration is
// already recorded, so they do nothing.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection: %w", err)
	}
	// Release the lock before the connection returns to the pool. A session-level
	// advisory lock outlives the pool checkout, so an un-released connection would
	// keep the lock and deadlock every later migrator. Use a fresh context so the
	// unlock still runs if ctx was cancelled. If the unlock itself fails on a still-
	// live connection, destroy that connection instead of returning it to the pool,
	// so the session — and with it the lock — ends.
	locked := false
	defer func() {
		if locked {
			if _, uerr := conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", migrateAdvisoryLockKey); uerr != nil {
				slog.Warn("migration advisory unlock failed; discarding connection", "error", uerr)
				conn.Hijack().Close(context.Background())
				return
			}
		}
		conn.Release()
	}()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrateAdvisoryLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	locked = true

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	files, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)

	for _, file := range files {
		var applied bool
		if err := conn.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, file,
		).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		sql, err := migrations.ReadFile(file)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", file, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, file); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}
