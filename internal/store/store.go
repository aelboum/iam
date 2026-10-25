// Package store is the Postgres persistence layer of the engine.
package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a unique constraint is violated.
	ErrConflict = errors.New("already exists")
	// ErrInvalidReference is returned when a referenced row does not exist.
	ErrInvalidReference = errors.New("referenced resource does not exist")
	// ErrInvalidRole is returned when role keys are not defined or not granted.
	ErrInvalidRole = errors.New("role not defined or not granted")
)

type Store struct {
	pool *pgxpool.Pool
	// limiterPool is a small dedicated pool for shared rate limits (optional).
	limiterPool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// mapErr translates driver errors into store errors.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return ErrConflict
		case "23503": // foreign_key_violation
			return ErrInvalidReference
		case "22P02": // invalid_text_representation, e.g. malformed uuid
			return ErrNotFound
		}
	}
	return err
}

// execOne runs a statement that must affect exactly one row.
func (s *Store) execOne(ctx context.Context, sql string, args ...any) error {
	tag, err := s.pool.Exec(ctx, sql, args...)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
