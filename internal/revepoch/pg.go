package revepoch

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PGAuthority is the reference Authority backed by a PostgreSQL database that is
// OPERATIONALLY SEPARATE from the IAM database: a different server/cluster with
// its own backup and restore lifecycle and its own credentials, reached by its
// own connection string (IAM_REVOCATION_AUTHORITY_URL). It must never point at
// the IAM database — that would defeat the restore/PITR protection, since the
// two would then be restored together.
//
// Durability and monotonicity come from an append-only log keyed by signing-key
// id with a bigserial epoch: a key id is recorded at most once (idempotent), the
// epoch never decreases, and the authority's backups are independent of IAM's.
// Operators are responsible for deploying it on independent, backed-up
// infrastructure; see the D3 runbook.
type PGAuthority struct {
	pool *pgxpool.Pool
}

// NewPGAuthority wraps an already-open pool for the separate authority database.
func NewPGAuthority(pool *pgxpool.Pool) *PGAuthority { return &PGAuthority{pool: pool} }

// Migrate creates the authority's schema. It is additive and idempotent, so it
// is safe to run on every start.
func (a *PGAuthority) Migrate(ctx context.Context) error {
	_, err := a.pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS revocation_epoch_log (
			epoch        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
			key_id       text        NOT NULL UNIQUE,
			recorded_at  timestamptz NOT NULL DEFAULT now(),
			recorded_by  text        NOT NULL DEFAULT ''
		)`)
	if err != nil {
		return fmt.Errorf("revepoch migrate: %w", err)
	}
	return nil
}

func (a *PGAuthority) Current(ctx context.Context) (Epoch, error) {
	var e int64
	if err := a.pool.QueryRow(ctx, `SELECT COALESCE(max(epoch), 0) FROM revocation_epoch_log`).Scan(&e); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return Epoch(e), nil
}

func (a *PGAuthority) Record(ctx context.Context, keyID string) (Epoch, error) {
	// Idempotent append: a second record of the same key id conflicts and does
	// not advance the epoch. The unique constraint makes this atomic.
	var e int64
	err := a.pool.QueryRow(ctx, `
		INSERT INTO revocation_epoch_log (key_id)
		VALUES ($1)
		ON CONFLICT (key_id) DO NOTHING
		RETURNING epoch`, keyID).Scan(&e)
	switch {
	case err == nil:
		return Epoch(e), nil
	case errors.Is(err, pgx.ErrNoRows):
		// Already recorded: return the existing epoch, no advance.
		if err := a.pool.QueryRow(ctx, `SELECT epoch FROM revocation_epoch_log WHERE key_id=$1`, keyID).Scan(&e); err != nil {
			return 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return Epoch(e), nil
	default:
		return 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
}

func (a *PGAuthority) RevokedSince(ctx context.Context, since Epoch) ([]Record, error) {
	rows, err := a.pool.Query(ctx, `
		SELECT key_id, epoch FROM revocation_epoch_log
		WHERE epoch > $1 ORDER BY epoch ASC`, int64(since))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		var e int64
		if err := rows.Scan(&r.KeyID, &e); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		r.Epoch = Epoch(e)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return out, nil
}
