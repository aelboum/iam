// Package revepoch defines the independent revocation-epoch authority that
// protects CRYPTO-05 signing-key revocation against database restore/PITR
// (owner decision D3).
//
// The IAM PostgreSQL database cannot be the sole authority for revocation,
// because restoring PostgreSQL to a point before a revocation also restores its
// historical (pre-revocation) rows and tombstone state. The revocation epoch is
// therefore held by an authority that lives outside IAM PostgreSQL's backup and
// restore lifecycle. On startup and recovery the engine reconciles its local
// revocation state against this authority and refuses to sign until the two
// agree (see internal/revocation and the keyStore signing gate).
//
// Security properties required of every Authority implementation:
//   - Durable, monotonically increasing epoch (never decreases).
//   - Idempotent, atomic recording of a revoked key id.
//   - Authenticated reads and writes.
//   - Independence from IAM PostgreSQL restore/PITR.
//   - A detectable rollback: a Current() lower than a previously reconciled
//     epoch is treated as fail-closed by callers, never silently accepted.
package revepoch

import (
	"context"
	"errors"
)

// Epoch is a durable, monotonically increasing revocation counter. It only ever
// increases; a value lower than one previously observed signals an unexpected
// rollback of the authority and must be treated as fail-closed by callers. It is
// an int64 to match the PostgreSQL bigint identity that backs the reference
// authority; epochs start at 1 and are never negative.
type Epoch int64

// Record is one revoked signing-key id and the epoch at which the authority
// recorded it.
type Record struct {
	KeyID string
	Epoch Epoch
}

var (
	// ErrUnavailable means the authority could not be reached or read. Callers
	// must fail closed (refuse to sign) rather than assume no revocations.
	ErrUnavailable = errors.New("revepoch: authority unavailable")
	// ErrRollback means the authority reported an epoch lower than one already
	// reconciled locally — an unexpected rollback. Callers must fail closed and
	// never lower local state to match.
	ErrRollback = errors.New("revepoch: authority epoch rolled back")
)

// Authority is the independent revocation-epoch authority. Implementations must
// satisfy the security properties documented on the package.
type Authority interface {
	// Current returns the highest epoch the authority has recorded (0 if none).
	// It returns ErrUnavailable on outage; callers must fail closed.
	Current(ctx context.Context) (Epoch, error)

	// Record durably records keyID as revoked and returns the epoch at which it
	// is recorded. It is idempotent: recording an already-recorded key returns
	// that key's existing epoch and does not advance the authority. The returned
	// epoch is always >= every epoch the authority has previously returned.
	Record(ctx context.Context, keyID string) (Epoch, error)

	// RevokedSince returns every revoked key id the authority recorded at an
	// epoch strictly greater than since, ascending by epoch, so a lagging or
	// restored IAM database can re-apply the revocations it is missing.
	RevokedSince(ctx context.Context, since Epoch) ([]Record, error)
}
