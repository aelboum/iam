// Package revocation implements the CRYPTO-05 D3 startup/recovery reconciliation
// between the IAM database and the independent revocation-epoch authority, and
// the fail-closed signing gate the engine consults before using a signing key.
//
// The authority (internal/revepoch) is the source of truth for which signing
// keys have been revoked. On startup and periodically, the engine reconciles its
// local tombstone state against the authority and refuses to sign until the two
// agree. This is what prevents a PostgreSQL restore/PITR to a point before a
// revocation from silently resurrecting a revoked signing key: the authority
// still reports the higher epoch, so the engine re-applies the missing
// revocation and keeps the signing gate closed until it has.
package revocation

import (
	"context"
	"fmt"

	"github.com/aelboum/iam/internal/revepoch"
)

// ReconcileStore is the subset of *store.Store the reconciler needs.
type ReconcileStore interface {
	ReconciledEpoch(ctx context.Context) (int64, error)
	SetReconciledEpoch(ctx context.Context, epoch int64) error
	EnsureSigningKeyRevoked(ctx context.Context, id, actor, reason string) error
}

// reconcileActor labels audit events written by reconciliation.
const reconcileActor = "system:reconcile"

// Reconcile brings the local database up to the authority's current revocation
// epoch and returns the epoch reconciled through. It:
//
//   - reads the authority's current epoch (fails closed on outage);
//   - refuses to proceed if the local reconciled epoch is AHEAD of the authority
//     (an unexpected rollback: returns revepoch.ErrRollback and never lowers
//     local state to match);
//   - otherwise re-applies every revocation the authority recorded after the
//     local epoch (idempotent tombstones) and advances the local marker.
//
// On success the returned epoch equals the authority's current epoch, so a
// caller may open the signing gate. Any error means reconciliation is incomplete
// and the gate must stay closed.
func Reconcile(ctx context.Context, st ReconcileStore, auth revepoch.Authority) (int64, error) {
	cur, err := auth.Current(ctx)
	if err != nil {
		return 0, fmt.Errorf("read authority epoch: %w", err)
	}
	local, err := st.ReconciledEpoch(ctx)
	if err != nil {
		return 0, fmt.Errorf("read local reconciled epoch: %w", err)
	}
	switch {
	case revepoch.Epoch(local) > cur:
		// The authority is behind the local marker. Never lower the authority or
		// reactivate keys; this is a fail-closed condition requiring an operator.
		return 0, fmt.Errorf("%w: local reconciled epoch %d exceeds authority epoch %d", revepoch.ErrRollback, local, cur)
	case revepoch.Epoch(local) == cur:
		return int64(cur), nil // already reconciled
	}

	recs, err := auth.RevokedSince(ctx, revepoch.Epoch(local))
	if err != nil {
		return 0, fmt.Errorf("list revoked since %d: %w", local, err)
	}
	for _, r := range recs {
		if err := st.EnsureSigningKeyRevoked(ctx, r.KeyID, reconcileActor,
			fmt.Sprintf("D3 reconciliation at epoch %d", r.Epoch)); err != nil {
			return 0, fmt.Errorf("re-apply revocation of %s: %w", r.KeyID, err)
		}
	}
	if err := st.SetReconciledEpoch(ctx, int64(cur)); err != nil {
		return 0, fmt.Errorf("advance reconciled epoch: %w", err)
	}
	return int64(cur), nil
}
