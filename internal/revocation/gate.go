package revocation

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/aelboum/iam/internal/revepoch"
)

// Gate is the fail-closed signing gate. It starts CLOSED and only opens after a
// successful reconciliation against the independent revocation-epoch authority.
// The signing-key access boundary (keyStore.current) calls Err before using a
// key; a non-nil Err means signing and JWKS publication are refused.
type Gate struct {
	mu  sync.RWMutex
	err error
}

// NewGate returns a gate that is closed with the given reason until opened.
func NewGate(reason string) *Gate { return &Gate{err: errors.New(reason)} }

// Err returns nil when the gate is open, or the reason it is closed.
func (g *Gate) Err() error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.err
}

// Open marks the gate open (signing allowed).
func (g *Gate) Open() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.err = nil
}

// Close marks the gate closed with err (signing refused). err must be non-nil.
func (g *Gate) Close(err error) {
	if err == nil {
		err = errors.New("signing gate closed")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.err = err
}

// Runner reconciles the gate against the authority on startup and on an interval.
type Runner struct {
	store    ReconcileStore
	auth     revepoch.Authority
	gate     *Gate
	interval time.Duration
	log      *slog.Logger
}

// NewRunner wires a reconciliation runner. The gate it returns starts closed.
func NewRunner(st ReconcileStore, auth revepoch.Authority, interval time.Duration, log *slog.Logger) (*Runner, *Gate) {
	if log == nil {
		log = slog.Default()
	}
	g := NewGate("startup: signing-key revocation state not yet reconciled")
	return &Runner{store: st, auth: auth, gate: g, interval: interval, log: log}, g
}

// ReconcileOnce runs one reconciliation and applies the gate policy:
//
//   - success: open the gate.
//   - rollback detected: close the gate (an operator must intervene; the engine
//     must never sign against a rolled-back authority).
//   - authority unavailable or other error: if the gate is already open (we were
//     consistent before this transient error), leave it open so a brief authority
//     outage does not take signing down; if it is still closed (e.g. at startup),
//     keep it closed — fail closed until we can confirm the revocation state.
//
// It returns the reconciliation error, if any, for the caller to log or act on.
func (r *Runner) ReconcileOnce(ctx context.Context) error {
	_, err := Reconcile(ctx, r.store, r.auth)
	switch {
	case err == nil:
		if r.gate.Err() != nil {
			r.log.Info("signing-key revocation state reconciled; signing gate open")
		}
		r.gate.Open()
		return nil
	case errors.Is(err, revepoch.ErrRollback):
		r.log.Error("revocation-epoch authority rolled back; closing signing gate (operator action required)", "error", err)
		r.gate.Close(err)
		return err
	default:
		if r.gate.Err() == nil {
			// Already open and consistent: tolerate a transient authority outage.
			r.log.Warn("revocation reconciliation failed; keeping signing gate open on last-known-good state", "error", err)
		} else {
			r.log.Error("revocation reconciliation failed; signing gate stays closed (fail-closed)", "error", err)
		}
		return err
	}
}

// Run reconciles once synchronously (so startup fails closed until it succeeds or
// the caller proceeds with a closed gate), then keeps reconciling on the interval
// until ctx is cancelled.
func (r *Runner) Run(ctx context.Context) {
	_ = r.ReconcileOnce(ctx)
	if r.interval <= 0 {
		return
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = r.ReconcileOnce(ctx)
		}
	}
}
