package oidcop

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestSigningGateBlocksAtKeyBoundary proves the CRYPTO-05 D3 fail-closed gate is
// enforced at the actual signing-key access boundary (keyStore.current, which
// backs both SigningKey and KeySet): while the gate returns an error the engine
// refuses to hand out a key for signing or JWKS publication, even when a usable
// key is cached; once the gate opens, the cached key is served. The gate is
// checked before the cache, so a closed gate cannot be bypassed by a warm cache.
func TestSigningGateBlocksAtKeyBoundary(t *testing.T) {
	ks := newKeyStore(nil, nil, 30*24*time.Hour)

	// Seed a usable, in-cache key so the only thing that can stop signing is the
	// gate (priv is never dereferenced on this path).
	now := ks.now()
	ks.keys = []*signingKey{{id: "cached", createdAt: now.Add(-time.Hour), rotateAt: now.Add(29 * 24 * time.Hour)}}
	ks.loadedAt = now

	closed := errors.New("not reconciled")
	gateErr := closed
	ks.gate = func() error { return gateErr }

	ctx := context.Background()
	if _, _, err := ks.current(ctx); err == nil {
		t.Fatal("current() must fail while the signing gate is closed")
	}
	if _, err := ks.SigningKey(ctx); err == nil {
		t.Error("SigningKey must fail while the signing gate is closed")
	}
	if _, err := ks.KeySet(ctx); err == nil {
		t.Error("KeySet must fail while the signing gate is closed")
	}

	// Open the gate: the cached key is served without touching a database.
	gateErr = nil
	if _, _, err := ks.current(ctx); err != nil {
		t.Errorf("current() must succeed once the gate is open: %v", err)
	}
	if _, err := ks.SigningKey(ctx); err != nil {
		t.Errorf("SigningKey must succeed once the gate is open: %v", err)
	}
}
