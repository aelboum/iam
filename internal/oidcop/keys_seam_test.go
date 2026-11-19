package oidcop

import (
	"testing"
	"time"
)

// These tests exercise the CRYPTO-05 Phase 1 clock/TTL seam deterministically:
// needsNewKey and signer take an explicit now and publish-lead, so key selection
// and rotation timing are driven by an injected clock with no sleeps and no
// database. They pin the production selection semantics the seam must preserve.

func TestNeedsNewKeyUsesInjectedClockAndLead(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lead := 3 * time.Minute

	if !needsNewKey(nil, base, lead) {
		t.Error("empty key set must require a new key")
	}

	// Newest key rotates at base+30m; a successor must be published once now is
	// within one publish-lead of that rotation (base+27m), not before.
	keys := []*signingKey{{id: "k1", rotateAt: base.Add(30 * time.Minute)}}

	if needsNewKey(keys, base.Add(26*time.Minute), lead) {
		t.Error("no new key needed more than one lead before rotation")
	}
	if !needsNewKey(keys, base.Add(28*time.Minute), lead) {
		t.Error("new key needed once within one lead of rotation")
	}
	// Exactly at the threshold (rotateAt-lead) is not yet "after", so still false.
	if needsNewKey(keys, base.Add(27*time.Minute), lead) {
		t.Error("threshold instant is not yet past the lead boundary")
	}
}

func TestSignerPrefersNewestSufficientlyPublishedKey(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lead := 3 * time.Minute
	now := base.Add(10 * time.Minute)

	// Newest first: k2 was created 1m ago (not yet published a full lead), k1
	// 10m ago (well published). signer must skip k2 and pick k1.
	k2 := &signingKey{id: "k2", createdAt: now.Add(-1 * time.Minute)}
	k1 := &signingKey{id: "k1", createdAt: now.Add(-10 * time.Minute)}
	if got := signer([]*signingKey{k2, k1}, now, lead); got.id != "k1" {
		t.Fatalf("signer picked %q, want k1 (newest published at least one lead)", got.id)
	}

	// With only one key, even if it is newer than the lead, it is used (bootstrap).
	only := &signingKey{id: "only", createdAt: now.Add(-1 * time.Minute)}
	if got := signer([]*signingKey{only}, now, lead); got.id != "only" {
		t.Fatalf("signer picked %q, want only (single-key bootstrap)", got.id)
	}

	// Once k2 has itself been published a full lead, it becomes the signer.
	later := k2.createdAt.Add(lead + time.Second)
	if got := signer([]*signingKey{k2, k1}, later, lead); got.id != "k2" {
		t.Fatalf("signer picked %q, want k2 after it crossed the publish lead", got.id)
	}
}

func TestNewKeyStoreDefaultsPreserveProductionTiming(t *testing.T) {
	ks := newKeyStore(nil, nil, 30*24*time.Hour)
	if ks.cacheTTL != keyCacheTTL {
		t.Errorf("cacheTTL default = %v, want %v", ks.cacheTTL, keyCacheTTL)
	}
	if ks.pubLead != publishLead {
		t.Errorf("pubLead default = %v, want %v", ks.pubLead, publishLead)
	}
	if ks.now == nil {
		t.Error("now must default to a real clock, not nil")
	}
}
