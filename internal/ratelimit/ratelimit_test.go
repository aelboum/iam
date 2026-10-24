package ratelimit

import (
	"strconv"
	"testing"

	"golang.org/x/time/rate"
)

func TestBurstThenLimited(t *testing.T) {
	l := New(60, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("event %d within burst was refused", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("event beyond burst was allowed")
	}
	if !l.Allow("other") {
		t.Fatal("keys must be limited independently")
	}
}

// A flood of distinct keys must not block new keys, and must not reset the
// limit of a key that is currently being throttled.
func TestFullTableEvictsWithoutLosingActiveLimits(t *testing.T) {
	l := New(1, 2)
	l.Allow("victim")
	l.Allow("victim") // bucket now empty: victim is throttled
	for i := 0; len(l.entries) < maxKeys; i++ {
		l.entries["flood-"+strconv.Itoa(i)] = &entry{limiter: rate.NewLimiter(l.limit, l.burst)}
	}
	if !l.Allow("newcomer") {
		t.Fatal("a new key was refused because the table was full")
	}
	if l.Allow("victim") {
		t.Fatal("eviction reset the limit of a throttled key")
	}
	if len(l.entries) > maxKeys {
		t.Fatalf("table grew past maxKeys: %d", len(l.entries))
	}
}
