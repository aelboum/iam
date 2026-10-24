// Package ratelimit provides an in-memory, per-key token bucket limiter.
//
// Limits are per engine instance. When running several instances behind a
// load balancer, the effective limit is multiplied by the instance count.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Limiter allows `burst` events at once and refills at `perMinute`.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	limit   rate.Limit
	burst   int
}

func New(perMinute float64, burst int) *Limiter {
	l := &Limiter{entries: map[string]*entry{}, limit: rate.Limit(perMinute / 60), burst: burst}
	go l.cleanup()
	return l
}

// maxKeys bounds memory. When a flood of distinct keys fills the table, room
// is made by evicting entries (see evict); new keys are never refused, so a
// flood cannot block legitimate users.
const maxKeys = 100_000

// Allow reports whether an event for key may happen now.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= maxKeys {
			l.evict()
		}
		e = &entry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[key] = e
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

// evict frees space. Entries whose bucket is full carry no state (a new
// limiter would behave the same), so they go first and no limit is lost.
// Only if every entry is actively throttled are arbitrary entries dropped.
func (l *Limiter) evict() {
	now := time.Now()
	for k, e := range l.entries {
		if e.limiter.TokensAt(now) >= float64(l.burst) {
			delete(l.entries, k)
		}
	}
	for k := range l.entries { // map iteration order is random
		if len(l.entries) < maxKeys*9/10 {
			break
		}
		delete(l.entries, k)
	}
}

// cleanup drops idle keys so memory stays bounded.
func (l *Limiter) cleanup() {
	for range time.Tick(5 * time.Minute) {
		l.mu.Lock()
		for k, e := range l.entries {
			if time.Since(e.lastSeen) > 10*time.Minute {
				delete(l.entries, k)
			}
		}
		l.mu.Unlock()
	}
}
