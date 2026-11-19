package revepoch

import (
	"context"
	"sort"
	"sync"
)

// MemAuthority is an in-memory Authority for tests. It is durable only for the
// lifetime of the process, so it is never a production authority; it exists to
// drive reconciliation and gate logic deterministically and to simulate outage
// and rollback. It is safe for concurrent use.
type MemAuthority struct {
	mu          sync.Mutex
	next        Epoch
	byKey       map[string]Epoch
	unavailable bool
}

// NewMemAuthority returns an empty in-memory authority.
func NewMemAuthority() *MemAuthority {
	return &MemAuthority{byKey: map[string]Epoch{}}
}

// SetUnavailable simulates an authority outage: while set, every method returns
// ErrUnavailable so tests can prove callers fail closed.
func (m *MemAuthority) SetUnavailable(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unavailable = v
}

// ForceRollback lowers the authority's current epoch to e, simulating an
// unexpected rollback (for example a restore of the authority's own store to an
// earlier point). It never deletes recorded keys; it only rewinds the counter so
// a subsequent Current() can be seen as lower than a reconciled epoch.
func (m *MemAuthority) ForceRollback(e Epoch) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next = e
}

func (m *MemAuthority) Current(ctx context.Context) (Epoch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unavailable {
		return 0, ErrUnavailable
	}
	return m.next, nil
}

func (m *MemAuthority) Record(ctx context.Context, keyID string) (Epoch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unavailable {
		return 0, ErrUnavailable
	}
	if e, ok := m.byKey[keyID]; ok {
		return e, nil // idempotent: no advance
	}
	m.next++
	m.byKey[keyID] = m.next
	return m.next, nil
}

func (m *MemAuthority) RevokedSince(ctx context.Context, since Epoch) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.unavailable {
		return nil, ErrUnavailable
	}
	out := make([]Record, 0, len(m.byKey))
	for k, e := range m.byKey {
		if e > since {
			out = append(out, Record{KeyID: k, Epoch: e})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Epoch < out[j].Epoch })
	return out, nil
}
