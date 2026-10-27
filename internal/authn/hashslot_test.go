package authn

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// drainHashSlots empties the shared semaphore so each test starts clean.
func drainHashSlots() {
	for {
		select {
		case <-hashSlots:
		default:
			return
		}
	}
}

// Internal security audit N12: a full hashing pool must shed after the timeout,
// a freed slot must be usable by a waiter, and nothing may leak a slot.

func TestAcquireHashSlotShedsWhenFull(t *testing.T) {
	drainHashSlots()
	defer drainHashSlots()
	for i := 0; i < cap(hashSlots); i++ {
		hashSlots <- struct{}{}
	}
	s := &Service{cfg: Config{HashWaitTimeout: 50 * time.Millisecond}}
	start := time.Now()
	release, err := s.acquireHashSlot()
	if !errors.Is(err, ErrRateLimited) || release != nil {
		t.Fatalf("full pool: got release!=nil=%v err=%v, want nil release + ErrRateLimited", release != nil, err)
	}
	if d := time.Since(start); d < 40*time.Millisecond || d > 2*time.Second {
		t.Fatalf("shed after %v; want ~the timeout, not an indefinite wait", d)
	}
}

func TestAcquireHashSlotReleaseAllowsWaiter(t *testing.T) {
	drainHashSlots()
	defer drainHashSlots()
	for i := 0; i < cap(hashSlots); i++ {
		hashSlots <- struct{}{}
	}
	go func() { time.Sleep(30 * time.Millisecond); <-hashSlots }() // free one slot
	s := &Service{cfg: Config{HashWaitTimeout: 2 * time.Second}}
	release, err := s.acquireHashSlot()
	if err != nil || release == nil {
		t.Fatalf("a freed slot must be acquirable: release==nil=%v err=%v", release == nil, err)
	}
	release()
}

func TestAcquireHashSlotNoLeakUnderConcurrency(t *testing.T) {
	drainHashSlots()
	defer drainHashSlots()
	s := &Service{cfg: Config{HashWaitTimeout: 5 * time.Second}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if release, err := s.acquireHashSlot(); err == nil && release != nil {
				release()
			}
		}()
	}
	wg.Wait()
	if held := len(hashSlots); held != 0 {
		t.Fatalf("slot leak: %d slot(s) still held after every acquire released", held)
	}
}
