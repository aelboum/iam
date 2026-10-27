package authn

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zitadel/passwap"
	"github.com/zitadel/passwap/argon2"
	"github.com/zitadel/passwap/bcrypt"
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
	if !errors.Is(err, ErrOverloaded) || release != nil {
		t.Fatalf("full pool: got release!=nil=%v err=%v, want nil release + ErrOverloaded", release != nil, err)
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

func newVerifyTestService(timeout time.Duration) *Service {
	return &Service{
		passwords: passwap.NewSwapper(
			argon2.NewArgon2id(argon2.RecommendedIDParams, nil),
			bcrypt.NewVerifier(nil),
		),
		cfg: Config{HashWaitTimeout: timeout},
	}
}

// R1/R4: VerifySecret must distinguish a genuine mismatch (false, nil) from an
// overload shed (false, ErrOverloaded), and never report overload as invalid.
func TestVerifySecretContract(t *testing.T) {
	drainHashSlots()
	defer drainHashSlots()
	s := newVerifyTestService(2 * time.Second)
	h, err := s.hash("the-real-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if ok, err := s.VerifySecret(h, "the-real-secret"); !ok || err != nil {
		t.Fatalf("correct secret: ok=%v err=%v, want true,nil", ok, err)
	}
	if ok, err := s.VerifySecret(h, "the-wrong-secret"); ok || err != nil {
		t.Fatalf("wrong secret: ok=%v err=%v, want false,nil (genuine mismatch)", ok, err)
	}
	// Overload: a full pool makes verify shed; it must surface as ErrOverloaded,
	// not as a (false, nil) invalid-secret result.
	for i := 0; i < cap(hashSlots); i++ {
		hashSlots <- struct{}{}
	}
	ok, err := newVerifyTestService(50*time.Millisecond).VerifySecret(h, "the-real-secret")
	for i := 0; i < cap(hashSlots); i++ {
		<-hashSlots
	}
	if ok || !errors.Is(err, ErrOverloaded) {
		t.Fatalf("overload: ok=%v err=%v, want false + ErrOverloaded (not a mismatch)", ok, err)
	}
}

type countingHandler struct{ warns *atomic.Int64 }

func (h countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h countingHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		h.warns.Add(1)
	}
	return nil
}
func (h countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingHandler) WithGroup(string) slog.Handler      { return h }

// R3: repeated shedding must not flood the logs; the WARN is throttled to about
// once per second while every shed is still counted.
func TestHashShedLogThrottled(t *testing.T) {
	drainHashSlots()
	defer drainHashSlots()
	var warns atomic.Int64
	prev := slog.Default()
	slog.SetDefault(slog.New(countingHandler{&warns}))
	defer slog.SetDefault(prev)
	hashShedLogAt.Store(0)
	before := hashShedTotal.Load()

	for i := 0; i < cap(hashSlots); i++ {
		hashSlots <- struct{}{}
	}
	s := &Service{cfg: Config{HashWaitTimeout: 10 * time.Millisecond}}
	for i := 0; i < 20; i++ {
		if _, err := s.acquireHashSlot(); !errors.Is(err, ErrOverloaded) {
			t.Fatalf("acquire %d: err=%v, want ErrOverloaded", i, err)
		}
	}
	for i := 0; i < cap(hashSlots); i++ {
		<-hashSlots
	}
	if n := warns.Load(); n < 1 || n > 3 {
		t.Fatalf("shed warnings = %d; want throttled (1-3), not ~20", n)
	}
	if got := hashShedTotal.Load() - before; got < 20 {
		t.Fatalf("shed total counted = %d; want >= 20 (every shed counted)", got)
	}
}
