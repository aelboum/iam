package sizing

import (
	"runtime"
	"testing"
)

func TestAutoHashSlotsFloorAndTracksGOMAXPROCS(t *testing.T) {
	got := AutoHashSlots()
	if got < 2 {
		t.Fatalf("AutoHashSlots()=%d, must be floored at 2", got)
	}
	if want := max(2, runtime.GOMAXPROCS(0)); got != want {
		t.Fatalf("AutoHashSlots()=%d, want max(2, GOMAXPROCS)=%d", got, want)
	}
}

func TestParseMemMax(t *testing.T) {
	cases := []struct {
		in       string
		want     uint64
		wantKnow bool
	}{
		{"max\n", 0, false},              // cgroup v2 unlimited sentinel
		{"", 0, false},                   // empty
		{"  \n", 0, false},               // whitespace only
		{"0", 0, false},                  // zero is not a real limit
		{"notanumber", 0, false},         // unparseable
		{"536870912\n", 536870912, true}, // 512 MiB
		{"  1073741824 ", 1073741824, true},
	}
	for _, c := range cases {
		got, know := parseMemMax(c.in)
		if got != c.want || know != c.wantKnow {
			t.Errorf("parseMemMax(%q)=(%d,%v), want (%d,%v)", c.in, got, know, c.want, c.wantKnow)
		}
	}
}

func TestParseMemLimitV1(t *testing.T) {
	cases := []struct {
		in       string
		want     uint64
		wantKnow bool
	}{
		{"9223372036854771712\n", 0, false}, // v1 "no limit" sentinel -> unlimited
		{"0", 0, false},
		{"garbage", 0, false},
		{"268435456\n", 268435456, true}, // 256 MiB
	}
	for _, c := range cases {
		got, know := parseMemLimitV1(c.in)
		if got != c.want || know != c.wantKnow {
			t.Errorf("parseMemLimitV1(%q)=(%d,%v), want (%d,%v)", c.in, got, know, c.want, c.wantKnow)
		}
	}
}

func TestCheckUnknownLimitAlwaysOK(t *testing.T) {
	// An unknown limit must never block startup, even with a huge slot count.
	if warn, ok := Check(10000, 0, false); !ok || warn != "" {
		t.Fatalf("unknown limit: got ok=%v warn=%q, want ok=true, empty warn", ok, warn)
	}
}

func TestCheckSufficientLimit(t *testing.T) {
	// 4 slots need ~256 MiB hashing + 128 MiB base = 384 MiB; a 1 GiB limit is fine.
	if warn, ok := Check(4, 1024*1024*1024, true); !ok || warn != "" {
		t.Fatalf("sufficient limit: got ok=%v warn=%q, want ok=true, empty warn", ok, warn)
	}
}

func TestCheckInsufficientLimitWarns(t *testing.T) {
	// 8 slots need ~512 MiB hashing + 128 MiB base = 640 MiB; a 256 MiB limit is not enough.
	warn, ok := Check(8, 256*1024*1024, true)
	if ok {
		t.Fatalf("insufficient limit: got ok=true, want ok=false")
	}
	if warn == "" {
		t.Fatalf("insufficient limit: want a non-empty warning")
	}
}

func TestCheckBoundaryExactFit(t *testing.T) {
	// Exactly at the limit must be allowed: 2 slots (128 MiB) + 128 MiB base = 256 MiB.
	if warn, ok := Check(2, 256*1024*1024, true); !ok || warn != "" {
		t.Fatalf("exact fit: got ok=%v warn=%q, want ok=true, empty warn", ok, warn)
	}
}

func TestRequiredMiB(t *testing.T) {
	if got := RequiredMiB(3); got != 3*ArgonHashMiB {
		t.Fatalf("RequiredMiB(3)=%d, want %d", got, 3*ArgonHashMiB)
	}
}

// A limit above MaxInt MiB must clamp instead of wrapping to a negative int,
// which would make every sizing check fail (gosec G115).
func TestCheckClampsHugeLimit(t *testing.T) {
	if warn, ok := Check(2, ^uint64(0), true); !ok || warn != "" {
		t.Fatalf("huge limit: got ok=%v warn=%q, want ok=true", ok, warn)
	}
}

// On this (non-Linux) host the cgroup files are absent, so MemoryLimit must
// report the limit as unknown rather than inventing one.
func TestMemoryLimitUnknownWhenNoCgroup(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("cgroup files may exist on Linux; this asserts the no-cgroup path")
	}
	if _, known := MemoryLimit(); known {
		t.Fatalf("MemoryLimit() reported a known limit on %s, want unknown", runtime.GOOS)
	}
}
