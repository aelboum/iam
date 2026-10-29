// Package sizing decides how many concurrent password hashes the engine allows
// and checks that choice against the memory the process is actually allowed to
// use. Each argon2id hash holds tens of megabytes resident, so an unbounded or
// badly sized pool is a memory-exhaustion risk (internal security audit N12).
package sizing

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// ArgonHashMiB is the peak resident memory of one in-flight argon2id hash at the
// engine's parameters. It tracks zitadel/passwap argon2.RecommendedIDParams,
// whose Memory is 64*1024 KiB = 64 MiB. Keep this in step with that parameter.
const ArgonHashMiB = 64

// BaseReserveMiB is memory the engine needs for everything other than in-flight
// hashing — the Go runtime, the pgx connection pool, request buffers and caches.
// The safety check reserves it before accounting for hashing slots. It is a
// deliberately modest floor, not a measured working-set; operators with tight
// limits should set IAM_HASH_SLOTS explicitly.
const BaseReserveMiB = 128

// MaxHashSlots caps IAM_HASH_SLOTS so a typo cannot request a pool whose peak
// hashing memory (slots * 64 MiB) is absurd. 1024 slots is already ~64 GiB of
// hashing headroom; the memory check guards realistic limits below that.
const MaxHashSlots = 1024

// AutoHashSlots is the default concurrent-hash slot count when the operator sets
// no override: GOMAXPROCS, floored at 2.
//
// GOMAXPROCS, unlike runtime.NumCPU, honours a cgroup CPU quota on Go 1.25+, so
// this already scales down inside a CPU-limited container instead of sizing to
// the host's physical cores. CPU-quota awareness is automatic in the runtime;
// memory-limit awareness is not (see MemoryLimit), which is why the two are
// handled separately.
func AutoHashSlots() int {
	return max(2, runtime.GOMAXPROCS(0))
}

// RequiredMiB estimates the peak resident memory of slots concurrent argon2id
// hashes.
func RequiredMiB(slots int) int { return slots * ArgonHashMiB }

// Linux cgroup files reporting the memory high-water limit. v2 is a single
// unified hierarchy; v1 is the legacy per-controller layout.
const (
	cgroupV2MemMax   = "/sys/fs/cgroup/memory.max"
	cgroupV1MemLimit = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
)

// cgroupV1Unlimited: cgroup v1 reports "no limit" as a page-aligned sentinel
// near math.MaxInt64. Any value this large is treated as unlimited rather than
// as a genuine exabyte-scale limit.
const cgroupV1Unlimited uint64 = 1 << 62

// MemoryLimit reports the process's memory high-water limit in bytes and whether
// a finite limit was found. It reads the cgroup v2 file first, then the v1 file.
// A missing file (non-Linux hosts, or no cgroup memory controller), an
// unlimited sentinel, or an unparseable value all yield known=false — the caller
// must treat an unknown limit as "cannot check", never as "no limit".
func MemoryLimit() (bytes uint64, known bool) {
	if b, err := os.ReadFile(cgroupV2MemMax); err == nil {
		// The v2 file is authoritative when present: "max" means unlimited.
		return parseMemMax(string(b))
	}
	if b, err := os.ReadFile(cgroupV1MemLimit); err == nil {
		return parseMemLimitV1(string(b))
	}
	return 0, false
}

// parseMemMax parses a cgroup v2 memory.max value: a decimal byte count, or the
// literal "max" for unlimited.
func parseMemMax(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "max" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}

// parseMemLimitV1 parses a cgroup v1 memory.limit_in_bytes value, treating the
// huge "no limit" sentinel as unlimited.
func parseMemLimitV1(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 || v >= cgroupV1Unlimited {
		return 0, false
	}
	return v, true
}

// Check decides whether running slots concurrent hashes is safe given a memory
// limit. When known is false it can make no judgement and returns ok=true with
// no warning. When a finite limit is known and the estimated hashing peak plus
// the base reserve would exceed it, it returns ok=false and a warning naming the
// numbers and the remedy.
func Check(slots int, limitBytes uint64, known bool) (warning string, ok bool) {
	if !known {
		return "", true
	}
	// Clamp before narrowing: a cgroup limit above MaxInt MiB (never real, but
	// possible from a bogus file) would otherwise wrap to a negative int and
	// make every sizing check fail.
	mib := limitBytes / (1024 * 1024)
	if mib > math.MaxInt {
		mib = math.MaxInt
	}
	limitMiB := int(mib)
	needMiB := RequiredMiB(slots) + BaseReserveMiB
	if needMiB <= limitMiB {
		return "", true
	}
	return fmt.Sprintf(
		"hash-slot sizing may exceed the memory limit: %d slots need ~%d MiB hashing + %d MiB base = ~%d MiB, "+
			"but the container memory limit is ~%d MiB; lower IAM_HASH_SLOTS or raise the memory limit",
		slots, RequiredMiB(slots), BaseReserveMiB, needMiB, limitMiB,
	), false
}
