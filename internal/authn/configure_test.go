package authn

import "testing"

// ConfigureHashSlots sizes the process-wide hashing pool at startup. It must set
// the requested capacity and floor sub-2 requests at 2 so the pool is never
// degenerate (internal security audit N12).
func TestConfigureHashSlots(t *testing.T) {
	saved := hashSlots
	t.Cleanup(func() { hashSlots = saved })

	for _, c := range []struct{ in, want int }{
		{in: 5, want: 5},
		{in: 16, want: 16},
		{in: 1, want: 2},  // floored
		{in: 0, want: 2},  // floored
		{in: -3, want: 2}, // floored
	} {
		ConfigureHashSlots(c.in)
		if got := cap(hashSlots); got != c.want {
			t.Fatalf("ConfigureHashSlots(%d): cap=%d, want %d", c.in, got, c.want)
		}
	}
}
