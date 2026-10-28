package db

import (
	"context"
	"testing"
	"time"
)

// TestOpenFailsFastWhenPostgresUnavailable proves the startup database handshake
// fails closed: when Postgres is unreachable, Open and OpenLimited return an
// error promptly (so run() exits non-zero with a clear message) rather than
// hanging or panicking. This guards the fail-fast startup contract documented in
// OPERATIONS.md. It needs no database — it points at a closed loopback port.
func TestOpenFailsFastWhenPostgresUnavailable(t *testing.T) {
	// Nothing listens on port 1; connect_timeout bounds the attempt even if a
	// host were to black-hole the connection instead of refusing it.
	const deadURL = "postgres://iam:iam@127.0.0.1:1/iam?sslmode=disable&connect_timeout=2"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("Open", func(t *testing.T) {
		start := time.Now()
		pool, err := Open(ctx, deadURL)
		if err == nil {
			pool.Close()
			t.Fatalf("Open returned nil error against an unreachable database")
		}
		if d := time.Since(start); d > 9*time.Second {
			t.Fatalf("Open blocked %v against an unreachable database; want a prompt failure", d)
		}
	})

	t.Run("OpenLimited", func(t *testing.T) {
		start := time.Now()
		pool, err := OpenLimited(ctx, deadURL, 4)
		if err == nil {
			pool.Close()
			t.Fatalf("OpenLimited returned nil error against an unreachable database")
		}
		if d := time.Since(start); d > 9*time.Second {
			t.Fatalf("OpenLimited blocked %v against an unreachable database; want a prompt failure", d)
		}
	})
}
