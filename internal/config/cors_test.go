package config

import (
	"strings"
	"testing"
)

// baseEnv sets the minimum a Load() call needs, so a test can vary one variable.
func baseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("IAM_ISSUER", "https://auth.example.com")
	t.Setenv("IAM_DATABASE_URL", "postgres://x")
	t.Setenv("IAM_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("IAM_DEV_MODE", "false")
	t.Setenv("IAM_WEBAUTHN_RP_ID", "example.com")
	t.Setenv("IAM_WEBAUTHN_ORIGINS", "https://app.example.com")
}

// CORS is opt-in and exact: unset means no CORS headers, and a non-origin or a
// plain-http origin outside dev mode is refused at boot rather than silently
// widening who may call the API (independent security assessment, 2026-10-29).
func TestCORSOrigins(t *testing.T) {
	baseEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.CORSOrigins) != 0 {
		t.Fatalf("CORS enabled by default: %v", cfg.CORSOrigins)
	}

	t.Setenv("IAM_CORS_ORIGINS", "https://app.example.com, https://admin.example.com")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("load with origins: %v", err)
	}
	if got := strings.Join(cfg.CORSOrigins, ","); got != "https://app.example.com,https://admin.example.com" {
		t.Fatalf("origins = %q", got)
	}

	for _, bad := range []string{
		"https://app.example.com/path", // not an origin
		"app.example.com",              // no scheme
		"http://app.example.com",       // plain http outside dev mode
		"https://app.example.com?x=1",  // query
	} {
		t.Setenv("IAM_CORS_ORIGINS", bad)
		if _, err := Load(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}

	// Plain http is fine in dev mode.
	t.Setenv("IAM_DEV_MODE", "true")
	t.Setenv("IAM_ISSUER", "http://localhost:8080")
	t.Setenv("IAM_WEBAUTHN_RP_ID", "localhost")
	t.Setenv("IAM_WEBAUTHN_ORIGINS", "http://localhost:3000")
	t.Setenv("IAM_CORS_ORIGINS", "http://localhost:3000")
	if _, err := Load(); err != nil {
		t.Fatalf("dev-mode http origin refused: %v", err)
	}
}
