// Package config loads engine settings from environment variables.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// HTTP listen address, e.g. ":8080".
	ListenAddr string
	// Public issuer URL of the OIDC provider, e.g. "https://auth.example.com".
	Issuer string
	// Postgres connection URL.
	DatabaseURL string
	// 32-byte key used to encrypt secrets at rest (signing keys, TOTP secrets)
	// and to derive the OIDC provider's token encryption key.
	MasterKey [32]byte
	// Older master keys accepted for decryption only (IAM_MASTER_KEY_PREVIOUS).
	PreviousMasterKeys [][32]byte
	// Optional instance admin API key created at startup if it does not exist.
	BootstrapAdminKey string
	// Allows http issuer and relaxed client checks. Never enable in production.
	DevMode bool

	// Trust X-Forwarded-For / X-Real-IP for the client IP. Only enable behind
	// a reverse proxy that overwrites these headers, or clients can spoof them.
	TrustProxy bool
	// Count rate limits in Postgres so they hold across all engine instances.
	SharedRateLimits bool
	// Number of reverse proxies in front of the engine that append to
	// X-Forwarded-For. The client IP is the entry this many hops from the right.
	ProxyHops int
	// Serve Swagger UI at /docs.
	EnableDocs bool

	AccessTokenLifetime time.Duration // short, because JWTs cannot be recalled
	RefreshIdle         time.Duration // refresh token expires if unused this long
	SessionMaxAge       time.Duration // absolute login lifetime, refresh cannot extend it
	LoginLifetime       time.Duration // how long a session API login stays open
	KeyRotationInterval time.Duration
	MaxFailedLogins     int
	LockoutDuration     time.Duration
	AuditRetention      time.Duration

	// Passkeys: the relying party ID (a domain) and the login UI origins.
	WebAuthnRPID    string
	WebAuthnOrigins []string
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:        env("IAM_LISTEN_ADDR", ":8080"),
		Issuer:            strings.TrimRight(os.Getenv("IAM_ISSUER"), "/"),
		DatabaseURL:       os.Getenv("IAM_DATABASE_URL"),
		BootstrapAdminKey: os.Getenv("IAM_BOOTSTRAP_ADMIN_KEY"),
		DevMode:           os.Getenv("IAM_DEV_MODE") == "true",
		TrustProxy:        os.Getenv("IAM_TRUST_PROXY") == "true",
		SharedRateLimits:  os.Getenv("IAM_SHARED_RATE_LIMITS") == "true",
		MaxFailedLogins:   5,
	}
	cfg.EnableDocs = os.Getenv("IAM_ENABLE_DOCS") == "true" // opt-in only
	hops, err := strconv.Atoi(env("IAM_TRUSTED_PROXY_HOPS", "1"))
	if err != nil || hops < 1 || hops > 10 {
		return nil, errors.New("IAM_TRUSTED_PROXY_HOPS must be between 1 and 10")
	}
	cfg.ProxyHops = hops

	// Passkeys are bound to a domain. By default the engine's own host and
	// origin; set these to your login UI's domain and origin(s).
	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil || issuerURL.Hostname() == "" {
		return nil, errors.New("IAM_ISSUER must be an absolute URL")
	}
	cfg.WebAuthnRPID = env("IAM_WEBAUTHN_RP_ID", issuerURL.Hostname())
	for _, o := range strings.Split(env("IAM_WEBAUTHN_ORIGINS", issuerURL.Scheme+"://"+issuerURL.Host), ",") {
		if o = strings.TrimSpace(o); o != "" {
			cfg.WebAuthnOrigins = append(cfg.WebAuthnOrigins, o)
		}
	}
	durations := []struct {
		dst      *time.Duration
		name     string
		fallback time.Duration
	}{
		{&cfg.AccessTokenLifetime, "IAM_ACCESS_TOKEN_TTL", 5 * time.Minute},
		{&cfg.RefreshIdle, "IAM_REFRESH_IDLE_TTL", 7 * 24 * time.Hour},
		{&cfg.SessionMaxAge, "IAM_SESSION_MAX_AGE", 30 * 24 * time.Hour},
		{&cfg.LoginLifetime, "IAM_LOGIN_TTL", 15 * time.Minute},
		{&cfg.KeyRotationInterval, "IAM_KEY_ROTATION", 30 * 24 * time.Hour},
		{&cfg.LockoutDuration, "IAM_LOCKOUT_DURATION", 15 * time.Minute},
		{&cfg.AuditRetention, "IAM_AUDIT_RETENTION", 365 * 24 * time.Hour},
	}
	for _, d := range durations {
		v, err := time.ParseDuration(env(d.name, d.fallback.String()))
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("%s must be a positive duration like 5m or 168h", d.name)
		}
		*d.dst = v
	}
	if cfg.Issuer == "" {
		return nil, errors.New("IAM_ISSUER is required")
	}
	if cfg.DatabaseURL == "" {
		return nil, errors.New("IAM_DATABASE_URL is required")
	}

	key, err := base64.StdEncoding.DecodeString(os.Getenv("IAM_MASTER_KEY"))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("IAM_MASTER_KEY must be 32 bytes, base64 encoded (generate with: openssl rand -base64 32)")
	}
	copy(cfg.MasterKey[:], key)

	// Previous master keys, comma-separated, still accepted for decryption
	// during a rotation. Remove them after running `iamd rotate-keys`.
	for _, v := range strings.Split(os.Getenv("IAM_MASTER_KEY_PREVIOUS"), ",") {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		old, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(old) != 32 {
			return nil, errors.New("IAM_MASTER_KEY_PREVIOUS entries must be 32 bytes, base64 encoded")
		}
		var k [32]byte
		copy(k[:], old)
		cfg.PreviousMasterKeys = append(cfg.PreviousMasterKeys, k)
	}

	if cfg.BootstrapAdminKey != "" && len(cfg.BootstrapAdminKey) < 32 {
		return nil, errors.New("IAM_BOOTSTRAP_ADMIN_KEY must be at least 32 characters")
	}
	if !cfg.DevMode && strings.HasPrefix(cfg.Issuer, "http://") {
		return nil, errors.New("IAM_ISSUER must use https unless IAM_DEV_MODE=true")
	}
	return cfg, nil
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
