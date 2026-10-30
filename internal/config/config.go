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

	"github.com/aelboum/iam/internal/sizing"
	"github.com/jackc/pgx/v5/pgconn"
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
	// HashWaitTimeout bounds how long a request waits for a password-hashing
	// slot before it is shed as rate-limited, so one tenant cannot grow an
	// unbounded hashing backlog for everyone else (internal security audit N12).
	HashWaitTimeout time.Duration
	// OrgLoginLimit caps password-login (argon2) attempts per organization per
	// minute, aggregated across all of that org's keys, accounts and IPs, so one
	// tenant cannot monopolize the shared hashing capacity (internal security
	// audit N12/A4).
	OrgLoginLimit int
	// HashSlots is the number of concurrent argon2id password hashes allowed
	// across the process. 0 means auto-size from GOMAXPROCS (container-aware).
	// Each slot can hold ~64 MiB resident while hashing (internal security audit
	// N12).
	HashSlots int
	// StrictSizing makes an insufficient-memory sizing check fatal at startup
	// instead of a warning, so a misconfigured deployment fails fast rather than
	// risking OOM under load.
	StrictSizing bool

	// Passkeys: the relying party ID (a domain) and the login UI origins.
	WebAuthnRPID    string
	WebAuthnOrigins []string

	// CORSOrigins are the browser origins allowed to call the API directly.
	// Empty means no CORS headers (the API is normally called server-to-server).
	CORSOrigins []string

	// WeakPasswordFile optionally points at an operator-supplied breached/common
	// password denylist (one password per line) merged into the embedded list at
	// startup. Empty uses only the embedded list.
	WeakPasswordFile string
}

func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:        env("IAM_LISTEN_ADDR", ":8080"),
		Issuer:            strings.TrimRight(os.Getenv("IAM_ISSUER"), "/"),
		DatabaseURL:       os.Getenv("IAM_DATABASE_URL"),
		BootstrapAdminKey: os.Getenv("IAM_BOOTSTRAP_ADMIN_KEY"),
		DevMode:           os.Getenv("IAM_DEV_MODE") == "true",
		WeakPasswordFile:  os.Getenv("IAM_WEAK_PASSWORD_FILE"),
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
		{&cfg.HashWaitTimeout, "IAM_HASH_WAIT_TIMEOUT", 3 * time.Second},
	}
	for _, d := range durations {
		v, err := time.ParseDuration(env(d.name, d.fallback.String()))
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("%s must be a positive duration like 5m or 168h", d.name)
		}
		*d.dst = v
	}
	orgLimit, err := strconv.Atoi(env("IAM_ORG_LOGIN_LIMIT", "1200"))
	if err != nil || orgLimit <= 0 {
		return nil, errors.New("IAM_ORG_LOGIN_LIMIT must be a positive integer (password logins per org per minute)")
	}
	cfg.OrgLoginLimit = orgLimit

	// IAM_HASH_SLOTS: 0 (or unset) means auto-size from GOMAXPROCS at startup.
	// A positive count overrides it, bounded so a typo cannot request a pool whose
	// peak hashing memory is absurd.
	slots, err := strconv.Atoi(env("IAM_HASH_SLOTS", "0"))
	if err != nil || slots < 0 || slots > sizing.MaxHashSlots {
		return nil, fmt.Errorf("IAM_HASH_SLOTS must be an integer between 0 (auto) and %d", sizing.MaxHashSlots)
	}
	cfg.HashSlots = slots
	cfg.StrictSizing = os.Getenv("IAM_STRICT_SIZING") == "true"
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
	if err := ValidateWebAuthn(cfg.WebAuthnRPID, cfg.WebAuthnOrigins, cfg.DevMode); err != nil {
		return nil, err
	}
	// CORS is opt-in: only exact origins, and https outside dev mode, so a
	// wildcard or a typo cannot silently widen who may call the API.
	for _, o := range strings.Split(os.Getenv("IAM_CORS_ORIGINS"), ",") {
		if o = strings.TrimSpace(o); o == "" {
			continue
		}
		norm, ok := NormalizeOrigin(o)
		if !ok {
			return nil, fmt.Errorf("IAM_CORS_ORIGINS entry %q must be an origin like https://app.example.com", o)
		}
		if !strings.HasPrefix(norm, "https://") && !(cfg.DevMode && strings.HasPrefix(norm, "http://")) {
			return nil, fmt.Errorf("IAM_CORS_ORIGINS entry %q must use https unless IAM_DEV_MODE=true", o)
		}
		// Stored normalised (lowercase scheme/host, default port dropped) so the
		// exact-match against the browser-sent Origin cannot silently miss on case
		// or an explicit default port.
		cfg.CORSOrigins = append(cfg.CORSOrigins, norm)
	}
	return cfg, nil
}

// NormalizeOrigin canonicalises an HTTP Origin for exact-match comparison: the
// scheme and host are lowercased and the scheme's default port is dropped, so
// https://App.Example.com and https://app.example.com:443 both compare equal to
// the browser-sent https://app.example.com. ok is false when s is not a bare
// origin (scheme://host[:port], nothing else).
func NormalizeOrigin(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", false
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, true
}

// DatabaseUsesTLS reports whether the connection string will attempt or require
// a TLS connection to Postgres. pgx resolves sslmode (and its libpq default,
// prefer) into a TLS config: sslmode=disable leaves it nil, i.e. a plaintext
// connection, while prefer/require/verify-ca/verify-full all set one. The caller
// uses this only to warn in production; the database URL is never logged.
func DatabaseUsesTLS(databaseURL string) (bool, error) {
	c, err := pgconn.ParseConfig(databaseURL)
	if err != nil {
		return false, err
	}
	return c.TLSConfig != nil, nil
}

// ValidateWebAuthn checks the passkey relying party settings (audit L10):
// every origin must be an origin (scheme://host[:port], nothing else) whose
// host is the RP ID or a subdomain of it, and outside dev mode it must use https.
func ValidateWebAuthn(rpID string, origins []string, devMode bool) error {
	rpID = strings.ToLower(rpID)
	if rpID == "" || strings.ContainsAny(rpID, ":/") {
		return errors.New("IAM_WEBAUTHN_RP_ID must be a bare domain name")
	}
	if len(origins) == 0 {
		return errors.New("IAM_WEBAUTHN_ORIGINS needs at least one origin")
	}
	for _, o := range origins {
		u, err := url.Parse(o)
		// Exactly an origin: browsers send it without a trailing slash and it is compared exactly.
		if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return fmt.Errorf("IAM_WEBAUTHN_ORIGINS entry %q must be an origin like https://login.example.com", o)
		}
		if u.Scheme != "https" && !(devMode && u.Scheme == "http") {
			return fmt.Errorf("IAM_WEBAUTHN_ORIGINS entry %q must use https unless IAM_DEV_MODE=true", o)
		}
		host := strings.ToLower(u.Hostname())
		if host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return fmt.Errorf("IAM_WEBAUTHN_ORIGINS entry %q is not within IAM_WEBAUTHN_RP_ID %q", o, rpID)
		}
	}
	return nil
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
