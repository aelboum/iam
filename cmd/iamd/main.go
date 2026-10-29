// Command iamd runs the IAM engine: OIDC provider plus REST management API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/aelboum/iam/internal/api"
	"github.com/aelboum/iam/internal/authn"
	"github.com/aelboum/iam/internal/config"
	"github.com/aelboum/iam/internal/db"
	"github.com/aelboum/iam/internal/docs"
	"github.com/aelboum/iam/internal/oidcop"
	"github.com/aelboum/iam/internal/ratelimit"
	"github.com/aelboum/iam/internal/secret"
	"github.com/aelboum/iam/internal/sizing"
	"github.com/aelboum/iam/internal/store"
)

func main() {
	// `iamd healthcheck` lets a container runtime probe the server; the
	// distroless image has no shell or curl.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if len(os.Args) > 1 && os.Args[1] == "rotate-keys" {
		check := len(os.Args) > 2 && os.Args[2] == "--check"
		if err := rotateKeys(check); err != nil {
			slog.Error("rotate-keys failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "purge" {
		if err := purgeOnce(); err != nil {
			slog.Error("purge failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Size the process-wide password-hashing pool and check it against the
	// container's memory limit before serving. Each slot can hold ~64 MiB
	// resident while hashing, so an oversized pool risks OOM (internal security
	// audit N12). An unknown memory limit (non-Linux, or no cgroup) yields no
	// judgement; a known, insufficient limit warns, or fails fast under
	// IAM_STRICT_SIZING.
	slots := cfg.HashSlots
	if slots == 0 {
		slots = sizing.AutoHashSlots()
	}
	limitBytes, known := sizing.MemoryLimit()
	if warn, ok := sizing.Check(slots, limitBytes, known); !ok {
		if cfg.StrictSizing {
			return errors.New(warn)
		}
		slog.Warn(warn)
	}
	authn.ConfigureHashSlots(slots)
	slog.Info("password-hashing pool sized", "slots", slots, "auto", cfg.HashSlots == 0, "mem_limit_known", known)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}

	st := store.New(pool)
	box := atRestBox(cfg)

	if cfg.BootstrapAdminKey != "" {
		created, err := st.BootstrapAPIKey(ctx, "bootstrap admin", secret.Hash(cfg.BootstrapAdminKey))
		if err != nil {
			return err
		}
		if created {
			slog.Info("bootstrap admin key created; it is not recreated if you delete it later")
		}
	}

	issuerURL, err := url.Parse(cfg.Issuer)
	if err != nil {
		return err
	}
	// Shared limits count across all instances; in-memory limits per instance.
	limits := ratelimit.Factory(ratelimit.Memory)
	if cfg.SharedRateLimits {
		// A small dedicated pool, so a saturated main pool cannot stall limits (audit M10).
		limiterPool, err := db.OpenLimited(ctx, cfg.DatabaseURL, 4)
		if err != nil {
			return err
		}
		defer limiterPool.Close()
		st.SetLimiterPool(limiterPool)
		limits = func(name string, perMinute float64, burst int) ratelimit.Allower {
			return st.NewPGLimiter(name, perMinute, burst)
		}
	}
	webAuthn, err := authn.NewWebAuthn(cfg.WebAuthnRPID, issuerURL.Host, cfg.WebAuthnOrigins)
	if err != nil {
		return err
	}
	slog.Info("passkeys", "rp_id", cfg.WebAuthnRPID, "origins", cfg.WebAuthnOrigins)
	var previousCodeKeys [][32]byte
	for _, k := range cfg.PreviousMasterKeys {
		previousCodeKeys = append(previousCodeKeys, secret.Derive(k, "email-code-hmac"))
	}
	an := authn.NewService(st, box, authn.Config{
		Limits:           limits,
		Issuer:           cfg.Issuer,
		DevMode:          cfg.DevMode,
		WebAuthn:         webAuthn,
		IssuerName:       issuerURL.Host,
		SessionLifetime:  cfg.LoginLifetime,
		MaxFailedLogins:  cfg.MaxFailedLogins,
		LockoutDuration:  cfg.LockoutDuration,
		HashWaitTimeout:  cfg.HashWaitTimeout,
		OrgLoginLimit:    cfg.OrgLoginLimit,
		CodeKey:          secret.Derive(cfg.MasterKey, "email-code-hmac"),
		PreviousCodeKeys: previousCodeKeys,
	})
	storage := oidcop.NewStorage(st, an, box, oidcop.TokenConfig{
		KeyRotation:   cfg.KeyRotationInterval,
		AccessToken:   cfg.AccessTokenLifetime,
		RefreshIdle:   cfg.RefreshIdle,
		SessionMaxAge: cfg.SessionMaxAge,
	})
	provider, err := oidcop.NewProvider(cfg.Issuer, cfg.MasterKey, cfg.PreviousMasterKeys, cfg.DevMode, storage)
	if err != nil {
		return err
	}
	apiServer := api.NewServer(st, box, an, provider, cfg.Issuer, cfg.DevMode, limits)

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	if cfg.TrustProxy {
		router.Use(forwardedFor(cfg.ProxyHops))
	}
	router.Use(middleware.Recoverer, securityHeaders, noStore, cors(cfg.CORSOrigins), limitOAuthEndpoints(limits))
	router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := st.Ping(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("ok"))
	})
	router.Get(oidcop.LoggedOutPath, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("signed out"))
	})
	router.Mount("/v1", apiServer.Routes())
	router.Get(authn.CallbackPath, apiServer.IDPCallback)
	if cfg.EnableDocs {
		docs.Register(router)
	}
	// The OpenID Provider serves discovery, authorize, token, userinfo,
	// introspect, revoke, end_session and keys from the issuer root.
	router.Mount("/", provider)

	go purgeLoop(ctx, st, cfg.AuditRetention)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", cfg.ListenAddr, "issuer", cfg.Issuer)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// forwardedFor sets the client IP from X-Forwarded-For behind `hops` trusted
// proxies. Each proxy appends the address it received the request from, so
// only the rightmost `hops` entries are trustworthy; anything to their left
// was written by the client and is ignored. X-Real-IP is never trusted.
func forwardedFor(hops int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var chain []string
			for _, h := range r.Header.Values("X-Forwarded-For") {
				for _, part := range strings.Split(h, ",") {
					if p := strings.TrimSpace(part); p != "" {
						chain = append(chain, p)
					}
				}
			}
			if len(chain) >= hops {
				if ip := net.ParseIP(chain[len(chain)-hops]); ip != nil {
					r.RemoteAddr = net.JoinHostPort(ip.String(), "0")
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func healthcheck() int {
	addr := os.Getenv("IAM_LISTEN_ADDR")
	if addr == "" || strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
		if addr == "127.0.0.1" {
			addr += ":8080"
		}
	}
	client := &http.Client{Timeout: 3 * time.Second}
	// #nosec G704 -- the target is the operator-set IAM_LISTEN_ADDR, not user input.
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

// atRestBox encrypts with the current master key and still decrypts data
// sealed with any IAM_MASTER_KEY_PREVIOUS key.
func atRestBox(cfg *config.Config) *secret.Box {
	var previous [][32]byte
	for _, k := range cfg.PreviousMasterKeys {
		previous = append(previous, secret.Derive(k, "at-rest-encryption"))
	}
	return secret.NewBox(secret.Derive(cfg.MasterKey, "at-rest-encryption"), previous...)
}

// keyFingerprint identifies a master key in logs without revealing it.
func keyFingerprint(k [32]byte) string {
	return secret.Hash(string(k[:]))[:12]
}

// rotateKeys re-encrypts all stored secrets with the current master key.
// Run it after deploying a new IAM_MASTER_KEY with the old one in
// IAM_MASTER_KEY_PREVIOUS. It works in small batches and can be re-run
// after an interruption.
//
// With --check it is strictly read-only (no insert, update or delete): it
// opens every encrypted value with the current key only and fails if any
// value still needs a previous key (audit M9). Only remove
// IAM_MASTER_KEY_PREVIOUS after --check succeeds.
func rotateKeys(check bool) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	st := store.New(pool)
	slog.Info("master key", "fingerprint", keyFingerprint(cfg.MasterKey), "previous_keys", len(cfg.PreviousMasterKeys))
	if check {
		currentOnly := secret.NewBox(secret.Derive(cfg.MasterKey, "at-rest-encryption"))
		var total, unreadable int
		// Read-only: --check must never insert, update or delete a row.
		err := st.ScanEncryptedReadOnly(ctx, func(v store.EncryptedValue) error {
			total++
			if _, err := currentOnly.Open(v.Sealed); err != nil {
				unreadable++
				slog.Error("value not readable with the current master key", "table", v.Table, "id", v.ID)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if unreadable > 0 {
			return fmt.Errorf("%d of %d encrypted values need a previous key: run `iamd rotate-keys` and keep IAM_MASTER_KEY_PREVIOUS", unreadable, total)
		}
		slog.Info("all encrypted values are readable with the current master key; IAM_MASTER_KEY_PREVIOUS can be removed after the token lifetimes noted in DEPLOYMENT.md", "values", total)
		return nil
	}
	box := atRestBox(cfg)
	n, err := st.Reencrypt(ctx, func(sealed []byte) ([]byte, bool, error) {
		plain, current, err := box.OpenCurrent(sealed)
		if err != nil || current {
			return nil, false, err
		}
		return box.Seal(plain), true, nil
	})
	if err != nil {
		return err
	}
	slog.Info("re-encrypted secrets with the current master key; now run `iamd rotate-keys --check`", "values", n)
	return nil
}

// purgeOnce deletes expired rows once (the server does this every 10 minutes).
func purgeOnce() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	st := store.New(pool)
	if err := st.PurgeExpired(ctx); err != nil {
		return err
	}
	slog.Info("purged expired rows", "tables", store.PurgedTables)
	return st.PurgeRateLimits(ctx)
}

// securityHeaders sets defensive headers on every response. The CSP is
// restrictive for JSON/API responses (nothing is loaded); the /docs handler
// overrides it with the policy its CDN-hosted assets need.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()")
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// noStorePaths are responses that carry tokens or token-derived identity.
// RFC 6749 §5.1 requires Cache-Control: no-store on any response containing
// tokens or credentials; RFC 6750 §5.3 asks for it on protected-resource
// responses too, so a shared cache cannot replay a revoked token's answer.
var noStorePaths = map[string]bool{
	"/oauth/token": true, "/oauth/introspect": true, "/revoke": true,
	"/userinfo": true, "/authorize/callback": true,
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if noStorePaths[r.URL.Path] {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

// cors answers preflight requests and, when origins are configured, allows
// exactly those origins. The API is normally called server-to-server, so the
// default (no IAM_CORS_ORIGINS) adds no CORS headers at all.
func cors(allowed []string) func(http.Handler) http.Handler {
	allow := map[string]bool{}
	for _, o := range allowed {
		allow[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allow[origin] {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Add("Vary", "Origin")
				if r.Method == http.MethodOptions {
					h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
					h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Session-Token, X-End-User-IP")
					h.Set("Access-Control-Max-Age", "600")
				}
			}
			if r.Method == http.MethodOptions {
				w.Header().Set("Allow", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// limitOAuthEndpoints rate-limits the token, introspection and revocation
// endpoints per client IP, which slows client secret and code guessing.
func limitOAuthEndpoints(limits ratelimit.Factory) func(http.Handler) http.Handler {
	limiter := limits("oauth", 120, 60)
	// /authorize stores a pending request per call, so it is limited too.
	authorizeLimiter := limits("authorize", 60, 30)
	// The federated-login callback is public and unauthenticated; each call
	// hashes the state and probes idp_intents, so limit it per IP like the other
	// public OAuth endpoints rather than leave it as an unthrottled DB-load vector.
	callbackLimiter := limits("idp-callback", 60, 30)
	limited := map[string]ratelimit.Allower{
		"/oauth/token": limiter, "/oauth/introspect": limiter, "/revoke": limiter,
		"/userinfo":  limiter,
		"/authorize": authorizeLimiter, "/authorize/callback": authorizeLimiter,
		authn.CallbackPath: callbackLimiter,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Trim a trailing slash so /oauth/token/ is limited like /oauth/token.
			if l := limited[strings.TrimSuffix(r.URL.Path, "/")]; l != nil {
				host, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					host = r.RemoteAddr
				}
				if !l.Allow(host) {
					w.Header().Set("Retry-After", "60")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"error":"too many requests, try again later"}` + "\n"))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// purgeLoop periodically deletes expired auth requests, tokens, sessions and keys.
func purgeLoop(ctx context.Context, st *store.Store, auditRetention time.Duration) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		if err := st.PurgeExpired(ctx); err != nil && ctx.Err() == nil {
			slog.Error("purge expired", "error", err)
		}
		if err := st.PurgeAudit(ctx, auditRetention); err != nil && ctx.Err() == nil {
			slog.Error("purge audit", "error", err)
		}
		if err := st.PurgeRateLimits(ctx); err != nil && ctx.Err() == nil {
			slog.Error("purge rate limits", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
