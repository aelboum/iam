// Command iamd runs the IAM engine: OIDC provider plus REST management API.
package main

import (
	"context"
	"errors"
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
	"github.com/aelboum/iam/internal/store"
)

func main() {
	// `iamd healthcheck` lets a container runtime probe the server; the
	// distroless image has no shell or curl.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
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
	box := secret.NewBox(secret.Derive(cfg.MasterKey, "at-rest-encryption"))

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
	an := authn.NewService(st, box, authn.Config{
		IssuerName:      issuerURL.Host,
		SessionLifetime: cfg.LoginLifetime,
		MaxFailedLogins: cfg.MaxFailedLogins,
		LockoutDuration: cfg.LockoutDuration,
		CodeKey:         secret.Derive(cfg.MasterKey, "email-code-hmac"),
	})
	storage := oidcop.NewStorage(st, an, box, oidcop.TokenConfig{
		KeyRotation:   cfg.KeyRotationInterval,
		AccessToken:   cfg.AccessTokenLifetime,
		RefreshIdle:   cfg.RefreshIdle,
		SessionMaxAge: cfg.SessionMaxAge,
	})
	provider, err := oidcop.NewProvider(cfg.Issuer, cfg.MasterKey, cfg.DevMode, storage)
	if err != nil {
		return err
	}
	apiServer := api.NewServer(st, an, provider, cfg.Issuer, cfg.DevMode)

	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	if cfg.TrustProxy {
		router.Use(forwardedFor(cfg.ProxyHops))
	}
	router.Use(middleware.Recoverer, securityHeaders, limitOAuthEndpoints())
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

// securityHeaders sets defensive headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// limitOAuthEndpoints rate-limits the token, introspection and revocation
// endpoints per client IP, which slows client secret and code guessing.
func limitOAuthEndpoints() func(http.Handler) http.Handler {
	limiter := ratelimit.New(120, 60)
	// /authorize stores a pending request per call, so it is limited too.
	authorizeLimiter := ratelimit.New(60, 30)
	limited := map[string]*ratelimit.Limiter{
		"/oauth/token": limiter, "/oauth/introspect": limiter, "/revoke": limiter,
		"/authorize": authorizeLimiter, "/authorize/callback": authorizeLimiter,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if l := limited[r.URL.Path]; l != nil {
				host, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					host = r.RemoteAddr
				}
				if !l.Allow(host) {
					w.Header().Set("Retry-After", "60")
					http.Error(w, `{"error":"slow_down"}`, http.StatusTooManyRequests)
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
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
