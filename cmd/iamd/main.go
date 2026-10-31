// Command iamd runs the IAM engine: OIDC provider plus REST management API.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
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
	// `iamd revoke-key <key-id>` is the emergency response to a leaked signing
	// key: it drops the key so every instance stops publishing and trusting it
	// within one key-cache interval (audit CRYPTO-05).
	if len(os.Args) > 1 && os.Args[1] == "revoke-key" {
		if len(os.Args) < 3 || os.Args[2] == "" {
			slog.Error("revoke-key needs a signing-key id: iamd revoke-key <key-id>")
			os.Exit(2)
		}
		if err := revokeSigningKey(os.Args[2]); err != nil {
			slog.Error("revoke-key failed", "error", err)
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

	// Warn once at startup if a production engine talks to Postgres without TLS.
	// This is acceptable only when the engine and database share a trusted
	// private network on a single host (as the bundled compose files do); for a
	// remote or managed database, TLS is required to protect credentials and row
	// data in transit. A parse error here is left to db.Open to report. The
	// database URL is never logged (it carries the password).
	if !cfg.DevMode {
		if usesTLS, terr := config.DatabaseUsesTLS(cfg.DatabaseURL); terr == nil && !usesTLS {
			slog.Warn("database connection is not using TLS (sslmode=disable); acceptable only when the engine and Postgres share a trusted private network on one host. For a remote or managed database set sslmode=verify-full with sslrootcert. See docs/DEPLOYMENT.md.")
		}
	}

	// Extend the breached/common-password denylist from an operator file if one
	// is configured (security follow-up #1). Fail fast: a configured-but-
	// unreadable list is a misconfiguration, not something to silently ignore.
	if cfg.WeakPasswordFile != "" {
		if err := authn.AddWeakPasswordFile(cfg.WeakPasswordFile); err != nil {
			return err
		}
		slog.Info("loaded operator weak-password denylist", "file", cfg.WeakPasswordFile)
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
	router.Use(middleware.Recoverer, securityHeaders, relaxCSPForFormPost, honestDiscovery, noStore, cors(cfg.CORSOrigins), limitOAuthEndpoints(limits))
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

// revokeSigningKey is the emergency response to a leaked signing key (CRYPTO-05).
// It durably revokes the key: the key is marked REVOKED, a permanent tombstone is
// written and a single audit event is recorded, all in one transaction, so the
// revocation survives restart and cannot be resurrected by a reappearing row.
// Within one key-cache interval every running engine stops publishing the key in
// the JWKS and signing with it, provided the database is reachable at its next
// reload; an engine that cannot reach the database stops signing rather than keep
// using a cached key. If this was the active signer, a running engine promotes a
// published successor or generates a new key on its next reload, so signing
// continues. The reason is read from IAM_REVOKE_REASON when set.
//
// Already-issued JWT access tokens remain valid at external resource servers
// until their JWKS cache refreshes and the token exp passes; IAM cannot recall
// them. Revocation is irreversible for this key.
func revokeSigningKey(id string) error {
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
	reason := os.Getenv("IAM_REVOKE_REASON")
	if reason == "" {
		reason = "emergency revocation via iamd revoke-key"
	}
	// Returns only after a durable commit; on an ambiguous failure the operator
	// re-runs this command, which is idempotent.
	if err := st.RevokeSigningKey(ctx, id, "system", reason); err != nil {
		return err
	}
	slog.Warn("signing key revoked (durable): marked REVOKED with a permanent tombstone and audit record. It leaves the JWKS and stops being used within about one minute on every engine that can reach the database; an engine that cannot reach the database stops signing rather than use a cached key. Already-issued JWTs remain valid at external resource servers until their JWKS cache refreshes and the token exp passes. This revocation is irreversible; a successor key is promoted or generated automatically.", "key_id", id)
	return nil
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

// formPostPaths are the OIDC authorization endpoints that can render the
// auto-submitting form_post HTML page (zitadel/oidc AuthResponseFormPost). That
// page carries an inline onload auto-submit and a cross-origin <form action>
// pointing at the relying party's already-validated redirect_uri, both of which
// the strict API CSP (default-src 'none'; form-action 'self') blocks — finding
// M-01. Only responses on these paths are eligible for the scoped relaxation.
var formPostPaths = map[string]bool{
	"/authorize": true, "/authorize/callback": true,
}

// formPostActionRe extracts the single <form action="..."> target from the
// fixed form_post template. The template has exactly one form, so this is
// deterministic; the captured value is the redirect_uri the library already
// validated against the client's registered allow-list before rendering.
var formPostActionRe = regexp.MustCompile(`action="([^"]+)"`)

// formPostMarker is a string unique to the form_post template's auto-submit
// handler; its presence identifies a form_post response and distinguishes it
// from the redirects, JSON errors and other non-HTML responses on the same
// paths, which keep the strict CSP.
var formPostMarker = []byte("document.forms[0].submit()")

// relaxCSPForFormPost narrows the CSP relaxation needed for the OIDC form_post
// auto-submit page (finding M-01) to that page alone. On the authorization
// paths it buffers the response; if the body is the form_post page it replaces
// the strict policy set by securityHeaders with one that
//   - permits the page's fixed inline auto-submit (script-src 'unsafe-inline'),
//   - permits the single cross-origin POST only to the exact origin of the
//     already-validated redirect_uri (form-action <origin>),
//   - keeps default-src 'none', base-uri 'none' and frame-ancestors 'none'.
//
// A nonce/hash would need a fork of the library template (it has no nonce hook)
// or 'unsafe-hashes', which is less interoperable; the page carries no
// user-controlled script, only HTML-escaped data in hidden inputs, so a
// page-scoped 'unsafe-inline' is a bounded, justified relaxation. Every other
// response — JSON, redirects (including query-mode), errors — keeps the strict
// policy. If the redirect origin cannot be parsed the strict policy is kept
// (fail closed), so a malformed response never gets a looser policy.
func relaxCSPForFormPost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !formPostPaths[strings.TrimSuffix(r.URL.Path, "/")] {
			next.ServeHTTP(w, r)
			return
		}
		dw := &deferredWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(dw, r)
		if csp, ok := formPostCSP(dw.buf.Bytes()); ok {
			w.Header().Set("Content-Security-Policy", csp)
		}
		w.WriteHeader(dw.status)
		_, _ = w.Write(dw.buf.Bytes())
	})
}

// deferredWriter buffers the body and status so relaxCSPForFormPost can inspect
// the body (to decide and build the scoped CSP) before the real headers are
// committed. Header writes pass straight through to the wrapped writer, so
// headers the handler sets (Cache-Control, etc.) are preserved.
type deferredWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	buf         bytes.Buffer
}

func (d *deferredWriter) WriteHeader(code int) {
	if !d.wroteHeader {
		d.status = code
		d.wroteHeader = true
	}
}

func (d *deferredWriter) Write(b []byte) (int, error) { return d.buf.Write(b) }

// formPostCSP returns the scoped CSP for a form_post auto-submit page, or
// ok=false when body is not that page or the redirect origin cannot be parsed
// (caller then keeps the strict CSP — fail closed).
func formPostCSP(body []byte) (string, bool) {
	if !bytes.Contains(body, formPostMarker) {
		return "", false
	}
	m := formPostActionRe.FindSubmatch(body)
	if m == nil {
		return "", false
	}
	u, err := url.Parse(string(m[1]))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	origin := u.Scheme + "://" + u.Host
	return "default-src 'none'; script-src 'unsafe-inline'; form-action " + origin +
		"; base-uri 'none'; frame-ancestors 'none'", true
}

// discoveryPath is where the provider serves the OIDC discovery document.
const discoveryPath = "/.well-known/openid-configuration"

// discoveryDropResponseTypes and discoveryDropGrantTypes are the capabilities
// zitadel/oidc hard-codes into every discovery document but this engine does not
// implement: the implicit-flow response types, the implicit grant, and the JWT
// bearer assertion grant (its key lookup is an unimplemented stub). The library
// bakes these into op.ResponseTypes / op.GrantTypes and offers no config switch,
// so a client built from the raw document would pick a flow that fails at
// runtime (audit L-04). honestDiscovery strips them from the served document.
var discoveryDropResponseTypes = map[string]bool{
	"id_token": true, "id_token token": true,
}
var discoveryDropGrantTypes = map[string]bool{
	"implicit": true, "urn:ietf:params:oauth:grant-type:jwt-bearer": true,
}

// honestDiscovery rewrites the discovery document so it advertises only the
// response types and grant types the engine actually accepts (audit L-04). On
// the discovery path it buffers the response, removes the unsupported entries
// from response_types_supported and grant_types_supported, and serves the
// result with every other field passed through untouched. If the body is not a
// 200 JSON object it is served verbatim; the rewrite only ever removes
// capabilities, never adds any, so it can never widen the advertised surface.
func honestDiscovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimSuffix(r.URL.Path, "/") != discoveryPath {
			next.ServeHTTP(w, r)
			return
		}
		dw := &deferredWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(dw, r)
		body := dw.buf.Bytes()
		if dw.status == http.StatusOK {
			if rewritten, ok := rewriteDiscovery(body); ok {
				body = rewritten
				// deferredWriter wrote the body to a buffer, so the length
				// changed; set it explicitly so a stale Content-Length from the
				// library cannot truncate the rewritten document.
				w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			}
		}
		w.WriteHeader(dw.status)
		_, _ = w.Write(body)
	})
}

// rewriteDiscovery removes the unsupported response types and grant types from a
// discovery document. It returns the rewritten JSON with ok=true when it changed
// something, and ok=false (serve the original) when the body is not a JSON
// object or nothing needed removing. Every field other than the two filtered
// arrays is preserved.
func rewriteDiscovery(body []byte) ([]byte, bool) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false
	}
	changed := filterDiscoveryArray(doc, "response_types_supported", discoveryDropResponseTypes)
	changed = filterDiscoveryArray(doc, "grant_types_supported", discoveryDropGrantTypes) || changed
	if !changed {
		return nil, false
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}
	return out, true
}

// filterDiscoveryArray removes drop-listed entries from the named string-array
// field of a discovery document, rewriting it in place, and reports whether it
// removed anything. A field that is absent or not a string array is left alone.
func filterDiscoveryArray(doc map[string]json.RawMessage, field string, drop map[string]bool) bool {
	raw, ok := doc[field]
	if !ok {
		return false
	}
	var vals []string
	if err := json.Unmarshal(raw, &vals); err != nil {
		return false
	}
	kept := make([]string, 0, len(vals))
	for _, v := range vals {
		if !drop[v] {
			kept = append(kept, v)
		}
	}
	if len(kept) == len(vals) {
		return false
	}
	encoded, err := json.Marshal(kept)
	if err != nil {
		return false
	}
	doc[field] = encoded
	return true
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
		// Trim a trailing slash so /oauth/token/ gets no-store like /oauth/token,
		// matching the rate limiter's path normalisation.
		if noStorePaths[strings.TrimSuffix(r.URL.Path, "/")] {
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
			// This CORS layer covers only the management API (/v1...). The mounted
			// OIDC provider serves its own CORS on its public endpoints, so its
			// requests — and any preflight for them — must pass through untouched:
			// answering OPTIONS here for every path would strip the provider's CORS
			// and break browser SPAs on /oauth/token and discovery.
			if !strings.HasPrefix(r.URL.Path, "/v1") {
				next.ServeHTTP(w, r)
				return
			}
			origin := r.Header.Get("Origin")
			if norm, ok := config.NormalizeOrigin(origin); ok && allow[norm] {
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

// limitOAuthEndpoints rate-limits the provider's public endpoints per client IP,
// which slows client-secret and code guessing and bounds the DB-load and
// crypto-work surface. Every unauthenticated provider endpoint is covered: the
// token, introspection and revocation endpoints; userinfo; end_session and the
// device-authorization endpoint; authorize and its callback; the federated-login
// callback; and the cacheable metadata endpoints (JWKS and discovery) on a more
// generous budget (audit I-05).
func limitOAuthEndpoints(limits ratelimit.Factory) func(http.Handler) http.Handler {
	limiter := limits("oauth", 120, 60)
	// /authorize stores a pending request per call, so it is limited too.
	authorizeLimiter := limits("authorize", 60, 30)
	// The federated-login callback is public and unauthenticated; each call
	// hashes the state and probes idp_intents, so limit it per IP like the other
	// public OAuth endpoints rather than leave it as an unthrottled DB-load vector.
	callbackLimiter := limits("idp-callback", 60, 30)
	// Discovery and JWKS are cacheable GET metadata that every relying party
	// fetches legitimately (JWKS on each key rotation), so they get a wider budget
	// than the OAuth endpoints while still bounding an unauthenticated flood.
	metadataLimiter := limits("oauth-metadata", 240, 120)
	limited := map[string]ratelimit.Allower{
		"/oauth/token": limiter, "/oauth/introspect": limiter, "/revoke": limiter,
		"/userinfo":             limiter,
		"/end_session":          limiter,
		"/device_authorization": limiter,
		"/authorize":            authorizeLimiter, "/authorize/callback": authorizeLimiter,
		authn.CallbackPath: callbackLimiter,
		"/keys":            metadataLimiter,
		discoveryPath:      metadataLimiter,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Trim a trailing slash so /oauth/token/ is limited like /oauth/token.
			if l := limited[strings.TrimSuffix(r.URL.Path, "/")]; l != nil {
				if !l.Allow(limiterKey(r.RemoteAddr)) {
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

// limiterKey derives the rate-limit bucket for a request's source address. IPv6
// providers routinely assign a single customer a whole /64, so an attacker can
// rotate through 2^64 addresses to defeat a per-address limit; collapsing IPv6
// to its /64 prefix keeps one client on one bucket. IPv4 keeps its full address,
// and an unparseable address falls back to the raw host string (audit N10).
func limiterKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if ip.To4() != nil {
		return ip.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
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
