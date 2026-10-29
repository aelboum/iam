# Independent security assessment — 2026-10-29

| | |
|---|---|
| **Target** | `github.com/aelboum/iam` (headless OIDC identity engine, Go/chi/pgx) |
| **Commit assessed** | `69015ac` (`origin/main`, merge of PR #12) |
| **Assessment branch** | `security/assessment-2026-10-29` |
| **Method** | Full-source review of every tracked file (114 files, ~17.4k lines), automated SAST/SCA/secret scanning, and dynamic testing of a live instance backed by a disposable Postgres |
| **Date** | 2026-10-29 |
| **Assessor** | External-style independent review (Hermes Agent), not the author of the code |
| **Verdict** | **No Critical or High finding. 3 Medium, 14 Low, 7 Informational.** All Medium and Low findings were remediated in this branch with regression tests; the Informational ones are dispositioned below. |

> This is an independent assessment in the sense that it was performed against
> the code as shipped, without the author's context, and every claim below is
> backed by a command or a test in this repository. It is still **not** a
> substitute for a commissioned third-party penetration test (readiness
> criterion 12, currently waived — see SECURITY.md).

## 1. Scope and approach

In scope: the whole repository at the commit above — `cmd/`, `internal/`
(api, authn, config, db + migrations, docs, oidcop, ratelimit, secret, sizing,
store), deploy manifests, compose files, CI, scripts, and documentation.

Out of scope: the Go standard library and third-party modules beyond
reachability analysis; live Google/Microsoft/Entra round trips (already covered
by the project's own staging evidence); the operator's host, DNS and TLS.

Phases actually executed:

1. **Reconnaissance** — full file inventory, `git log`, dependency graph,
   trust-boundary map from `docs/SECURITY.md`.
2. **Automated scanning** — `gitleaks detect` over the full history,
   `gosec` (all rules), `govulncheck` (reachability), `staticcheck`, `go vet`,
   `gofmt`.
3. **Manual review** — every Go file, every SQL migration, every manifest,
   every script, read in full; each route traced from router to SQL.
4. **Dynamic testing** — engine booted in dev mode against a disposable
   Postgres; 8 probe suites covering authn, authz/tenant isolation, the full
   OIDC code flow, federation, password reset, lockout, rate limits, malformed
   input and header hygiene.
5. **Performance/availability testing** — synthetic 200k-token / 100k-session
   dataset, `EXPLAIN (ANALYZE, BUFFERS)` on the hot statements.
6. **Remediation and re-test** — fixes applied, unit/integration tests added,
   full suite re-run, every fix re-verified against the live instance.

## 2. Executive summary

The engine is in unusually good security shape for its size. The core
properties an identity provider must have held up under direct attack:

- **Tenant isolation** is enforced at every route, not just the obvious ones.
  An org-scoped admin key was refused on another org's org, users, audit and
  keys (403), and got the same 404 as a missing object for foreign user ids.
  A login-scoped key was refused on the entire management API.
- **The OIDC flow** is correct: PKCE is mandatory for public clients, codes are
  single-use and client-bound, a wrong `code_verifier` does not burn the code,
  refresh tokens rotate with family-wide reuse detection, and revocation is
  client-scoped and idempotent.
- **Federation** is the strongest area: browser binding, single-use intents
  burned even on binding mismatch, identity keyed on `(idp_id, sub)` and never
  email, issuer pinning for presets, and an SSRF guard that checks the resolved
  address on every hop.
- **Account recovery and lockout** resist enumeration: unknown users get the
  same status, body shape and hashing time as wrong passwords, and the
  per-factor lockout cannot be bypassed through the reset path.
- **No secret ever reached git**: `gitleaks` over 82 commits and 951 KB found
  nothing, and the three suppressions in `.gitleaksignore` are genuine test
  fixtures.

What it did **not** get right was mostly in the operational layer: the periodic
purge sequentially scanned six of the hottest tables because their `expires_at`
columns were unindexed, token responses were cacheable, and a few input and
header details were loose. None of those is exploitable for data disclosure on
its own; together they are the difference between "correct" and "operable".

Twelve reachable standard-library vulnerabilities were also live at the
assessed commit, all fixed in Go 1.27.2/1.27.3 while the module pinned 1.26.10.

## 3. Findings

Severity uses a CVSS v3.1 base estimate. "Fixed" means the change is in this
branch with a regression test; "Dispositioned" means accepted with a rationale.

### Medium

| ID | Finding | CVSS | Status |
|----|---------|------|--------|
| M-01 | Periodic purge sequentially scans six hot tables | 5.3 | Fixed |
| M-02 | `sessions.user_id::text` cast defeats the index on every credential change | 4.3 | Fixed |
| M-03 | Token, introspection and userinfo responses are cacheable | 4.3 | Fixed |

**M-01 — Unindexed expiry purges (availability).**
`store.PurgeExpired` runs every ten minutes and deletes `WHERE expires_at <
now()` from nine tables. Only three had an `expires_at` index; `access_tokens`,
`refresh_tokens`, `sessions`, `auth_requests`, `signing_keys` and
`email_verifications` were each fully scanned. `PurgeAudit` had the same problem
on `audit_events.at`, whose only index is `(org_id, at DESC)`.

Measured on the disposable database:

```
200k access_tokens:  Seq Scan, 133 ms, 203,279 shared buffers
100k sessions:       Seq Scan,  72 ms, 101,820 shared buffers
```

The cost is linear in table size and runs on the tables that grow fastest, so a
busy instance pays seconds of I/O every ten minutes on the same disks that serve
logins. A single failing table also aborted the whole loop, so one error left
the other eight unpurged.

*Remediation:* migration `0008` adds the missing indexes (and drops the
superseded `users_org_id_username_key` constraint); `PurgeExpired` now collects
the first error and continues with the remaining tables. Re-measured with the
realistic steady state (0.1 % of rows expired): **Index Scan, 31 ms** instead of
133 ms, and the cost no longer tracks table size.

**M-02 — Text cast on a uuid column (availability).**
`revokeUserCredentialsTx` deleted sessions and reset tokens with
`WHERE user_id::text = $1`. The cast makes the uuid index unusable, so every
password change, lock, logout, TOTP change and user deletion scanned `sessions`
and `password_resets` in full. Confirmed by `EXPLAIN`: `Seq Scan` before,
`Index Scan using sessions_user_idx` after.

*Remediation:* compare as uuid (`user_id = $1::uuid`) and index
`sessions(user_id)` / `password_resets(user_id, expires_at)`.

**M-03 — Cacheable token responses (specification + token lifetime).**
RFC 6749 §5.1 requires `Cache-Control: no-store` on any response containing
tokens; RFC 6750 §5.3 asks for it on protected-resource responses. None of
`/oauth/token`, `/oauth/introspect`, `/revoke`, `/userinfo` or
`/authorize/callback` sent it, so a shared cache or an aggressive browser cache
could serve a token response after the token was revoked.

*Remediation:* a `noStore` middleware sets `Cache-Control: no-store` and
`Pragma: no-cache` on exactly those paths.

### Low

| ID | Finding | Status |
|----|---------|--------|
| L-01 | No CSP / `Permissions-Policy` / CORP on API responses | Fixed |
| L-02 | TOTP enrollment codes verifiable without any attempt cap | Fixed |
| L-03 | Oversized body reported as 400 "unexpected EOF" instead of 413 | Fixed |
| L-04 | Trailing data after the JSON body silently ignored | Fixed |
| L-05 | `/userinfo` unthrottled; `/oauth/token/` (trailing slash) unthrottled | Fixed |
| L-06 | `userinfo` answers 403 with an empty body after revocation, not 401 | Dispositioned |
| L-07 | API accepts dotless emails (`a@b`) that federation rejects | Fixed |
| L-08 | `uint64 → int` narrowing in `sizing.Check` (gosec G115) | Fixed |
| L-09 | Bootstrap marker written before the key row: a failed insert suppresses bootstrap forever | Fixed |
| L-10 | Deleting an IdP left its users' sessions alive | Fixed |
| L-11 | Quota check is check-then-insert, so a burst can exceed the cap | Dispositioned |
| L-12 | No CORS at all: `OPTIONS` returned 405, so no browser SPA could call the API | Fixed |
| L-13 | `last_used_at` written on every authenticated request | Fixed |
| L-14 | `/healthz` unauthenticated and unthrottled, and pings the database | Dispositioned |

**L-01** — only `/docs` had a CSP. API responses now carry
`default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action
'self'`, `Cross-Origin-Resource-Policy`, `Cross-Origin-Opener-Policy` and a
`Permissions-Policy`; the docs handler still overrides the CSP with the policy
its CDN assets need.

**L-02** — `VerifyTOTPEnrollment` had no counter, so a six-digit pending code
was guessable without bound (measured: 30 wrong codes, 30 × 401). Anyone holding
a management key could activate TOTP on a user whose secret nobody holds and
lock that user out of the second factor. Now capped at five attempts per
enrollment (migration `0008` adds `users.totp_enroll_attempts`, reset by
`SetPendingTOTP`), returning 429 afterwards.

**L-03/L-04** — `decode` now refuses a declared oversize body with 413 and
requires exactly one JSON value; `{"a":1}GARBAGE` and `{...}{...}` are 400.

**L-05** — `/userinfo` joined the OAuth limiter and the limiter lookup trims a
trailing slash.

**L-07** — `validEmail` now delegates to `authn.ValidEmail`, so the API and the
federation path agree that a domain needs a dot.

**L-09** — the marker row was inserted first, so a transient failure between the
two statements left the marker behind and the bootstrap key was never created
again. The key is now inserted first, in the same transaction.

**L-10** — `DeleteIDP` now ends the sessions of users linked to that IdP in the
same transaction.

**L-12** — `IAM_CORS_ORIGINS` (opt-in, exact origins, https outside dev mode)
plus a preflight handler that answers 204 instead of chi's 405.

**L-13** — `AuthenticateAPIKey` refreshed `last_used_at` with an `UPDATE ... 
RETURNING` on every request. It now selects and refreshes at most once a
minute, best-effort.

### Informational

| ID | Finding | Disposition |
|----|---------|-------------|
| I-01 | 12 reachable stdlib vulnerabilities at the assessed commit (GO-2026-6599/6600/6603/6605/6607/6608/6610/6611/6612/6613/6617/6809), all fixed in Go 1.27.2/1.27.3 | Fixed: `toolchain go1.27.3` in `go.mod`, Dockerfile pinned to `golang:1.27.3-alpine`; `govulncheck` now reports 0 |
| I-02 | gosec G101 on three SQL column-list constants | Fixed: `#nosec G101` with justification |
| I-03 | gosec G704 on the healthcheck's `client.Get` | Fixed: `#nosec G704`; the target is operator-set `IAM_LISTEN_ADDR` |
| I-04 | gosec G710 on `http.Redirect` in `IDPCallback` | Fixed: `#nosec G710`; the target is a `return_url` validated at intent creation, and the live probe confirmed no open redirect |
| I-05 | `staticcheck` SA4000 in `secret_test.go` (identical expressions) | Fixed |
| I-06 | OIDC provider endpoints reflect any `Origin` (library CORS) | Accepted: they are public and credential-free; `/v1` is exact-match |
| I-07 | Dockerfile base images not digest-pinned | Partly fixed (exact patch tag); digest pinning needs a registry pull at build time |

## 4. Verified as strong (evidence)

| Property | How it was verified |
|---|---|
| Tenant isolation on every route | Org key vs foreign org: 403 on org, users, audit, keys; 404 for foreign user ids; login key refused on the whole management API |
| No user enumeration | Unknown login name returns the same 201 shape as a known one; unknown user on reset returns the same 202 `{}` as the cooldown; dummy hash equalises timing |
| Lockout | 5 wrong passwords → 401 for the correct one too; unlock restores login |
| Rate limits | Per-IP login 20 burst → 429 with `Retry-After: 60`; invalid-key flood throttled at 30 with a valid key still working |
| PKCE | Public client without `code_challenge` refused; wrong verifier → `invalid_grant` and the code survives |
| Code binding | Code from client A refused with client B's credentials |
| Refresh rotation | Reuse of a rotated token revokes the family; revoke is client-scoped (401 for a foreign client) and idempotent |
| Federation | Full self-IdP round trip; replay of the callback → 400; second redeem → 401; weak binding → 400; `javascript:` return URL → 400 |
| SSRF guard | `PublicAddress` denylist incl. metadata ranges; https-only transport outside dev mode; body caps |
| Secrets | `gitleaks` full history: 0 leaks; client secrets and TOTP secrets sealed with AES-GCM; API keys stored as SHA-256 |
| Crypto | argon2id with bcrypt upgrade path, constant-time compares, single-use TOTP steps, passkey counter CAS |
| Migrations | Per-file transactions under a cluster-wide advisory lock |

## 5. Residual risk after remediation

| Risk | Severity | Note |
|---|---|---|
| No independent external penetration test | High (process) | Unchanged; the owner's waiver stands |
| Shared argon2 pool can still be saturated (N12) | Medium | Bounded and shed as 503, but no per-tenant reservation |
| Login-scoped key can recover accounts for its users (D3) | Medium | By design; key custody is the control |
| `userinfo` 403 instead of 401 after revocation (L-06) | Low | Inside the library; clients must treat 403 as "token no longer usable" |
| Quota race (L-11) | Low | Exceeding by a handful under a burst is harmless |
| `/healthz` unthrottled (L-14) | Low | Cheap, but a flood consumes pool connections |
| IPv6 limits key on the full address, not /64 (N10) | Low | Unchanged |
| No metrics/alerting backend | Low | Runbook-level, unchanged |

## 6. Re-test results

After remediation, on the same live instance:

```
trailing garbage            -> 400  invalid JSON body: trailing data after the JSON value
oversize body               -> 413  request body is too large
dotless email               -> 400  a valid email is required
TOTP enrollment, 8 guesses  -> 401 x5 then 429 x3
token response              -> Cache-Control: no-store, Pragma: no-cache
userinfo response           -> Cache-Control: no-store
OPTIONS /v1/orgs            -> 204 + Access-Control-Allow-Origin (listed origin only)
API response headers        -> CSP, CORP, COOP, Permissions-Policy, nosniff
purge of expired tokens     -> Index Scan using access_tokens_expires_idx (31 ms vs 133 ms)
revoke by user              -> Index Scan using sessions_user_idx
```

Automated gates: `gosec -severity medium` **0 issues** (5 justified
suppressions), `staticcheck` **clean**, `govulncheck` **0 vulnerabilities**,
`gitleaks` **0 leaks**, `gofmt`/`go vet` clean, `go test ./...` **all packages
pass** against a disposable Postgres.

## 7. Applied changes

| Area | File |
|---|---|
| Indexes, enrollment counter, redundant constraint | `internal/db/migrations/0008_perf_and_enroll_cap.sql` |
| Purge resilience | `internal/store/oidc.go` |
| uuid comparisons | `internal/store/email.go` |
| Enrollment cap | `internal/store/users.go`, `internal/authn/authn.go` |
| Bootstrap ordering | `internal/store/apikeys.go` |
| IdP deletion | `internal/store/idp.go` |
| `last_used_at` throttle | `internal/store/apikeys.go` |
| Headers, no-store, CORS, limiter coverage, JSON 429 | `cmd/iamd/main.go` |
| Body limits, trailing data, email rule | `internal/api/api.go`, `internal/api/users.go` |
| CORS config + validation | `internal/config/config.go` |
| G115 clamp | `internal/sizing/sizing.go` |
| Toolchain pin | `go.mod`, `Dockerfile` |
| CI gates | `.github/workflows/ci.yml` |
| Suppressions with rationale | `internal/store/oidc.go`, `internal/store/apikeys.go`, `internal/api/sessions.go`, `cmd/iamd/main.go` |
| Tests | `cmd/iamd/headers_test.go`, `internal/api/decode_test.go`, `internal/store/assessment_test.go`, `internal/config/cors_test.go`, `internal/sizing/sizing_test.go`, `internal/secret/secret_test.go` |

## 8. Recommendations not applied here

1. **Commission the external penetration test.** The waiver is a business
   decision, but this assessment and the four internal ones share a blind spot:
   they all read the same source.
2. **Per-tenant hashing reservation** rather than one global pool, to close N12.
3. **Digest-pin the base images** and add a `docker scout`/`trivy` image scan to
   CI; the Dockerfile is now patch-pinned but not digest-pinned.
4. **Metrics and alerting** on `shed_total`, `org_limit` denials, purge duration
   and 5xx rate; today they are log lines only.
5. **Batch the purge** (delete in bounded chunks) once tables exceed a few
   million rows; the indexes make it cheap, not free.
6. **Normalise `userinfo` to 401** by wrapping the provider handler, or document
   the 403 contract for integrators.
7. **Rate-limit `/healthz`** or serve it from a cached readiness flag.
