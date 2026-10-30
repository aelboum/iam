# Internal security audit — IAM engine

| | |
|---|---|
| **Target** | `https://github.com/aelboum/iam` (local checkout `C:\Users\imran\Documents\IAM`) |
| **Audited commit** | `2f78ab65c93c24ff2518345cac370074c862c8a4` (`fix(security): remediate independent assessment findings`) |
| **Branch** | `security/assessment-2026-10-29` (behind `origin/security/assessment-2026-10-29` by 1; `origin/main` is 4 commits ahead) |
| **Audit date** | 2026-10-29 |
| **Type** | Internal, source-first audit with local dynamic validation. **Not** an independent penetration test. |
| **Verdict** | **No Critical, no High.** 2 Medium, 6 Low, 8 Informational. Production readiness remains **NO-GO**; independent-pentest criterion 12 remains **NOT PERFORMED**. |
| **Repository changes** | One new file: this report. No tracked file modified, nothing committed, pushed or deployed. |

---

## 1. Executive summary

The engine is in unusually good security shape for its size (14.3k lines of Go, 77 files). The
core identity invariants hold under manual adversarial review and under live probing: tenant
isolation is enforced at every object-level boundary tested, authentication failure paths are
uniform and enumeration-resistant, lockout is reserved-before-verify so parallel guessing is
capped, refresh-token rotation detects reuse and revokes the family, PKCE is mandatory for public
clients, federation binds the flow to the browser, and the outbound IdP client is SSRF-guarded at
the dialer. `govulncheck` reports zero reachable vulnerabilities, `gitleaks` is clean over full
history, `staticcheck` is clean, `gosec` at low severity reports only unhandled-`Write` noise, and
`go test -race ./...` passes on every package.

Two Medium findings are worth acting on before any release:

1. **The global CSP added by the previous audit's own remediation breaks `response_mode=form_post`.**
   `default-src 'none'` with no `script-src` blocks the inline `onload` auto-submit, and
   `form-action 'self'` blocks the cross-origin form target. Any relying party that uses
   `form_post` — the recommended mode for keeping the code out of URLs and `Referer` — receives a
   blank page and no code. Confirmed live.
2. **No compose file sets a container memory limit**, so the `sizing` guard that the N12
   hashing-pool mitigation depends on never engages. `memory.max` reads `max`, `MemoryLimit()`
   returns `known=false`, and `Check()` waves the configuration through. Confirmed live.

Six Low findings cluster around logout and factor-removal semantics (`end_session` without
`id_token_hint` revokes nothing; deleting an IdP or removing a factor leaves issued tokens alive),
discovery drift (advertised response types and grants that do not work), an inconsistent session-token
transport, and an unhardened Postgres service definition.

None of the Low findings is an authentication bypass, a privilege escalation or a cross-tenant
exposure. The most important limitation is structural and already documented by the project: no
independent third party has tested this system, and the owner has waived that gate.

## 2. Repository and commit baseline

```
$ git remote -v
origin  https://github.com/aelboum/iam.git (fetch)
origin  https://github.com/aelboum/iam.git (push)

$ git branch --show-current
security/assessment-2026-10-29

$ git rev-parse HEAD
2f78ab65c93c24ff2518345cac370074c862c8a4

$ git status --porcelain=v1
?? strix_runs/

$ git rev-list --left-right --count origin/main...HEAD
4       0
```

- Working tree: clean apart from one pre-existing untracked directory, `strix_runs/` (a prior
  AI-scanner run: `coverage.json`, `findings.sarif`, `run.json`, `strix.log`). Left untouched.
- `HEAD` **is** the merge-base with `origin/main`; `origin/main` (`b9b7c6c`) is **4 commits ahead**.
  The local checkout is **stale**. The four commits are `db980e0` (regressions from this very
  assessment), `3e27958` (merge), `7533c69` (deploy-hardening follow-ups) and `b9b7c6c` (merge),
  touching `cmd/iamd/main.go`, `internal/api/api.go`, `internal/config/config.go`,
  `internal/store/apikeys.go`, `deploy/Caddyfile` and both prod/staging compose files — i.e.
  **several files this report makes findings against have already changed upstream**. See §17.
- The local branch is also 1 commit behind its own remote (`db980e0`).
- Per instructions the checkout was **not** updated, reset, cleaned or stashed. All findings are
  against `2f78ab6` and must be re-validated against `origin/main` before remediation.
- No tags exist. 87 commits of history were scanned.

## 3. Audit scope and exclusions

**In scope:** every Go package, SQL migration, compose/Dockerfile/Caddyfile, CI workflow, script,
env template, and security document in the repository; the engine run locally against a disposable
Postgres; the unauthenticated HTTP surface; the full authenticated management and login API.

**Out of scope / not performed:**

- No production or staging deployment was contacted. The IAM staging stack was not started,
  restarted or reconfigured.
- `vps-ai-pbx` and `zitadel-stack` were not touched. (Observation: three `zdrill-*` containers were
  running at session start and were destroyed at 20:14 local by an external process — `docker
  events` shows their `destroy` events, none of which came from this audit. They are not part of
  this repository.)
- No live Google / Microsoft / Entra round trip (no external IdP registration was used).
- No load, DoS or credential-stuffing campaign; no exploitation against any live system.
- No dependency upgrades, workflow changes, branch/PR/issue creation.
- `semgrep` and `trivy` are not installed and were not installed.
- No image scanning of `caddy:2.8.4-alpine`, `postgres:17.2-alpine` or
  `gcr.io/distroless/static-debian12:nonroot` (no scanner available); tag currency was assessed by
  reading, not by CVE query.

## 4. Component inventory

Single Go module `github.com/aelboum/iam` (`go 1.26.10`, `toolchain go1.27.3`).

| Area | Files |
|---|---|
| Entry point / server wiring | `cmd/iamd/main.go` (491), `main_test.go`, `headers_test.go` |
| REST management + login API | `internal/api/{api,users,sessions,orgs,projects}.go` (2,312 total) + 5 test files |
| Authentication | `internal/authn/{authn,federation,passkeys,providers}.go` (1,766) + 9 test files |
| OIDC provider adapter | `internal/oidcop/{storage,keys,provider,models}.go` (1,585) + 5 test files |
| Persistence | `internal/store/*.go` (2,014) + 8 test files |
| Schema | `internal/db/migrations/0001..0008` (9 files, 426 lines), `internal/db/db.go` |
| Crypto helpers | `internal/secret/secret.go`, `internal/sizing/sizing.go`, `internal/ratelimit/ratelimit.go` |
| Config | `internal/config/config.go` |
| Docs UI | `internal/docs/{docs.go,openapi.yaml}` |
| Infra | `Dockerfile`, `.dockerignore`, `deploy/Caddyfile`, 5 compose files, `.github/workflows/ci.yml` |
| Scripts | `scripts/{smoke_test,features_test,rotation_test}.py`, `scripts/migration_rehearsal.sh` |
| Docs | `README.md`, `docs/{SECURITY,OPERATIONS,DEPLOYMENT,DEPLOY_HARDENING,PENTEST,ROADMAP,SECURITY_ASSESSMENT_2026-10-29,STAGING,SOCIAL_LOGIN,EXTERNAL_VALIDATION,PENTEST_*}.md` |

**Routes.** 50 `/v1` management/login routes (all behind `requireAPIKey`), plus the OP surface
(`/authorize`, `/authorize/callback`, `/oauth/token`, `/oauth/introspect`, `/userinfo`, `/revoke`,
`/end_session`, `/keys`, `/.well-known/openid-configuration`, `/device_authorization`), `/healthz`,
`/logged-out`, `/idp/callback`, and optionally `/docs*`. `internal/docs/openapi.yaml` documents
exactly the 50 `/v1` paths — no drift.

## 5. Tools and exact commands

All run from the repository root. Disposable Postgres: `postgres:17-alpine` on `127.0.0.1:55432`
(container `iam-audit-pg`), created and destroyed by this audit.

```
go build ./...
go vet ./...
go test ./...                                   # IAM_TEST_DATABASE_URL set
CGO_ENABLED=1 go test -race ./...               # run in golang:1.27.3-alpine + gcc/musl-dev
govulncheck ./...
govulncheck -show verbose ./...
gosec -quiet -severity low -confidence low ./...
staticcheck ./...
gitleaks detect --source=. --redact --no-banner
```

Local dynamic validation: engine built to scratch and run on `127.0.0.1:8099` with
`IAM_DEV_MODE=true`, `IAM_SHARED_RATE_LIMITS` unset, a disposable database `iam_live`, and a
throwaway master key. Probe scripts live outside the repository in
`%LOCALAPPDATA%\hermes\cache\scratch\iamaudit\` (`probe.py` … `probe5.py`). Postgres cgroup
behaviour was measured with `docker run --rm alpine cat /sys/fs/cgroup/memory.max`, with and
without `--memory=1g`.

Tool versions: Go 1.27.3 (host) and `golang:1.27.3-alpine` (race run), Docker 29.8.2.

## 6. Tests executed and results

| Command | Result |
|---|---|
| `go build ./...` | pass |
| `go vet ./...` | pass, no output |
| `go test ./...` | **pass**, all 10 test packages (`api` 4.2s, `authn` 5.8s, `db` 4.4s, `oidcop` 3.5s, `store` 4.5s) |
| `CGO_ENABLED=1 go test -race ./...` | **pass**, no data race reported in any package |
| `govulncheck ./...` | 0 reachable; 1 module-level (`GO-2026-5932`, `x/crypto/openpgp`, not called) |
| `gosec -severity low` | 7 findings, all `G104` unhandled `w.Write`/`Close`; 5 reviewed `#nosec` |
| `staticcheck ./...` | clean |
| `gitleaks` full history (87 commits) | 0 leaks |

`go test -race` cannot run on the Windows host (no `gcc`); it was run inside
`golang:1.27.3-alpine` on a Docker network shared with the disposable database. The repository was
mounted read-only, so the run could not modify the working tree.

## 7. Findings by severity

**No Critical. No High. 2 Medium, 6 Low, 8 Informational.**

### Medium

#### M-01 — Global CSP breaks `response_mode=form_post` (regression from the L-01 fix)

| | |
|---|---|
| Severity / confidence | **Medium** / high (confirmed live) |
| Location | `cmd/iamd/main.go:372` (`securityHeaders`), applied router-wide at `cmd/iamd/main.go:170` |
| Component | OIDC authorization endpoint, `form_post` response mode |
| Introduced by | `2f78ab6` — the CSP was added as remediation for prior finding L-01 |

**Evidence.** `securityHeaders` sets, on *every* response:

```
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
```

The OP renders `form_post` with an inline handler and a cross-origin form target
(`github.com/zitadel/oidc/v3@v3.51.16/pkg/op/form_post.html.tmpl`). Live capture from
`GET /authorize/callback?id=…` after a completed login:

```
HTTP 200
Content-Type: text/html; charset=utf-8
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'

<body onload="javascript:document.forms[0].submit()">
<form method="post" action="https://app.example.test/cb">
<input type="hidden" name="state" value="xyz-state"/>
<input type="hidden" name="code" value="eyJhbG…"/>
```

**Failure condition.** Two independent CSP violations:

1. Inline event handlers are governed by `script-src`, falling back to `default-src`. With
   `default-src 'none'` and no `script-src`, `onload` never runs — the form is never submitted.
2. `form-action` does not fall back to `default-src`; it is explicitly `'self'`. The form targets
   the relying party's origin, which differs from the issuer origin, so submission is blocked even
   if a user submits manually.

**Preconditions / attacker capability.** None — it is a configuration defect. Any client that sends
`response_mode=form_post` is affected. The engine stores and honours `ResponseMode`
(`internal/oidcop/storage.go:108`, `internal/oidcop/models.go:111`), so the mode is reachable.

**Impact.** Login completes server-side but the browser is left on a blank page and the client never
receives the code. Fails closed, so no token leakage — but a full functional break of a standard
OIDC mode, and of the mode recommended for keeping codes out of URLs and `Referer` headers. Clients
that switched to `form_post` *because* of the previous audit's hardening are the ones broken.

**Existing mitigation.** `response_mode=query` (the default) works — verified: the same flow returns
`302` with `?code=…&state=…`.

**Reproduction status.** Reproduced live, twice, on a disposable local instance.

**Test coverage.** None. `cmd/iamd/headers_test.go` asserts the CSP string but not that the OP's HTML
still functions under it.

**Remediation.** Add a `script-src` that permits the inline handler and widen `form-action` to the
registered redirect origins — or, more simply, override the CSP on the OP's HTML responses only
(e.g. `script-src 'unsafe-inline'; form-action https:`) while leaving the strict JSON policy in
place. Do not relax the policy for JSON responses.

**Suggested regression test.** Boot the engine, complete a code flow with `response_mode=form_post`,
assert the callback response's CSP contains a `script-src` that allows inline handlers and a
`form-action` that covers the redirect origin.

**Further investigation.** Confirm whether the upstream library can be made to emit a non-inline
submit (e.g. a `<button>` plus `noscript`) so `'unsafe-inline'` is avoidable.

#### M-02 — No container memory limit, so the hashing-pool sizing guard never engages

| | |
|---|---|
| Severity / confidence | **Medium** (availability) / high |
| Location | `docker-compose.prod.yml:30-58`, `docker-compose.staging.yml:43-74`, `docker-compose.yml:15-24`; guard at `internal/sizing/sizing.go:66-127`, `cmd/iamd/main.go:73-85` |
| Component | argon2id hashing pool sizing (the N12 mitigation) |

**Evidence.** No compose file sets `mem_limit`, `deploy.resources.limits.memory`, or any equivalent:

```
$ grep -rn "mem_limit\|deploy:\|resources:" docker-compose*.yml
(no output)
```

`sizing.MemoryLimit()` reads `/sys/fs/cgroup/memory.max`; `parseMemMax` treats the literal `max` as
"unknown" (`sizing.go:79-89`), and `Check()` returns `ok=true` with no warning when `known` is false
(`sizing.go:107-110`). Measured cgroup behaviour:

```
$ docker run --rm alpine cat /sys/fs/cgroup/memory.max
max
$ docker run --rm --memory=1g alpine cat /sys/fs/cgroup/memory.max
1073741824
```

So with the shipped compose files the guard is inert. The local run logged exactly that:

```json
{"msg":"password-hashing pool sized","slots":24,"auto":true,"mem_limit_known":false}
```

24 auto slots × 64 MiB (`sizing.ArgonHashMiB`) ≈ **1.5 GiB** of peak hashing memory with no limit
declared, on a host whose available memory the engine cannot see.

**Preconditions / attacker capability.** Unauthenticated. Any caller able to drive concurrent
password logins (`/v1/sessions/{id}/password`, `/oauth/token` client-secret checks) can push the
process to its hashing peak.

**Impact.** The N12 mitigation — "size the pool and check it against the container limit" — is
bypassed by default. Under a burst the process can be OOM-killed by the kernel rather than shedding
with a 503, taking every tenant down at once. `IAM_STRICT_SIZING=true` does not help: with
`known=false` it also passes.

**Existing mitigation.** `IAM_HASH_SLOTS` can be set explicitly, and `GOMAXPROCS` is cgroup-CPU-aware
so the slot count tracks CPU quota. Neither bounds memory.

**Reproduction status.** Mechanism reproduced live (cgroup values above, plus the engine's own log
line). Not reproduced as an actual OOM — that needs load.

**Test coverage.** `internal/sizing/sizing_test.go` covers the parser and `Check()` thoroughly, but
nothing asserts that the shipped compose files declare a limit.

**Remediation.** Add `mem_limit` (and `cpus`) to the `iam` service in every compose file, sized to
`slots × 64 MiB + ~128 MiB` base, and set `IAM_HASH_SLOTS` explicitly to match. Consider making
`IAM_STRICT_SIZING` the production default once limits exist. `docs/DEPLOY_HARDENING.md` should gain
a fifth section; it currently covers DNS, secrets, DB TLS and bootstrap rotation but not resources.

**Suggested regression test.** A CI step that parses each compose file and fails if the `iam` service
has no memory limit while `IAM_HASH_SLOTS` is unset or exceeds what the limit allows.

**Further investigation.** Confirm the intended production memory budget; the right limit is a
capacity decision, not a code one.

### Low

#### L-01 — `end_session` without `id_token_hint` revokes nothing

| | |
|---|---|
| Severity / confidence | **Low** / high (confirmed live) |
| Location | `internal/oidcop/storage.go:321-323` (`TerminateSession`), `:296-304` (`TerminateTokens`) |

`TerminateSession(userID, clientID)` calls `TerminateTokens`, which deletes
`WHERE subject = $1 AND client_id = $2`. The library only populates `userID` from a verified
`id_token_hint` (`op/session.go:78-92`). Without one, `subject` is `''` and the `DELETE` matches
nothing.

Live evidence, same access token throughout:

```
userinfo BEFORE logout:            200
end_session (no id_token_hint):    302  -> https://app.example.test/bye2
userinfo AFTER logout:             200  {"email":"victim@audit.test",…}
end_session (with id_token_hint):  302
userinfo AFTER hinted logout:      403
```

**Impact.** A relying party that calls `end_session` with only `client_id` and
`post_logout_redirect_uri` — a common, spec-legal shape — gets a successful redirect and a false
sense of logout while the access token keeps working for its full 5 minutes and the refresh token
for up to 30 days. Users believe they are signed out.

**Mitigations.** `id_token_hint` works correctly. `/revoke` and `POST /v1/users/{id}/logout` both
work. Access tokens are short-lived.

**Test coverage.** None for `end_session`.

**Remediation.** Either document `id_token_hint` as required for revocation and reject
hint-less calls, or implement `op.CanTerminateSessionFromRequest` and fall back to revoking by
`client_id` alone (broad, but honest) when no hint is present.

**Suggested regression test.** Obtain a token, call `end_session` with only `client_id`, assert
`/userinfo` returns 401/403 afterwards.

#### L-02 — Deleting an IdP ends sessions but leaves issued tokens alive

| | |
|---|---|
| Severity / confidence | **Low** / medium |
| Location | `internal/store/idp.go:100-116` |

`DeleteIDP` deletes `sessions` for users linked to the IdP, then deletes the IdP. It does **not**
touch `access_tokens` or `refresh_tokens`, and `checkUserCanUseClient`
(`internal/oidcop/storage.go:292-298`) never consults `user_identities`. The doc comment claims the
opposite: *"so a deleted (or compromised-then-removed) IdP cannot keep minting access through a
session that is still open."*

**Impact.** An org admin who removes a compromised IdP to cut off SSO does not cut off access: the
users' refresh tokens keep minting access tokens for up to 7 days idle / 30 days absolute. The users
remain legitimate, so this is not a takeover — it is a slower-than-expected containment.

**Mitigations.** `RevokeOrgTokens` / `RevokeUserTokens` exist and are used on other destructive
paths (`deleteApp`, `deleteProject`, `deleteOrg`), so the pattern is established and this path just
misses it. `TestDeleteIDPRevokesLinkedSessions` locks in the sessions-only behaviour.

**Remediation.** In the same transaction, also delete tokens for the linked users' subjects (or
document the gap and correct the comment).

**Suggested regression test.** Extend `TestDeleteIDPRevokesLinkedSessions` to assert an access token
issued before deletion is refused afterwards.

#### L-03 — Removing a factor does not revoke already-issued OAuth tokens

| | |
|---|---|
| Severity / confidence | **Low** / medium |
| Location | `internal/api/users.go:387-403` (`removeTOTP`), `:639-655` (`deletePasskey`), `:362-385` (`verifyTOTP`) |

These handlers call `DeleteUserSessions` (sessions + password resets) but not `RevokeUserTokens`.
`setPassword`, `lockUser` and `deleteUser` do call `RevokeUserTokens`.

**Impact.** Removing a passkey because it may be compromised, or removing TOTP, leaves any stolen
refresh token working. The token's `amr` also still claims the removed factor until it expires.

**Mitigations.** Access tokens are 5 minutes; `amr` is advisory. `README.md:227` documents
"changing TOTP ends logins in progress", so the current behaviour is at least described.

**Remediation.** Add `RevokeUserTokens` to `removeTOTP` and `deletePasskey` for consistency with the
other credential-change paths.

**Suggested regression test.** Mirror `TestSetPasswordHandlerRevokesOnlyTargetUser` for
`DELETE /v1/users/{id}/totp` and `DELETE /v1/users/{id}/passkeys/{cred}`.

#### L-04 — Discovery advertises response types and grants that do not work

| | |
|---|---|
| Severity / confidence | **Low** / high (confirmed live) |
| Location | `internal/oidcop/models.go:37-39` (`ResponseTypes` returns only `code`), `internal/oidcop/storage.go:504-510` (`GetKeyByIDAndClientID` and `ValidateJWTProfileScopes` both return "not supported") |

Discovery advertises:

```
response_types_supported: ["code", "id_token", "id_token token"]
grant_types_supported:    [..., "urn:ietf:params:oauth:grant-type:jwt-bearer"]
introspection_endpoint_auth_signing_alg_values_supported: ["RS256"]
```

Live results:

```
response_type=code             -> 302 to the login URL (works)
response_type=code id_token    -> 302 #error=unauthorized_client
response_type=id_token token   -> 302 #error=unauthorized_client
grant_type=jwt-bearer          -> parses, then fails; GetKeyByIDAndClientID is a stub
```

`GrantTypeJWTAuthorizationSupported()` is hard-coded `true` by the library
(`op/op.go:402-404`), so the engine cannot switch it off via config — but it can stop advertising
the capability by implementing the lookup, or document the gap.

**Impact.** An integrator who builds a client from discovery picks implicit flow or
`private_key_jwt` and hits a runtime failure. Fails closed with a clear error, so no security
consequence — wasted integration effort and a misleading capability surface.

**Remediation.** Either implement `GetKeyByIDAndClientID` (a JWKS column on `apps`) or document
"code flow only, `client_secret_basic`/`post`/`none` only" prominently in `README.md` and
`docs/SECURITY.md`.

**Suggested regression test.** Assert that every `response_types_supported` entry is accepted by
`/authorize` for a matching client.

#### L-05 — Session token transport is inconsistent between verbs

| | |
|---|---|
| Severity / confidence | **Low** / high (confirmed live) |
| Location | `internal/api/sessions.go:19` (`sessionTokenHeader`), used at `:67`, `:76`; body-only at `:91`, `:107`, `:268`, `:284` |

`GET` and `DELETE /v1/sessions/{id}` read `X-Session-Token`; `POST …/password`, `…/totp`,
`…/passkey/begin` and `…/passkey/finish` read `session_token` from the JSON body only. A header on a
POST is silently ignored:

```
GET  /v1/sessions/{id} with header          -> 200
POST /v1/sessions/{id}/password, header only -> 401 {"error":"session invalid or expired"}
POST /v1/sessions/{id}/password, body token  -> 200
```

**Impact.** Not a vulnerability — the token is required either way and the failure is closed — but
the `401` is indistinguishable from an expired session, which makes integration and incident
debugging harder.

**Remediation.** Accept the header on every session route (preferred: header only, so the token
never lands in a body that might be logged), or document the split explicitly.

#### L-06 — Postgres service definition is unhardened in prod and staging

| | |
|---|---|
| Severity / confidence | **Low** / high |
| Location | `docker-compose.prod.yml:60-73`, `docker-compose.staging.yml:76-92` |

The `iam` and `caddy` services both get `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`
and (for `iam`) `read_only: true`. The `postgres` service gets only
`security_opt: [no-new-privileges:true]` — no `cap_drop`, no resource limits, no `shm_size`.

**Impact.** The data-bearing service keeps the full default capability set. A Postgres compromise
has more to work with than necessary. No resource limit means an unbounded sort or connection storm
can starve the host that also runs the engine.

**Mitigations.** Postgres is not published to the host in prod or staging, and runs on the private
compose network only — verified in both files.

**Remediation.** `cap_drop: [ALL]` plus the specific capabilities Postgres needs (`CHOWN`,
`DAC_OVERRIDE`, `FOWNER`, `SETGID`, `SETUID`), a `mem_limit`, and an explicit `shm_size`.

### Informational

| ID | Finding | Location |
|---|---|---|
| I-01 | Two migrations share the `0007_` prefix (`0007_mfa_lockout.sql`, `0007_social_login.sql`). Ordering is decided by `sort.Strings` on the full path, so it works today, but any future `0007_*` file silently interleaves and the numbering no longer expresses intent. | `internal/db/migrations/`, `internal/db/db.go:101-105` |
| I-02 | The local `.env` carries `IAM_GOOGLE_CLIENT_ID` and `IAM_GOOGLE_CLIENT_SECRET`, but no code reads either name — Google login is configured per-org through the API. Dead configuration that suggests a global Google integration exists. | `.env` (gitignored) |
| I-03 | Documentation contradiction: `docs/DEPLOY_HARDENING.md:17-18` states production stays NO-GO until criterion 12 is *completed*; `docs/SECURITY.md:184-217` records criterion 12 as **waived** by the owner. | both files |
| I-04 | The audit trail has no integrity protection (no hash chain, no append-only grant) and `Store.Audit` swallows write failures after logging them, so a DB-level actor can rewrite history and a transient failure loses an event silently. | `internal/store/audit.go:24-35` |
| I-05 | `/end_session`, `/keys`, `/.well-known/openid-configuration` and `/device_authorization` are not in the rate-limit map. `/end_session` verifies a JWT signature per call. | `cmd/iamd/main.go:444-449` |
| I-06 | The dev compose file uses the literal password `iam` and `sslmode=disable`. Fine for dev; a copy-paste into anything reachable is not obviously unsafe from the file alone. | `docker-compose.yml:5-6,19` |
| I-07 | `iam` runs `read_only: true` with no `tmpfs: /tmp`, while the `Dockerfile:13` comment says "no writable filesystem outside /tmp". Nothing currently writes to `/tmp`, so this is latent, not broken. | `docker-compose.prod.yml:48`, `Dockerfile:13` |
| I-08 | Backup guidance is a placeholder: "tooling/location/retention are environment-specific", with no stated encryption requirement for the dump even though the dump contains encrypted secrets plus their key material context. | `docs/OPERATIONS.md:171-178` |

## 8. Attack-path analysis for the serious findings

**M-01 (form_post).** Path: RP sends `response_mode=form_post` → engine stores it
(`storage.go:108`) → user authenticates → callback returns HTML with inline `onload` and a
cross-origin `action` → CSP blocks both → browser sits on a blank page. No attacker needed; the
attack surface is "any RP that chose the more secure response mode". Because it fails closed there
is no token exposure, but a client that retries by falling back to `query` re-introduces the code-in-URL
and `Referer` leakage that `form_post` was chosen to avoid.

**M-02 (memory).** Path: unauthenticated `POST /v1/sessions` then `POST …/password` in a loop →
`CheckPassword` → `orgLogin`/`accountLimit` admit → `verify` → `acquireHashSlot` → up to
`GOMAXPROCS` concurrent argon2id runs at 64 MiB each → with no cgroup limit the kernel sees host
memory and does not reclaim until it is too late → OOM kill of the whole process, all tenants.
`HashWaitTimeout` (3 s) sheds only when the slot pool is full, which it will be — but the pool was
sized from `GOMAXPROCS` on a host whose memory was never checked, so the pool itself can be larger
than the box can hold.

**L-01 (logout).** Path: RP redirects browser to `/end_session?client_id=…&post_logout_redirect_uri=…`
→ library validates the URI against the registered list and returns `302` → `TerminateSession("",
clientID)` → `DELETE … WHERE subject = ''` → 0 rows. The user sees the logged-out page; the token
stays valid. On a shared or kiosk machine the next user inherits a live token for up to 5 minutes.

**L-02 / L-03 (containment).** Both are "revocation is narrower than the operator expects". The
window is bounded by the refresh idle TTL (7 days) and absolute session age (30 days), so the
practical exposure is a stolen refresh token surviving the action that was supposed to kill it.

## 9. Authentication and authorization coverage matrix

Verified by reading the handler and its middleware, then by live request. `A` = instance admin key,
`O` = org-scoped admin key, `L` = login-scope key.

| Route | Authn | Authz | Live result |
|---|---|---|---|
| `POST /v1/sessions`, `/password-resets`, `/federated-logins`, `/auth-requests/{id}/finalize` | any key | org scope via `canAccessOrg` | L → 201; foreign org → 403 |
| `GET/POST /v1/sessions/{id}/*` | any key | session token + org match (`authn.loadSession`) | wrong-org key → `ErrSessionInvalid`; `TestSessionScopedToOwningOrg` |
| `POST/GET/DELETE /v1/api-keys*` | A only | — | O → 403 |
| `GET /v1/audit` | A only | — | O → 403 |
| `POST/GET /v1/orgs` | A only | — | O → 403 |
| `GET /v1/orgs/{id}`, `/audit`, `POST /users`, `/machine-users`, `/idps`, `/projects` | any admin key | `requireOrgAccess` | foreign org → 403 |
| `DELETE /v1/orgs/{id}` | A only | — | O → 403 |
| `GET/PATCH/DELETE /v1/users/{id}`, `PUT /password`, `/lock`, `/unlock`, `/logout`, `/totp*`, `/passkeys*`, `/grants` | any admin key | `userForCaller` → 404 on foreign org | foreign user → 404 (no existence oracle) |
| `POST /v1/users/{id}/email/verification`, `/email/verify` | A only | — | O → 403 |
| `PATCH/DELETE /v1/user-grants/{id}` | any admin key | `userGrantForCaller` → 404 | foreign → 404 |
| `GET /v1/projects/{id}`, `/roles`, `/grants` | any admin key | `projectForReader` (owner or granted) | unrelated → 404 |
| `POST/DELETE /v1/projects/{id}`, `/roles`, `/apps` | any admin key | `projectForOwner` | granted-but-not-owner → 403 |
| `POST /v1/projects/{id}/grants` | A only | + `projectForOwner` | — |
| `PATCH /v1/project-grants/{id}` | any admin key | `projectGrantForOwner` | — |
| `DELETE /v1/project-grants/{id}` | owner **or** granted org | `canAccessOrg(granted)` else owner | by design (N20) |
| `GET /v1/orgs/{id}/project-grants` | any admin key | `requireOrgAccess` | — |
| `PUT /v1/orgs/{id}/idps/{idp}/trust` | A only | — | — |

**Holds.** Default-deny: `requireAPIKey` is router-wide on `/v1`, `requireAdminScope` gates the whole
management group, and every object route re-checks ownership. Foreign objects return `404` (no
existence oracle) while foreign *containers* return `403` — a deliberate and consistent split. Live
cross-tenant probe: 13 routes with Tenant A's key against Tenant B's objects, all `404`/`403`, all
correct with B's key. Login-scope keys reach only the session API (`403` on management routes).
Self-deletion of an API key is refused (`orgs.go:170`). A child key cannot outlive its parent
(`orgs.go:139-141`).

## 10. OIDC and federation review

**Holds.** `op.StaticIssuer` pins the issuer (no host-header confusion). PKCE S256 is required for
public clients and `plain` is refused (`storage.go:68-77`). The code is claimed only after PKCE and
client authentication succeed, so a stolen code with a wrong verifier cannot burn it
(`storage.go:140-162`). Refresh rotation is a single `UPDATE … WHERE used_at IS NULL` CAS; reuse
revokes the family and audits (`storage.go:256-284`). `no-store` on token/introspect/revoke/userinfo/
callback. `post_logout_redirect_uri` is validated against the registered list. Introspection is
scoped to the caller's project. Machine scopes are limited to one `urn:iam:project:<uuid>`.

**Federation.** State, nonce and PKCE verifier are 256-bit random; the state is stored hashed and
burned on claim; the intent is burned even on a binding mismatch; redemption requires the browser
binding cookie value (`federation.go:82-124`, `:303-342`). Identity is keyed on `(idp_id, sub)`,
never email. Email linking needs instance-admin `trust_email` **and** `link_by_email`. Untrusted
emails become `idp-<hash>@idp.invalid` placeholders. Preset issuers are computed server-side, so an
org admin cannot point "google" or "entra" at an arbitrary issuer; Entra is pinned to a tenant GUID.
Every discovery endpoint and the authorization URL pass `SafeIdPURL`; the outbound client refuses
non-public addresses at the dialer (post-DNS), speaks https only, caps bodies at 1 MiB and redirects
at 3.

**Findings.** M-01 (form_post), L-01 (logout), L-04 (advertised-but-unimplemented capabilities).
Accepted and unchanged: N7 (no step-up forwarding to the IdP), N9 (`SafeIdPURL` not re-run in the
callback), N14 (code reuse does not revoke issued tokens), N17 (codes stored as ciphertext, not
hashed), N25 (`userinfo` answers 403 with an empty body rather than 401 `invalid_token`).

**Not verified.** No live Google / Microsoft / Entra round trip; no live cross-tenant Entra
rejection (the project reports one from 2026-10-26 on a local non-prod target, which this audit did
not repeat).

## 11. Database, migration and concurrency review

**Holds.** Every query is parameterised; the only string concatenation is fixed identifiers
(`userColumns`, `projectTokenCond`, `Page.sql()` clamped integers, `PurgeExpired` table names from a
constant slice). No `Sprintf` into SQL. Migrations are forward-only, each in its own transaction with
its version row, serialised cluster-wide by a session-level advisory lock that is released before the
connection returns to the pool and whose failed unlock hijacks the connection (`db.go:67-137`).
`TestMigrateConcurrent` and `TestMigrateLockAcquisitionIsCancellable` cover it. Uniqueness is
enforced in the schema for `(org_id, lower(email))`, `(org_id, lower(username))`, `(user_id,
project_id)`, `(project_id, granted_org_id)`, `client_id`, `key_hash`, `token_hash`, `state_hash`.
Tenant isolation is application-enforced (no RLS) and every store method takes the owner id
explicitly.

**Concurrency.** `ReserveAttempt` is a single conditional `UPDATE` so parallel guesses cannot exceed
the threshold; `AcceptTOTPStep` and `UpdatePasskeyUse` are monotonic CAS; `ClaimAuthCode`,
`SetAuthCode`, `CompleteAuthRequest` and `RotateRefreshToken` are all single-statement guards;
`CreatePasswordReset` takes `FOR UPDATE` on the user row after an unlocked fast path. `go test -race`
is clean.

**Findings.** I-01 (duplicate migration prefix). Accepted and unchanged: N2 (no down-migration), N26
(quota check-then-insert). `sslmode=disable` on the compose network is a documented deploy-time
follow-up (`DEPLOY_HARDENING.md` §3) — not re-reported.

**Not verified.** No production-sized data; no deadlock or lock-cancellation testing beyond the
existing unit tests; no RLS.

## 12. Dependency and supply-chain review

**Holds.** `govulncheck` symbol mode: **0 reachable**. The single module-level hit is
`GO-2026-5932` (`x/crypto/openpgp`, unmaintained, no fix available) and the engine never calls
`openpgp` — informational, already register row `GO-2026-5932`. Direct dependencies are current and
pinned (`chi` 5.5.0, `go-jose` 4.1.6, `go-webauthn` 0.18.2, `pgx` 5.11.0, `zitadel/oidc` 3.51.16,
`zitadel/passwap` 0.12.1). `go.sum` present. `gitleaks` over 87 commits: 0 leaks; `.gitleaksignore`
uses three exact fingerprints, no blanket path suppressions.

**CI.** `permissions: contents: read` at workflow level; no write scopes, no `pull_request_target`,
so no untrusted-PR code execution with a token. Actions are pinned to major tags (`checkout@v4`,
`setup-go@v5`, `setup-python@v5`) — not SHAs. The `security` job runs `govulncheck`, `gitleaks`,
`gosec` and `staticcheck` as gates, so the scanners are not merely available, they are enforced.

**Build.** `CGO_ENABLED=0`, `-trimpath`, `-ldflags="-s -w"`. Builder pinned to `golang:1.27.3-alpine`
matching the `toolchain` directive, so a rebuild cannot silently pick up an older stdlib. Runtime is
`gcr.io/distroless/static-debian12:nonroot`, `USER nonroot`.

**Findings.** None above Informational. Gaps: actions pinned by tag not SHA; no image scanning
(`trivy`/`grype`) in CI; no SBOM; no digest pinning on `caddy:2.8.4-alpine`,
`postgres:17.2-alpine` or the distroless base. `postgres:17.2-alpine` is a patch behind the current
17.x line and `caddy:2.8.4-alpine` is a minor behind 2.8.x — both are floating-tag rebuild risks
rather than known-vulnerable pins, and neither was CVE-queried (no scanner).

## 13. Infrastructure and configuration review

**Holds.** Prod and staging publish only Caddy's 80/443; `iam` and `postgres` are `expose`-only.
`iam` and `caddy` are `read_only`, `cap_drop: [ALL]`, `no-new-privileges`; Caddy re-adds only
`NET_BIND_SERVICE`. Distroless nonroot runtime, no shell, no package manager. Healthcheck uses the
binary's own `healthcheck` subcommand (no curl in the image). Caddy sets HSTS, strips `Server`,
refuses `/docs` at the edge, and sets `X-Forwarded-Proto: https`; the engine trusts exactly one
proxy hop. `IAM_DEV_MODE` and `IAM_ENABLE_DOCS` are `"false"` in prod and staging. Staging pins its
own compose project name so teardown cannot reach other stacks. `config.Load` fails closed on a
missing/short master key, an http issuer outside dev mode, a bad proxy-hop count, a non-origin CORS
entry, and an RP ID/origin mismatch.

**Findings.** M-02 (no memory limits), L-06 (unhardened Postgres), I-06, I-07.

**Gaps not verifiable from the repository.** No TLS to Postgres (`sslmode=disable`), no secret store
(`.env.prod` on disk), bootstrap admin key still live after first start — all three are documented
deploy-time follow-ups in `docs/DEPLOY_HARDENING.md`, whose own header says nothing in it has been
executed. No monitoring/alerting configuration, no log shipping, no backup schedule, no
`mem_limit`/`cpus` anywhere.

## 14. Secrets and sensitive-data review

**Holds.** No secret is committed. `gitleaks` full history is clean and the three suppressions are
reviewed test fixtures. `.env` is gitignored and `.dockerignore`d. Struct tags keep
`PasswordHash`, `TOTPSecretEnc`, `ClientSecretHash` and `IDP.ClientSecretEnc` out of every JSON
response; `APIKey` has no hash field at all. Client secrets and machine secrets are returned exactly
once, at creation/rotation. TOTP secrets, IdP client secrets, signing keys, PKCE verifiers and
authorization codes are AES-256-GCM sealed. Email codes are HMAC'd with a derived key (a plain hash
of six digits is brute-forceable). `keyFingerprint` logs 12 hex chars of a hash, never the key.
Federated refusal paths log a coarse reason plus the Go error *type* only, so a unique-violation
cannot echo an email. The hash-shed and org-budget warnings are rate-limited to one line per second
so overload cannot flood the log.

**Findings.** I-02 (dead Google env vars in `.env`), I-04 (audit integrity). No secret value appears
in this report.

**Not verified.** No log-aggregation pipeline exists to inspect, so "no secret reaches the sink" was
established by reading every `slog` call site, not by inspecting real logs. `scripts/*.py` fixtures
were not individually audited for realistic-looking values.

## 15. Security regression-test gaps

Coverage is strong — 91 test functions, including cross-tenant store tests, per-factor lockout with
a concurrency row, refresh-family reuse, passkey counter CAS, migration concurrency, limiter
fallback, and revocation scoping per handler. Gaps that matter:

| Gap | Risk |
|---|---|
| No `end_session` test at all | L-01 shipped silently |
| No test that OP HTML survives the global CSP | M-01 shipped silently |
| No test that compose files declare resource limits | M-02 |
| `DeleteIDP` test asserts sessions only, not tokens | L-02 locked in as "correct" |
| No test for token revocation on factor removal | L-03 |
| No test that advertised discovery capabilities actually work | L-04 |
| No handler-level test that an org key gets 404 on a foreign user id (only the store/authn layer is covered) | regression risk on `userForCaller` |
| No test for `/healthz` or `/keys` behaviour under load | I-05 |

## 16. False positives and excluded findings

| Lead | Why excluded |
|---|---|
| `gosec` G104 ×7 (`w.Write`, `resp.Body.Close`, `conn.Hijack().Close`) | None carries a security decision; the response is already committed when `Write` fails. |
| `gosec` G710 on `http.Redirect` in `IDPCallback` | The target is `intent.ReturnURL`, validated by `redirectURLAllowed` at start and stored server-side; the request value is only the state. Correctly `#nosec`-annotated. |
| `gosec` G704 on `client.Get` in `healthcheck` | Target is the operator-set `IAM_LISTEN_ADDR`. |
| `gosec` G101 ×3 | SQL column lists. |
| `GO-2026-5932` (`x/crypto/openpgp`) | Not called; `govulncheck` reports 0 code-affected. |
| `govulncheck` stdlib CVEs | None — the `toolchain go1.27.3` directive plus the pinned builder already close the 12 the previous assessment fixed. |
| `org.ID` deref when `GetOrgByRef` returns nil | Short-circuited by `err != nil ||` in all three call sites (`sessions.go:46`, `:161`, `:211`). |
| `*pr.key.OrgID` deref in `projectForReader` / `listRoles` | Guarded by `canAccessOrg` returning true first for instance keys. |
| `end_session` unauthenticated | By design (RFC 8665); the redirect target is allowlisted. |
| No provider-side OAuth `state` binding | Documented responsibility split (`SECURITY.md:219-235`); the RP owns `state`. |
| `sslmode=disable` in compose | Documented deploy-time follow-up, not a defect in the repository. |
| Quota check-then-insert race (N26) | Accepted; caps are large and the overshoot is marginal. |
| `/healthz` unauthenticated + DB ping (N27) | Accepted; cheap and low-rate. |
| `userinfo` 403 empty body (N25) | Accepted; library behaviour, token refused either way. |

## 17. Components that could not be fully assessed

- **`origin/main` (`b9b7c6c`)** — 4 commits ahead of the audited SHA, and they touch
  `cmd/iamd/main.go` (the CSP lives here), `internal/api/api.go`, `internal/config/config.go`,
  `internal/store/apikeys.go`, `deploy/Caddyfile` and both compose files. **M-01 and M-02 in
  particular may already be addressed upstream.** Re-validate before remediation.
- **Live identity providers** — no Google, Microsoft or Entra round trip; no live cross-tenant
  Entra rejection.
- **TLS** — the shipped Caddyfile was read, not run; no protocol/cipher probe.
- **Container images** — no CVE scan of `caddy`, `postgres` or the distroless base.
- **Production behaviour** — no deployment exists to observe; every operational claim is
  config-derived.
- **`scripts/features_test.py` (41 KB) and `smoke_test.py` (30 KB)** — read for coverage, not
  line-audited.
- **`docs/ROADMAP.md` (34 KB)** — skimmed for the readiness gates, not read end to end.

## 18. Prioritized remediation plan

Plan only. Nothing below was implemented.

**P0 — confirmed Critical:** none.

**P1 — confirmed High:** none.

**P2 — Medium**

1. **M-01 — restore `form_post`.** Change: scope a relaxed CSP (`script-src 'unsafe-inline'`,
   `form-action https:`) to the OP's HTML responses only, leaving the strict JSON policy alone.
   Benefit: form_post works again without weakening JSON responses. Regression risk: low — the
   relaxed policy touches only responses that already render HTML. Tests: the form_post regression
   test above. Depends on: nothing.
2. **M-02 — declare container memory limits.** Change: `mem_limit`/`cpus` on the `iam` service in
   all compose files, explicit `IAM_HASH_SLOTS` to match, a fifth section in `DEPLOY_HARDENING.md`.
   Benefit: the N12 guard actually runs; OOM becomes a shed instead of a kill. Regression risk:
   medium — a limit set too low causes 503s under normal load, so it needs a capacity decision.
   Tests: the compose-lint CI step. Depends on: an agreed memory budget.

**P3 — Low**

3. **L-01** — require `id_token_hint`, or implement `CanTerminateSessionFromRequest`. Risk: low.
   Test: the logout regression test.
4. **L-02** — revoke linked users' tokens in `DeleteIDP`. Risk: low (users re-authenticate). Test:
   extend `TestDeleteIDPRevokesLinkedSessions`.
5. **L-03** — `RevokeUserTokens` on `removeTOTP` and `deletePasskey`. Risk: low. Test: mirror
   `TestSetPasswordHandlerRevokesOnlyTargetUser`.
6. **L-04** — implement `GetKeyByIDAndClientID`, or document code-flow-only. Risk: low either way.
7. **L-05** — accept `X-Session-Token` on all session routes. Risk: low; keep the body field for
   compatibility.
8. **L-06** — `cap_drop` + minimal `cap_add` + `mem_limit` + `shm_size` on Postgres. Risk: medium —
   wrong capabilities break startup, so verify with `docker compose config` and a boot.

**P3 — Informational**

9. I-01 renumber the second `0007_`; I-02 drop the dead Google env vars; I-03 reconcile the
   criterion-12 wording; I-04 consider a hash chain or append-only grant on `audit_events`; I-05 add
   `/end_session` to the limiter; I-06/I-07 tighten the dev compose and add `tmpfs: /tmp`; I-08
   state a backup encryption and retention requirement.

## 19. Recommended verification steps after remediation

- Re-run the full gate set: `go test -race ./...`, `govulncheck ./...`, `gosec`, `staticcheck`,
  `gitleaks`.
- M-01: complete a `form_post` flow in a browser and confirm the page auto-submits; assert the CSP
  on the callback response.
- M-02: `docker compose -f docker-compose.prod.yml config` shows a limit; boot under `--memory` and
  confirm the startup log reports `mem_limit_known:true` and a slot count that fits; drive a burst
  and confirm `503` shedding before any OOM.
- L-01: `end_session` with only `client_id` → `/userinfo` must fail afterwards.
- L-02/L-03: issue a token, delete the IdP / remove the factor, confirm `/userinfo` fails.
- L-04: every `response_types_supported` entry accepted by `/authorize`.
- L-06: `docker compose config` plus a clean Postgres boot and a `pg_isready` healthcheck pass.
- Re-run the whole audit against `origin/main` after the upstream 4 commits are merged.

## 20. Residual risks and readiness limitations

- **This is an internal audit, not an independent penetration test.** Criterion 12 remains
  **NOT PERFORMED**. The owner waived it on 2026-10-28 (`SECURITY.md:184-217`); a waiver is not a
  pass.
- **Production readiness remains NO-GO.** Beyond criterion 12, the four deploy-time follow-ups in
  `DEPLOY_HARDENING.md` (stable DNS, managed secret store, database TLS, bootstrap rotation) are
  unexecuted, and M-02 adds a fifth.
- **No live-provider validation.** Google, Microsoft-personal and Entra round trips, and live
  cross-tenant Entra rejection, are unverified in this audit.
- **The audited commit is stale by 4 upstream commits**, several of them in files this report
  criticises.
- **Availability risks are assessed by reading, not by load.** M-02, N12 and the shared-limiter
  design have no measured behaviour under load.
- **No RLS.** Tenant isolation is entirely application-enforced; one missed `WHERE org_id` in a
  future store method is a cross-tenant leak, and only tests stand between the two.
- **Audit-trail integrity is not cryptographic** (I-04), so the trail is trustworthy against
  application bugs but not against a DB-level actor.
- **No image scanning, no SBOM, no digest pinning.** Base-image drift is invisible to CI today.
- **Secrets live in a plaintext `.env.prod` on disk** until `DEPLOY_HARDENING.md` §2 is executed.

---

*Prepared from source review, static analysis and isolated local execution. No production or staging
system was contacted; no repository file other than this report was created or modified; nothing was
committed, pushed or deployed.*
