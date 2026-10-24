# IAM engine

Headless, API-driven identity engine for B2B2C SaaS. Your SaaS owns the UI;
the engine owns tenants, users, roles, login and OIDC tokens.

Protocol code comes from permissively licensed libraries (no AGPL code):

| Concern | Library | License |
|---|---|---|
| OIDC/OAuth2 provider | `github.com/zitadel/oidc/v3` | Apache-2.0 |
| Password hashing (argon2id, bcrypt import) | `github.com/zitadel/passwap` | BSD-3-Clause |
| TOTP | `github.com/pquerna/otp` | Apache-2.0 |
| JOSE/JWT | `github.com/go-jose/go-jose/v4` | Apache-2.0 |
| Postgres driver | `github.com/jackc/pgx/v5` | MIT |
| Router | `github.com/go-chi/chi/v5` | MIT |

Keep these license notices when you distribute the binary.

## Model

```
org (vendor)  ── owns ──>  project ── roles: admin, member, billing
                              │  └── apps (OIDC clients)
                              └── project grant ──> org (customer) [admin, member]
org (customer) ── users ── user grant (project, [admin])
```

- **Org**: a tenant. Your company is one org; each B2B customer is another.
- **Project**: your product. Defines roles and has apps (OIDC clients).
- **Project grant**: onboards a customer org and limits which roles it may hand out.
- **User grant**: assigns roles to a user, always within what their org was granted.
- Only users of the owner org or of a granted org can sign in to a project's apps.
  Revoking a grant removes its user grants and blocks token refresh.

Tokens carry the tenant context your backend needs:

```json
{ "sub": "<user id>", "org_id": "...", "org_slug": "acme", "project_id": "...", "roles": ["admin"] }
```

## Run

```sh
cp .env.example .env    # fill IAM_MASTER_KEY and IAM_BOOTSTRAP_ADMIN_KEY
docker compose up --build -d
python scripts/smoke_test.py   # full end-to-end check
python examples/demo/demo.py   # click-through demo at http://localhost:3000
```

**Production:** see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (HTTPS via Caddy, hardened
containers) and [docs/PENTEST.md](docs/PENTEST.md) (scope brief for an external
penetration test).

| Env var | Meaning |
|---|---|
| `IAM_ISSUER` | Public URL. https required unless `IAM_DEV_MODE=true`. |
| `IAM_DATABASE_URL` | Postgres URL. |
| `IAM_MASTER_KEY` | 32 bytes base64. Encrypts signing keys and TOTP secrets. **Back it up.** |
| `IAM_BOOTSTRAP_ADMIN_KEY` | Instance admin API key, created at startup. |
| `IAM_LISTEN_ADDR` | Default `:8080`. |
| `IAM_TRUST_PROXY` | `true` only behind a reverse proxy that appends to `X-Forwarded-For`. |
| `IAM_TRUSTED_PROXY_HOPS` | Number of such proxies (default `1`). The client IP is taken that many entries from the right; client-written entries are ignored. |
| `IAM_ENABLE_DOCS` | Serve Swagger UI at `/docs`. Defaults to the value of `IAM_DEV_MODE`. |
| `IAM_ACCESS_TOKEN_TTL` | Default `5m`. Keep short: JWT access tokens cannot be recalled. |
| `IAM_REFRESH_IDLE_TTL` | Default `168h` (7 days without use ends the session). |
| `IAM_SESSION_MAX_AGE` | Default `720h` (30 days after login, refresh cannot extend it). |
| `IAM_LOCKOUT_DURATION` | Default `15m`, after 5 failed attempts. |
| `IAM_LOGIN_TTL`, `IAM_KEY_ROTATION` | Login session window (`15m`) and signing key rotation (`720h`). |
| `IAM_AUDIT_RETENTION` | How long audit events are kept (default `8760h`, one year). |

## API

Interactive docs: **http://localhost:8080/docs** (Swagger UI, spec at `/docs/openapi.yaml`).
Click **Authorize** and paste your API key to try calls in the browser.

All `/v1` calls need `Authorization: Bearer <api key>`.
An **instance key** (bootstrap) can do everything. An **org key**
(`POST /v1/orgs/{id}/api-keys`) can only manage its own org: delegated
administration for your customers. Keys have a **scope**: `admin` for the
management API, or `login` for the session API only. Give your login UI
backend a `login` key (`POST /v1/api-keys {"name":"login ui","scope":"login"}`)
so a compromise of that server cannot manage users. Keys can expire
(`expires_in_days`).

| Method & path | Purpose |
|---|---|
| `POST/GET /v1/orgs` | Create / list orgs (instance key) |
| `GET/DELETE /v1/orgs/{orgID}` | Read / delete org |
| `POST/GET/DELETE /v1/orgs/{orgID}/api-keys[/{keyID}]` | Org-scoped API keys |
| `POST/GET /v1/orgs/{orgID}/users` | Create / list users |
| `GET/PATCH/DELETE /v1/users/{userID}` | Read / update / delete user |
| `PUT /v1/users/{userID}/password` | Set password |
| `POST /v1/users/{userID}/unlock` | Unlock after failed logins |
| `POST /v1/users/{userID}/logout` | Revoke all sessions and tokens |
| `POST /v1/users/{userID}/totp`, `POST .../totp/verify`, `DELETE .../totp` | Enroll / activate / remove TOTP |
| `POST/GET /v1/users/{userID}/grants`, `PATCH/DELETE /v1/user-grants/{id}` | User role grants |
| `POST/GET /v1/orgs/{orgID}/projects` | Create / list projects |
| `GET/DELETE /v1/projects/{projectID}` | Read / delete project |
| `POST/GET /v1/projects/{projectID}/roles`, `DELETE .../roles/{key}` | Project roles |
| `POST/GET /v1/projects/{projectID}/apps`, `GET/DELETE /v1/apps/{appID}` | OIDC apps |
| `POST/GET /v1/projects/{projectID}/grants`, `PATCH/DELETE /v1/project-grants/{id}` | Grant project to customer orgs |
| `GET /v1/orgs/{orgID}/project-grants` | Projects granted to an org |
| `POST/GET/DELETE /v1/api-keys[/{keyID}]` | Instance-wide keys (admin or login scope) |
| `POST /v1/users/{userID}/lock` | Lock user and revoke all their tokens |
| `POST /v1/users/{userID}/email/verification`, `POST .../email/verify` | Email verification code (you deliver it) |
| `GET /v1/orgs/{orgID}/audit`, `GET /v1/audit` | Audit trail: logins, lockouts, admin actions |

Creating an app returns `client_secret` **once** (web apps). `spa`/`native`
apps are public clients and must use PKCE.

## Login flow (headless)

Your login UI backend drives the login with the session API, using a `login`-scoped
key and sending the browser's IP in `X-End-User-IP`. The engine never renders HTML.

1. The SaaS redirects the browser to `GET {issuer}/authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid profile email offline_access&state=...&code_challenge=...`.
2. The engine redirects to the app's `login_url?authRequest=<id>`.
3. Your login UI backend calls:
   - `GET /v1/auth-requests/{id}` to get the app name and login hint,
   - `POST /v1/sessions` `{"org":"acme","login_name":"alice"}` to get `session_id` and `session_token`,
   - `POST /v1/sessions/{sid}/password` `{"session_token","password"}`,
   - `POST /v1/sessions/{sid}/totp` `{"session_token","code"}`, only if `mfa_required` is true,
   - `POST /v1/auth-requests/{id}/finalize` `{"session_id","session_token"}` to get `callback_url`.
4. Your login UI redirects the browser to `callback_url`. The engine then redirects to `redirect_uri?code=...`.
5. The SaaS exchanges the code at `POST /oauth/token`.

OIDC endpoints (from `/.well-known/openid-configuration`): `/authorize`, `/oauth/token`,
`/userinfo`, `/oauth/introspect`, `/revoke`, `/end_session`, `/keys`.
Any app in the same project can introspect tokens issued to that project's apps.

## Security properties

All of these are exercised by `scripts/smoke_test.py`.

**Credentials**
- Passwords use argon2id, 10–256 characters, and may not contain the username or email.
  Imported bcrypt hashes are verified and upgraded on login.
- API keys, session tokens, refresh tokens and email codes are stored as SHA-256 hashes only.
- Signing keys (RSA-2048, RS256) and TOTP secrets are AES-256-GCM encrypted.
  Signing keys rotate every 30 days and stay in the JWKS for 30 more days.

**Brute force and enumeration**
- Rate limits per login identity (10/min), per end-user IP on the session API (30/min)
  and per client IP on `/oauth/token`, `/oauth/introspect` and `/revoke` (120/min). Responses are `429` with `Retry-After`.
- Every password or TOTP attempt is counted before it is checked, so even many parallel
  guesses are capped at 5 per lockout window.
- 5 failed attempts lock the account for 15 minutes, then the counter starts over, so an
  attacker can slow a user down but never lock them out for good. While locked, the
  password is not evaluated at all and every attempt answers `401`, so guessing during a
  lockout learns nothing. Password and TOTP failures are counted separately; a correct
  password does not reset TOTP failures.
- Unknown login names get a real-looking session and fail at the password step exactly
  like a wrong password, with the same hashing time. Session state reveals nothing about
  the user until the password is verified.
- TOTP codes are accepted once (replay protection) and only after the password step.
- Email verification codes expire after 15 minutes and burn after 5 wrong tries.

**Tenancy**
- Only instance keys can grant a project to another org, so no tenant can pull another
  tenant's users into its apps. A granted org can leave a project (`DELETE /v1/project-grants/{id}`).
- Org keys only see auth requests for apps their org can use, and get the same answer
  for missing and foreign orgs.
- Logins containing `@` are looked up by email (unique per org), others by username;
  a username may only contain `@` if it is the user's own email.
- Only instance keys (your SaaS backend) can verify emails: they set `email_verified`
  or run the code flow and deliver the code. Tenants' org keys can do neither.
  Your apps should still identify users by `sub` (or `org_id` + email), never by email alone.

**Tokens and sessions**
- `/revoke` on a refresh token ends the whole login, including its access tokens.
- PKCE with S256 is required for public (`spa`, `native`) clients; `plain` is refused.
- `dev_mode` apps (plain-http redirects) can only be created when the engine runs with `IAM_DEV_MODE=true`.
- Changing a password ends all sessions and tokens; changing TOTP ends logins in progress.
  Deleting an org, project, app or grant revokes the affected tokens.
- Access tokens live 5 minutes. Introspection and `/userinfo` report a token inactive
  immediately when the user is locked or deleted or the org loses its grant.
- Refresh tokens rotate on every use. Presenting a used one is treated as theft:
  the whole login (every token in the family) is revoked and an audit event is written.
- Sessions end after 7 days unused and 30 days after login at the latest.
- Authorization codes are single use and expire after 5 minutes. A code is claimed only
  after PKCE and client authentication pass, so a stolen code submitted with a wrong
  verifier cannot burn it; concurrent exchanges cannot both succeed.
- Redirect and login URLs must be https (http only for loopback native apps or in dev
  mode); fragments, credentials and `javascript:`/`data:` schemes are refused.
- Re-entering the password on a session clears its earlier TOTP check.
- Locking a user (`/lock`) revokes their sessions and tokens at once. The automatic
  lockout does not end existing sessions, so failed guesses cannot log a user out.

**Operations**
- `login`-scoped keys for login UIs, optional key expiry, and an audit trail of logins,
  lockouts and every admin change, filterable per org.
- `X-Forwarded-For` is ignored unless `IAM_TRUST_PROXY=true`.
- `/docs` is off unless `IAM_ENABLE_DOCS=true`; it loads Swagger UI with Subresource
  Integrity and never stores your API key in the browser.
- The bootstrap admin key is created on the first start only; deleting it is permanent.
- Rate-limiter memory is capped without ever refusing new keys (idle entries are evicted
  first). The session API is limited per API key and per end-user IP, the management API
  per API key (600/min), `/authorize` per IP, and password hashing runs at most one per CPU.
- `X-End-User-IP` is honoured only on the login API; management calls and their audit
  entries always use the connection's address.
- Mutating requests finish even if the client disconnects, so no change is left half applied.
- `.dockerignore` keeps `.env` and demo state out of image builds.

**Known limits**
- Rate limits are in memory per instance; with several instances behind a load balancer,
  the effective limit is multiplied by the instance count.
- `X-End-User-IP` is trusted from API-key holders on the login API. Only give keys to your own backends.
- Per-tenant quotas: 100k users, 100 projects and 50 API keys per org; 50 apps and 200
  roles per project. Lists are paginated (`?limit=`, max 1000, and `?offset=`).
- Org keys expire (default 90 days, max 365), and deleting a key deletes the keys it created.
- Usernames are ASCII and case-insensitive; email codes are HMAC-protected with a 1-minute cooldown.
- JWT access tokens stay valid for up to 5 minutes after revocation unless your backend
  introspects them. Use introspection for sensitive operations.
- The master key cannot be rotated yet.

## Not yet implemented (next milestones)

- Passkeys/WebAuthn (`go-webauthn/webauthn`, BSD-3)
- Per-org external IdPs / SSO (OIDC/SAML federation) and JIT provisioning
- Org domain verification and email-based org discovery
- Password reset flow and breached-password checks
- Machine users / `client_credentials`, per-org login policy and branding
- Shared (Redis/Postgres) rate limits for multi-instance deployments, master key rotation
- SAML IdP (`zitadel/saml`, Apache-2.0)
