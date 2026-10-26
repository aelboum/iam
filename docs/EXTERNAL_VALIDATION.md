# External-validation checklist

The production gates in [ROADMAP.md](ROADMAP.md) that source review and local
tests cannot close. Each item needs a non-production external resource or a
human action. Nothing here authorizes production; it is the evidence set a GO
decision requires. Detailed procedures live in [STAGING.md](STAGING.md),
[DEPLOYMENT.md](DEPLOYMENT.md), and [PENTEST.md](PENTEST.md); this is the
executable top-level checklist. Record evidence (logs, run ids, timings) for
every checked box and keep it with the release record.

Use throwaway/test tenants and identities only. Never use customer identities,
production keys, or production data. Do not paste secrets into chat — inject
them as documented in "Secret injection" below.

## 1. Entra application registration and test identities (WS7)

- [ ] A dedicated **test Entra directory** (not production), its **Directory
      (tenant) ID** (GUID) recorded.
- [ ] An **app registration** in that directory: supported account type
      "Accounts in this organizational directory only"; platform **Web**;
      redirect URI `https://<staging-host>/idp/callback`.
- [ ] A **client secret** created for that app (value captured into the secret
      store, never into chat or the repo).
- [ ] A **test user** in that directory.
- [ ] **One out-of-directory identity** (a user from a different directory, or a
      personal Microsoft account) for the cross-tenant rejection check.

## 2. Entra login + explicit cross-tenant rejection (WS7)

- [ ] Configure the IdP via the engine API: `provider_type=entra`,
      `tenant=<directory GUID>`, `client_id`, `client_secret`. Confirm the
      response `callback_url` equals `{issuer}/idp/callback` and no secret is
      returned.
- [ ] Mint the authorization URL and verify host
      `login.microsoftonline.com/<guid>/...`, byte-exact
      `redirect_uri=https://<staging-host>/idp/callback`, `state`, `nonce`,
      PKCE `code_challenge`+`S256`, `scope=openid profile email`.
- [ ] Complete a **human browser login** as the directory test user; verify the
      redeemed session is `authenticated`, `amr=["fed"]`, `idp_checked`, and the
      identity is keyed on `(idp_id, subject)` (not email).
- [ ] **Cross-tenant rejection (mandatory gate):** attempt login with the
      out-of-directory identity; the engine must **reject** it (issuer `iss`
      mismatch, strict equality). Record the rejection as evidence.
- [ ] Live negatives pass: forged `state`, burned intent redeem, wrong
      `browser_binding`.

> **Status (2026-10-26):** sections 1 and 2 were completed against a *local,
> non-production* engine (`http://localhost:8080`, `IAM_DEV_MODE=true`) and passed,
> including the mandatory cross-tenant rejection gate — see ROADMAP.md WS7. The
> checkboxes above remain unchecked because they are the **HTTPS-staging** form of
> the same steps (real TLS host, `IAM_DEV_MODE` off), which must still be run under
> WS9 before they count toward GO.

## 3. Isolated HTTPS staging configuration and secret injection (WS9)

- [ ] Isolated host/cluster at a dedicated DNS name with **TLS 1.2+** terminated
      by a proxy in front of the engine; no production data/keys/traffic.
- [ ] Dedicated **Postgres 17** for staging only.
- [ ] `IAM_ISSUER=https://<staging-host>`; **`IAM_DEV_MODE` unset/false** (the
      engine must then accept only an https issuer — confirm it refuses http).
- [ ] `IAM_WEBAUTHN_RP_ID` / `IAM_WEBAUTHN_ORIGINS` set to the login UI's real
      domain/origin (invalid values fail fast at boot).
- [ ] Proxy trust: set `IAM_TRUST_PROXY=true` and `IAM_TRUSTED_PROXY_HOPS` to the
      exact trusted-hop count if the proxy sets client IP.
- [ ] **Secret injection:** `IAM_MASTER_KEY` (32-byte base64),
      `IAM_BOOTSTRAP_ADMIN_KEY` (≥32 chars), DB credentials, and per-org IdP
      client secrets supplied from the platform secret store as environment
      variables — freshly generated for staging, never reused, never committed,
      never baked into images.
- [ ] Rotate the bootstrap admin key to a managed instance-admin key after boot.

## 4. Migrations, backup/restore, recovery time, rollback (WS9 / WS4)

- [ ] Run [`scripts/migration_rehearsal.sh`](../scripts/migration_rehearsal.sh)
      against the staging engine image; retain its `ALL_PASS` log (fresh install,
      backup/restore to an isolated target, pre-0007 upgrade path).
- [ ] Confirm on the live staging DB: `schema_migrations` lists every migration;
      health check passes; a real login flow succeeds; audit events are written.
- [ ] **Real backup tooling** (not just the rehearsal script): take a backup with
      the environment's actual tooling, restore it onto an **isolated target
      first**, validate schema + data there before any reuse.
- [ ] **Measure and record recovery time** (backup → validated restore) so an
      incident has a known bound.
- [ ] **Rollback criteria rehearsed** (STAGING.md § *Rollback and recovery
      criteria*): abort conditions defined; understand that a binary rollback
      does **not** undo committed schema (0006/0007); schema + binary recovery
      decided together.

## 5. External penetration test and evidence retention

- [ ] Commission an external pentest using [PENTEST.md](PENTEST.md) as the scope
      brief; test against staging, not production.
- [ ] Triage findings; remediate Critical/High/Medium; record dispositions in
      SECURITY.md's residual-risk register.
- [ ] Retain the pentest report and remediation evidence with the release record.

## Supported-scope decision (gates GO)

- [ ] Production scope explicitly states which federated providers are supported.
- [ ] If **personal Microsoft accounts (WS6)** are in scope: resolve the Azure
      access issue and pass a live MSA round trip (same shape as Entra, issuer
      pinned to the consumers tenant). If **not** in scope: declare MSA out of
      scope and drop WS6. GO must not treat a deferred, never-tested provider as
      available.

When every applicable box is checked with retained evidence and all SECURITY.md
residual risks remain accepted, the go/no-go in ROADMAP.md can be revisited.
Until then production is **NO-GO**.
