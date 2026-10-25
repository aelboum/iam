# HTTPS staging rehearsal (WS9)

This is the plan for the staging rehearsal that production authorization depends
on. It is **not** evidence of a pass; it defines exactly what to provision and
run so the rehearsal produces retained evidence when an isolated staging host
and the provider credentials exist. Nothing here authorizes production traffic.

Staging exists to re-establish, under real HTTPS and the production
configuration posture, what the local non-production tests established on
`http://localhost` with `IAM_DEV_MODE=true`. The engine refuses an `http` or
private issuer unless dev mode is on (`internal/config/config.go`), so the
localhost round trips could not themselves prove the HTTPS path — that is the
gap this rehearsal closes.

## Prerequisites

All must be **non-production** and disposable:

1. An isolated host or cluster reachable at a dedicated DNS name over TLS
   (for example `iam.staging.example`), with a valid certificate terminated by
   a proxy in front of the engine. No production data, keys, or traffic.
2. A dedicated Postgres 17 instance for staging only.
3. Freshly generated `IAM_MASTER_KEY` (32-byte base64) and
   `IAM_BOOTSTRAP_ADMIN_KEY` (≥32 chars) created for staging and stored in the
   staging secret store — never reused from any other environment.
4. The live-provider registrations, each pointed at the staging callback
   `https://<staging-host>/idp/callback`:
   - **Google** — the WS5 OAuth client, or a staging-specific one, with the
     staging redirect URI added.
   - **Microsoft personal (WS6)** — *currently deferred* (see ROADMAP.md);
     fold in once the Azure app-registration access issue is resolved.
   - **Microsoft Entra (WS7)** — a test directory, app registration, directory
     GUID, a test user, and one out-of-directory identity for the mandatory
     cross-tenant rejection gate.

## Configuration posture (production-like, not dev)

Set on the staging engine, and confirm each at boot:

- `IAM_ISSUER=https://<staging-host>` — the callback is `{issuer}/idp/callback`.
- `IAM_DEV_MODE` **unset / false** — this is the whole point of staging; the
  engine must accept only an `https` issuer.
- `IAM_WEBAUTHN_RP_ID` and `IAM_WEBAUTHN_ORIGINS` set to the staging login UI's
  real domain and origin; invalid values fail fast at boot.
- TLS 1.2+ at the proxy; set `IAM_TRUST_PROXY=true` and
  `IAM_TRUSTED_PROXY_HOPS` to the exact number of trusted hops if the proxy
  sets the client IP.
- Secrets injected from the staging secret store as environment variables,
  never committed or baked into images.

## Rehearsal steps (produce evidence for each)

1. **Migration and recovery.** Run
   [`scripts/migration_rehearsal.sh`](../scripts/migration_rehearsal.sh) against
   the staging engine image (fresh install, backup/restore to an isolated
   target, pre-0007 upgrade path). Retain its `ALL_PASS` log.
2. **Startup posture.** Confirm the engine refuses to start with an `http`
   issuer (dev mode off), and starts cleanly with the `https` issuer. Confirm
   `schema_migrations` lists every migration and the health check passes.
3. **Live Google round trip over HTTPS.** Repeat the WS5 flow against the
   staging issuer: mint the authorization URL and verify host
   `accounts.google.com`, the byte-exact
   `redirect_uri=https://<staging-host>/idp/callback`, `state`, `nonce`, PKCE
   `code_challenge`+`S256`, and `scope=openid profile email`; complete a human
   browser login; verify the redeemed session is `authenticated`, `amr=["fed"]`,
   `idp_checked`, and the identity is keyed on `(idp_id, subject)`. Re-run the
   live negatives (forged state, burned intent, wrong binding).
4. **Live Entra round trip over HTTPS (WS7).** Same shape against the test
   directory, plus the **mandatory cross-tenant rejection gate**: a login
   attempt with an identity outside the configured directory must be rejected
   (issuer mismatch; strict equality).
5. **Microsoft personal (WS6).** Deferred — run once unblocked; same shape as
   Google, issuer pinned to the consumers tenant.
6. **Backup/restore of the staging database** using the environment's real
   backup tooling (not just the rehearsal script), restored to an isolated
   target and validated before any reuse.

## Go / no-go

Staging is complete for pre-production only when steps 1–4 pass with retained
evidence and the Entra cross-tenant rejection is proven live. WS6 may remain
deferred with that fact recorded. Production stays **NO-GO** until the overall
completion criteria in [ROADMAP.md](ROADMAP.md) are met; a staging pass is
pre-production evidence, never production authorization.
