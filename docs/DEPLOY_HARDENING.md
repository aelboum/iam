# Production deploy-time hardening runbook

A consolidated, verifiable checklist for the four production-hardening
follow-ups that [ROADMAP.md](ROADMAP.md) records as "to be applied at deploy
time": a **stable DNS name** (instead of an ephemeral tunnel), a **managed
secret store**, **database TLS**, and **bootstrap-admin rotation**. It builds on
the base procedure in [DEPLOYMENT.md](DEPLOYMENT.md) and the operational
guidance in [OPERATIONS.md](OPERATIONS.md); it does not replace them. Each
section is a *proposal* with explicit verification and rollback.

> **Status:** planning document. **Nothing in this runbook has been executed.**
> No production or staging host, DNS record, secret store, database, or
> credential has been created, changed, or rotated as a result of this file. The
> steps are written for an authorized operator to carry out at deploy time, each
> under its own explicit go-ahead. These follow-ups do **not** block the external
> penetration test (criterion 12), and applying them does **not** by itself make
> production **GO** — production remains **NO-GO** until criterion 12 is
> completed with evidence and release is explicitly authorized.

Carry the steps out against the real production (or a dedicated pre-production)
host only under separate, explicit authorization. Do not run them against the
shared staging instance or any co-hosted project.

---

## How to use

Apply the four sections in the order given — DNS first (everything else binds to
the stable issuer), then the secret store, then database TLS, then bootstrap
rotation as the last step once the permanent operator key is confirmed working.
Tick the verification box in each section before moving on; if a verification
fails, use that section's rollback and stop.

Legend: **Goal** — what "done" means. **Why** — the risk it closes. **Steps** —
proposed actions (placeholders in brackets). **Verify** — how to confirm it
worked. **Rollback** — how to undo if verification fails.

## 1. Stable DNS name (replace the ephemeral tunnel)

- **Goal.** The issuer is served from a permanent domain you control
  (`https://[auth.example.com]`) with a CA-issued certificate, not a throwaway
  tunnel hostname.
- **Why.** The OIDC issuer, discovery document, JWKS URL, redirect URIs and IdP
  callback are all derived from the issuer origin. A changing hostname breaks
  relying parties and federated callbacks and undermines certificate trust. A
  stable name is a prerequisite for the other three sections.
- **Steps.**
  1. Register / choose the production domain and create a DNS `A`/`AAAA` (or
     `CNAME`) record pointing at the production host, as in DEPLOYMENT.md step 1.
  2. Open ports 80 and 443 to the edge proxy (Caddy) only; keep `iam` and
     `postgres` off any public port.
  3. Let the edge proxy obtain and auto-renew the TLS certificate for the domain.
  4. Set the engine's issuer to `https://[auth.example.com]` and update every
     registered redirect URI and the IdP `callback_url`
     (`{issuer}/idp/callback`) at each external identity provider to match.
- **Verify.**
  - `curl https://[auth.example.com]/healthz` prints `ok`.
  - `/.well-known/openid-configuration` shows
    `"issuer":"https://[auth.example.com]"` and a reachable `jwks_uri` on the
    same origin.
  - The certificate chain validates (no browser/`curl` TLS warning) and a
    renewal is scheduled.
  - [ ] Verified.
- **Rollback.** Keep the prior ingress reachable until the new name verifies; if
  it fails, repoint relying parties and the IdP callback back to the previous
  issuer and investigate before retrying. Do not leave two live issuers in
  normal operation.

## 2. Managed secret store

- **Goal.** `IAM_MASTER_KEY` and all deployment secrets are injected from a
  managed secret store at start, not kept in a plaintext `.env.prod` on disk.
- **Why.** The master key encrypts signing keys, TOTP secrets, IdP client
  secrets, and stored tokens; a file on disk widens its exposure. DEPLOYMENT.md
  already recommends injecting from a secrets manager — this makes it the
  deploy-time default and adds verification.
- **Steps.**
  1. Create the secrets in your chosen managed store ([store name]); generate
     values with `openssl rand` per `.env.prod.example`.
  2. Inject them into the container environment at launch (store-native
     integration or an entrypoint that fetches them), so no secret is written to
     a persisted file or image layer.
  3. Keep `IAM_MASTER_KEY` recoverable from the store with strict access control
     and an audit trail; store it separately from database backups. **If the
     master key is lost, signing keys and TOTP secrets cannot be recovered.**
  4. Restrict read access to the deploy identity only; enable the store's access
     logging.
- **Verify.**
  - No secret value is present in `docker-compose.prod.yml`, the image, shell
    history, or an on-disk `.env.prod` (it stays gitignored and, ideally, absent).
  - The engine starts and `/healthz` is `ok` with secrets sourced only from the
    store.
  - Reading a secret is recorded in the store's audit log.
  - [ ] Verified.
- **Rollback.** Retain the previous secret-injection method until the store path
  verifies. If it fails, revert to the documented `.env.prod --env-file` method
  (DEPLOYMENT.md), confirm `/healthz`, and investigate. **Do not** print or echo
  secret values while debugging.

## 3. Database TLS

- **Goal.** The engine connects to Postgres over TLS with certificate
  verification, even when both run on the same host.
- **Why.** Defence in depth for credentials and tenant data in transit between
  the engine and the database; closes a local-network sniffing path and prepares
  for a future off-host database.
- **Steps.**
  1. Enable TLS on the Postgres server (server certificate + key); for a managed
     database, enable its TLS endpoint.
  2. Provide the CA certificate to the engine and set the connection to require
     TLS with verification (for example `sslmode=verify-full` and `sslrootcert`
     in the DSN, or the equivalent for your driver), using the DNS name on the
     server certificate.
  3. Keep Postgres off any public port; TLS is in addition to network isolation,
     not a replacement for it.
- **Verify.**
  - The engine connects and `/healthz` is `ok` with verification enabled.
  - A connection attempt **without** TLS, or with a bad CA, is refused (confirms
    verification is actually enforced, not merely offered).
  - [ ] Verified.
- **Rollback.** Stage the change in pre-production first. If the verified
  connection fails in production, revert the DSN to the previously working
  setting to restore service, then diagnose the certificate/CA chain offline.
  Record any temporary reversion as an accepted risk until fixed.

## 4. Bootstrap-admin rotation

- **Goal.** The one-time `IAM_BOOTSTRAP_ADMIN_KEY` is removed from the running
  configuration and replaced by an operator-minted instance key, as the final
  deploy step.
- **Why.** The bootstrap key exists only to create the first real key; leaving
  it live is a standing high-privilege credential. This is DEPLOYMENT.md step 5,
  surfaced here as a tracked hardening gate (readiness criterion 11 follow-up).
- **Steps.**
  1. Mint a permanent instance key: `POST /v1/api-keys`
     `{"name":"[ops]","expires_in_days":[90]}`. Store it in the managed secret
     store (§2).
  2. Mint any scoped keys the deployment needs (for example a `login`-scoped key
     for the login UI backend).
  3. Confirm the new operator key works for a representative management call.
  4. Delete the bootstrap key: `DELETE /v1/api-keys/{bootstrap_id}`, then remove
     `IAM_BOOTSTRAP_ADMIN_KEY` from the environment / secret store. It is never
     recreated.
- **Verify.**
  - The new operator key authenticates a management request (for example listing
    keys) successfully.
  - The bootstrap key no longer authenticates (a call with it is rejected).
  - `IAM_BOOTSTRAP_ADMIN_KEY` is absent from the environment and the secret store.
  - [ ] Verified.
- **Rollback.** Do **not** delete the bootstrap key until the replacement key is
  confirmed working (step 3). If the replacement fails verification, keep the
  bootstrap key in place, investigate, and retry; never end a deploy with no
  working instance key.

## Completion

When all four sections verify, record it against readiness criteria 7, 11 and 13
in [ROADMAP.md](ROADMAP.md) (production follow-ups cleared). This hardening is
operational readiness only: it does **not** satisfy criterion 12, and production
stays **NO-GO** until the independent external penetration test is completed with
retained evidence and release is explicitly authorized.
