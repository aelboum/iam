# Google and Microsoft login

Google, Microsoft personal accounts, and Microsoft Entra ID are configured as
per-organization identity providers through the existing SSO API
(`POST /v1/orgs/{orgID}/idps`). They reuse the whole federation flow —
discovery, strict issuer/audience checks, JWKS signature verification, nonce,
PKCE, the browser binding (`browser_binding`), the SSRF-guarded outbound HTTP
client, JIT-off-by-default, and the instance-admin `trust_email`/`trust_mfa`
policy. See the SSO section of the [README](../README.md) for the login and
redemption contract; nothing about it changes for these providers.

## Design decision

These providers are ordinary OIDC providers, so instead of a separate Microsoft
or Google stack the IdP record gains two fields:

- `provider_type`: `oidc` (generic, default), `google`, `microsoft`, `entra`.
- `tenant`: the Entra directory (tenant) GUID; empty otherwise.

For a preset the **engine computes and pins the issuer** rather than trusting an
issuer typed by an org admin (`internal/authn/providers.go`). This matters
because the OIDC library requires the discovered issuer to equal the configured
issuer and then uses that exact string as the expected `iss`. Pinning the issuer
therefore (a) stops an org admin pointing a `google`/`entra` provider at an
attacker-controlled issuer, and (b) makes an Entra provider reject tokens from
any directory other than its configured tenant (their `iss` differs), which
prevents tenant confusion. Identity is still keyed on `(idp_id, sub)`, never on
email.

## Supported account types

| provider_type | Accounts | Issuer (pinned) |
|---|---|---|
| `google` | Google accounts | `https://accounts.google.com` |
| `microsoft` | Microsoft personal accounts (MSA) only | `https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0` |
| `entra` | one Microsoft Entra directory | `https://login.microsoftonline.com/<tenant-GUID>/v2.0` |
| `oidc` | any generic OIDC provider | admin-supplied `issuer` |

**Not supported in this release:** multi-tenant Microsoft (`common` /
`organizations`). Those use a templated issuer (`.../{tenantid}/v2.0`) that the
strict-equality issuer check cannot validate without a custom verifier and an
explicit allowed-tenant list. Use one `entra` provider per directory instead.

## Configuration

Register the app at the provider, set the redirect URI to the engine's
`callback_url` (returned by the create call: `{issuer}/idp/callback`), then:

```
# Google
POST /v1/orgs/{orgID}/idps
{ "name": "Google", "provider_type": "google",
  "client_id": "...apps.googleusercontent.com", "client_secret": "..." }

# Microsoft personal accounts
POST /v1/orgs/{orgID}/idps
{ "name": "Microsoft", "provider_type": "microsoft",
  "client_id": "<app id>", "client_secret": "..." }

# Microsoft Entra ID (one directory)
POST /v1/orgs/{orgID}/idps
{ "name": "Entra", "provider_type": "entra",
  "tenant": "<directory (tenant) GUID>",
  "client_id": "<app id>", "client_secret": "..." }
```

`issuer` must be omitted for a preset (it is pinned); `tenant` is only for
`entra` and must be the directory GUID, not a domain. `client_secret` is
encrypted at rest and never returned by any read.

## Email and MFA trust (provider-specific policy)

Authentication is not authorization: a successful login proves an identity, not
membership of any org, project or workspace. Existing membership and permission
checks are unchanged, and no product roles are granted.

- Email is **not trusted by default** for any provider. An external email is
  stored unverified and is never used to link to an existing account unless an
  **instance admin** sets `trust_email` (`PUT /v1/orgs/{orgID}/idps/{idpID}/trust`).
  Org admins cannot grant it. Linking is always by `sub`, not by email.
- Recommended policy when trust is enabled: Google's `email_verified` is
  reliable for Google-managed addresses; Microsoft **personal** account email is
  often not verifiable, so prefer leaving `trust_email` off for `microsoft` and
  relying on `sub`; Entra email is as trustworthy as the directory you pin.
- `trust_mfa` is off by default, so a user with local TOTP must still complete
  it after federated login (`amr: fed` alone is not treated as MFA). Only an
  instance admin may set it, per directory.

## Provisioning

Just-in-time user creation is off unless `auto_create_users` is set, and
`allowed_email_domains` (exact domains, no wildcards) can restrict which
identities may be provisioned or linked. A login into a disabled or deleted
provider cannot create a session: delete the IdP (`DELETE …/idps/{idpID}`) to
turn a provider off.

**`allowed_email_domains` requires a verified email.** The domain filter only
admits identities whose token carries `email_verified: true`. Google and
generic OIDC providers that assert `email_verified` work with it; **Microsoft
personal (`microsoft`) and Entra (`entra`) tokens do not carry
`email_verified`, so a domain allowlist on those providers rejects every login
(it fails closed).** This is deliberate: Entra/MSA email is mutable and must not
be treated as verified (the "nOAuth" class of attack). To restrict an Entra
provider, pin it to the directory's tenant GUID (which already limits it to that
directory) rather than relying on an email-domain allowlist.

## Live verification (outstanding)

Creating a provider stores configuration only and makes no network call, so the
configuration, validation, and tenant-pinning paths are covered by automated
tests without credentials. A full login round trip against real Google and
Microsoft tenants requires registered apps and real client secrets and has not
been run in this environment; it remains an explicit pre-production step.
