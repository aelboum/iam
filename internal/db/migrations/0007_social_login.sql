-- Google, Microsoft personal, and Microsoft Entra ID login.
--
-- These are ordinary OpenID Connect providers, so they reuse the existing
-- per-org federation subsystem. Two columns record which provider preset an
-- IdP is and, for Entra, which directory (tenant) it is pinned to. The engine
-- computes and validates the issuer from these at configuration time, so an
-- org admin cannot point a "google" or "entra" provider at an arbitrary
-- issuer, and Entra tokens from any other tenant are rejected.
--
-- provider_type: 'oidc' (generic, the existing behaviour and the default for
-- every pre-existing row), 'google', 'microsoft' (personal MSA, the fixed
-- consumers tenant), or 'entra' (one Microsoft Entra directory).
-- tenant: the Entra directory (tenant) GUID; empty for every other type.
ALTER TABLE identity_providers ADD COLUMN provider_type text NOT NULL DEFAULT 'oidc';
ALTER TABLE identity_providers ADD COLUMN tenant text NOT NULL DEFAULT '';
