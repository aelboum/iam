-- CRYPTO-05 durable emergency signing-key revocation (Phase 2).
--
-- Replaces hard deletion as the revocation primitive with a durable lifecycle
-- state plus an authoritative tombstone, so a revoked key cannot be resurrected
-- by a reappearing signing_keys row (restored backup, lagging replica). The
-- tombstone, not row presence, is the authority: ListSigningKeys excludes any id
-- present in revoked_signing_keys.
--
-- Additive and backward compatible: existing rows default to 'ACTIVE' and the
-- key lifecycle is unchanged until a key is revoked. The restore/PITR revocation
-- epoch (owner decision D3) is intentionally NOT part of this migration.

ALTER TABLE signing_keys
    ADD COLUMN state text NOT NULL DEFAULT 'ACTIVE'
        CHECK (state IN ('ACTIVE', 'RETIRING', 'REVOKED')),
    ADD COLUMN revoked_at timestamptz,
    ADD COLUMN revoked_reason text;

-- Authoritative, permanent record of revoked key ids. It has no expires_at and
-- is never listed in PurgedTables, so PurgeExpired can never remove it. A key id
-- present here is never published in the JWKS or used to sign, even if a
-- signing_keys row with the same id reappears.
CREATE TABLE revoked_signing_keys (
    id          text PRIMARY KEY,
    revoked_at  timestamptz NOT NULL DEFAULT now(),
    revoked_by  text        NOT NULL,          -- audit actor convention: "user:<id>", "system", ...
    reason      text        NOT NULL DEFAULT ''
);
