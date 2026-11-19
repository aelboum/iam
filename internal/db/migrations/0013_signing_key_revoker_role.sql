-- CRYPTO-05 D6: signing-key revocation authorization.
--
-- Possession of database credentials or the ability to run the iamd binary must
-- not by itself grant signing-key revocation authority. Revocation now requires
-- an API key that has been explicitly granted the dedicated revoker capability.
-- The capability is independent of the admin scope and of tenant/project
-- ownership, and it is safe-by-default: every existing and future key is denied
-- until explicitly granted.
ALTER TABLE api_keys
    ADD COLUMN can_revoke_keys boolean NOT NULL DEFAULT false;

-- Break-glass credentials for emergency revocation when no ordinary authorized
-- operator key is usable. A break-glass secret is a distinct, pre-provisioned,
-- high-value credential stored only as a hash (never in plaintext). Using it is
-- an explicit, strongly-audited emergency path, not an anonymous bypass: the
-- operator must still supply an identity and a reason, and every use is recorded
-- in audit_events with break-glass context for mandatory post-event review.
CREATE TABLE break_glass_keys (
    key_hash    text        PRIMARY KEY,          -- secret.Hash(secret), never the secret
    label       text        NOT NULL DEFAULT '',  -- human label for the credential, e.g. "oncall-2026"
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz                        -- set to retire a credential without deleting its history
);
