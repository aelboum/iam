-- Usernames are case-insensitive: "Admin" and "admin" are the same login.
CREATE UNIQUE INDEX users_org_username_ci_key ON users (org_id, lower(username));

-- API keys remember which key created them. Deleting a key deletes the keys
-- it minted, so a revoked org key cannot leave descendants behind.
ALTER TABLE api_keys ADD COLUMN created_by uuid REFERENCES api_keys (id) ON DELETE CASCADE;

-- Lets the engine enforce a cooldown between verification codes.
ALTER TABLE email_verifications ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
