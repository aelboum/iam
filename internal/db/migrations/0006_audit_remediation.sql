-- Remediation of the security audit of commit 56de7b7.

-- Password resets: a user may hold several outstanding tokens, so a new request
-- no longer invalidates the token already emailed (audit L2). Pending reset
-- tokens are short-lived (30 minutes); recreating the table only means users
-- with a pending reset must request a new one.
DROP TABLE password_resets;
CREATE TABLE password_resets (
    token_hash  text PRIMARY KEY,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX password_resets_user_idx ON password_resets (user_id, created_at DESC);
CREATE INDEX password_resets_expires_idx ON password_resets (expires_at);

-- Expiry indexes for the purge job (audit M7).
CREATE INDEX idp_intents_expires_idx ON idp_intents (expires_at);
CREATE INDEX webauthn_registrations_expires_idx ON webauthn_registrations (expires_at);

-- Federated logins are bound to the browser that started them (audit M3).
-- Intents created before this migration have no binding and cannot be redeemed.
ALTER TABLE idp_intents ADD COLUMN binding_hash text NOT NULL DEFAULT '';

-- Identity provider trust policy (audit M2, M11, D1). Only an instance admin
-- may set trust_email or trust_mfa. JIT user creation is off unless enabled.
ALTER TABLE identity_providers ADD COLUMN trust_email boolean NOT NULL DEFAULT false;
ALTER TABLE identity_providers ADD COLUMN trust_mfa boolean NOT NULL DEFAULT false;
ALTER TABLE identity_providers ADD COLUMN allowed_email_domains text[] NOT NULL DEFAULT '{}';
ALTER TABLE identity_providers ALTER COLUMN auto_create_users SET DEFAULT false;

-- Session assurance details (audit D1, L8).
ALTER TABLE sessions ADD COLUMN idp_trust_mfa boolean NOT NULL DEFAULT false;
ALTER TABLE sessions ADD COLUMN passkey_synced boolean NOT NULL DEFAULT false;
