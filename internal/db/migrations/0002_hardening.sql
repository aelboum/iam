-- Temporary lockout instead of a permanent lock after failed logins.
-- users.locked stays as the manual (admin) lock.
ALTER TABLE users ADD COLUMN locked_until timestamptz;
UPDATE users SET locked = false, failed_logins = 0 WHERE locked AND failed_logins >= 5; -- old automatic locks
ALTER TABLE users ADD COLUMN totp_last_step bigint; -- last accepted TOTP time step (replay protection)

-- Sessions are also created for unknown login names (user_id NULL) so that
-- callers cannot tell which users exist.
ALTER TABLE sessions ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE sessions ADD COLUMN login_name text NOT NULL DEFAULT '';

-- API key scopes and expiry.
ALTER TABLE api_keys ADD COLUMN scope text NOT NULL DEFAULT 'admin'; -- admin | login
ALTER TABLE api_keys ADD COLUMN expires_at timestamptz;

-- Refresh token families: rotation marks tokens used instead of deleting them,
-- so a replayed token is recognised and its whole family revoked.
ALTER TABLE refresh_tokens ADD COLUMN family_id uuid;
UPDATE refresh_tokens SET family_id = id;
ALTER TABLE refresh_tokens ALTER COLUMN family_id SET NOT NULL;
ALTER TABLE refresh_tokens ADD COLUMN used_at timestamptz;
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX access_tokens_refresh_idx ON access_tokens (refresh_token_id);

-- Authorization codes expire sooner than the login window.
ALTER TABLE auth_requests ADD COLUMN code_expires_at timestamptz;

-- Email verification codes (delivered by the SaaS, e.g. by email).
CREATE TABLE email_verifications (
    user_id     uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    email       text        NOT NULL,
    code_hash   text        NOT NULL,
    attempts    integer     NOT NULL DEFAULT 0,
    expires_at  timestamptz NOT NULL
);

-- Security audit trail.
CREATE TABLE audit_events (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    org_id      uuid,
    actor       text        NOT NULL, -- "api_key:<id>", "user:<id>" or "system"
    action      text        NOT NULL,
    target      text        NOT NULL DEFAULT '',
    ip          text        NOT NULL DEFAULT '',
    detail      jsonb       NOT NULL DEFAULT '{}'
);
CREATE INDEX audit_events_org_at_idx ON audit_events (org_id, at DESC);
