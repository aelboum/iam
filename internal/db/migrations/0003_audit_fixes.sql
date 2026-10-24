-- Fixes from the security audit.

-- TOTP failures get their own counter: a correct password must not reset it.
ALTER TABLE users ADD COLUMN mfa_failed_logins integer NOT NULL DEFAULT 0;

-- An email identifies at most one user per org, so email logins are unambiguous.
DROP INDEX users_org_email_idx;
CREATE UNIQUE INDEX users_org_email_key ON users (org_id, lower(email));

-- Authorization codes are claimed atomically so concurrent exchanges cannot both succeed.
ALTER TABLE auth_requests ADD COLUMN code_used_at timestamptz;

-- One-time instance setup markers (e.g. the bootstrap admin key was created).
CREATE TABLE instance_state (
    key         text PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now()
);
