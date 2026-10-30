-- MFA backup / recovery codes (security follow-up #3). A user is issued a set of
-- single-use codes they can use in place of their second factor if they lose it.
-- Codes are stored only as HMAC hashes; the plaintext is shown once at creation.
CREATE TABLE mfa_recovery_codes (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    used_at    timestamptz
);

CREATE INDEX mfa_recovery_codes_user_idx ON mfa_recovery_codes (user_id);

-- A recovery code, once accepted in a login, satisfies the second factor for
-- that session (parallel to totp_checked_at).
ALTER TABLE sessions ADD COLUMN recovery_code_checked_at timestamptz;
