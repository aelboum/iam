-- Performance indexes for the periodic purge and for per-user credential
-- revocation (independent security assessment, 2026-10-29).
--
-- PurgeExpired deletes expired rows from nine tables every ten minutes, but
-- only three of them had an expires_at index: access_tokens, refresh_tokens,
-- sessions, auth_requests, signing_keys and email_verifications were each
-- sequentially scanned on every run. Measured on 200k access_tokens and 100k
-- sessions: 133 ms and 72 ms per run, growing linearly, on the hottest tables
-- in the schema. PurgeAudit had the same problem on audit_events.at.
--
-- Revoking a user's credentials (password change, lock, logout, delete) also
-- scanned sessions and password_resets because the statement compared
-- user_id::text, which cannot use a uuid index. The index below serves the
-- corrected comparison; the statements are fixed in the same change.
--
-- All indexes are additive and built with CREATE INDEX (not CONCURRENTLY) so
-- they stay inside the migration's transaction; on a very large existing
-- database the operator can build them out of band first (see DEPLOYMENT.md).

CREATE INDEX IF NOT EXISTS access_tokens_expires_idx ON access_tokens (expires_at);
CREATE INDEX IF NOT EXISTS refresh_tokens_expires_idx ON refresh_tokens (expires_at);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS auth_requests_expires_idx ON auth_requests (expires_at);
CREATE INDEX IF NOT EXISTS signing_keys_expires_idx ON signing_keys (expires_at);
CREATE INDEX IF NOT EXISTS email_verifications_expires_idx ON email_verifications (expires_at);
CREATE INDEX IF NOT EXISTS audit_events_at_idx ON audit_events (at);

CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);
CREATE INDEX IF NOT EXISTS password_resets_user_expires_idx ON password_resets (user_id, expires_at);

-- users_org_id_username_key (org_id, username) is superseded by the
-- case-insensitive unique index users_org_username_ci_key (org_id,
-- lower(username)) added in 0004: every lookup and every uniqueness rule now
-- uses the latter, so the older constraint only costs writes. It is a
-- constraint, so it must be dropped as one (its index goes with it).
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_org_id_username_key;

-- Bounds guessing of a pending TOTP enrollment code. The pending secret is
-- only known to whoever started the enrollment, but the six-digit code itself
-- was previously verifiable without any cap, so a holder of a management key
-- could brute-force a code and activate TOTP on a user whose secret nobody
-- holds (locking that user out of the second factor). Reset on every new
-- enrollment.
ALTER TABLE users ADD COLUMN totp_enroll_attempts integer NOT NULL DEFAULT 0;
