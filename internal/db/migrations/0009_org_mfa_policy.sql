-- Org-level MFA enforcement policy (security follow-up #2). When true, users of
-- this org must have a second factor (TOTP or a passkey) and use it to complete
-- a login; a user with no factor is blocked until they enrol one. Defaults to
-- false so existing orgs are unchanged.
ALTER TABLE orgs ADD COLUMN mfa_required boolean NOT NULL DEFAULT false;
