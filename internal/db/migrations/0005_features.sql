-- Password reset tokens (delivered by the SaaS, e.g. by email).
CREATE TABLE password_resets (
    user_id     uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    token_hash  text        NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);

-- Machine users authenticate with client credentials instead of a password.
ALTER TABLE users ADD COLUMN kind text NOT NULL DEFAULT 'human'; -- human | machine
ALTER TABLE users ADD COLUMN client_id text UNIQUE;
ALTER TABLE users ADD COLUMN client_secret_hash text;

-- Per-org external identity providers (OIDC federation, "bring your own SSO").
CREATE TABLE identity_providers (
    id                 uuid PRIMARY KEY,
    org_id             uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name               text        NOT NULL,
    issuer             text        NOT NULL,
    client_id          text        NOT NULL,
    client_secret_enc  bytea       NOT NULL,
    scopes             text[]      NOT NULL DEFAULT '{openid,profile,email}',
    auto_create_users  boolean     NOT NULL DEFAULT true,
    link_by_email      boolean     NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now()
);

-- Links an external identity (idp + subject) to a local user.
CREATE TABLE user_identities (
    idp_id      uuid        NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
    subject     text        NOT NULL,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (idp_id, subject)
);

-- One federated login attempt: from the redirect to the IdP until redeemed.
CREATE TABLE idp_intents (
    id                 uuid PRIMARY KEY,
    idp_id             uuid        NOT NULL REFERENCES identity_providers (id) ON DELETE CASCADE,
    state_hash         text        NOT NULL UNIQUE,
    nonce              text        NOT NULL,
    code_verifier_enc  bytea       NOT NULL,
    return_url         text        NOT NULL,
    user_id            uuid REFERENCES users (id) ON DELETE CASCADE,
    redeem_hash        text UNIQUE,
    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL
);

-- Passkeys (WebAuthn credentials). The library's credential struct is stored as JSON.
CREATE TABLE webauthn_credentials (
    id            text PRIMARY KEY, -- base64url credential id
    user_id       uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name          text        NOT NULL DEFAULT '',
    credential    jsonb       NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_id);

-- Pending passkey registration ceremonies.
CREATE TABLE webauthn_registrations (
    user_id     uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    session     jsonb       NOT NULL,
    expires_at  timestamptz NOT NULL
);

ALTER TABLE sessions ADD COLUMN passkey_checked_at timestamptz;
ALTER TABLE sessions ADD COLUMN idp_checked_at timestamptz;
ALTER TABLE sessions ADD COLUMN webauthn_session jsonb;

-- Shared rate limiting across engine instances (fixed one-minute windows).
CREATE UNLOGGED TABLE rate_limit_windows (
    key           text        NOT NULL,
    window_start  timestamptz NOT NULL,
    hits          integer     NOT NULL DEFAULT 0,
    PRIMARY KEY (key, window_start)
);
