-- Tenancy -------------------------------------------------------------------

CREATE TABLE orgs (
    id          uuid PRIMARY KEY,
    name        text        NOT NULL,
    slug        text        NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id               uuid PRIMARY KEY,
    org_id           uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    username         text        NOT NULL,
    email            text        NOT NULL,
    email_verified   boolean     NOT NULL DEFAULT false,
    given_name       text        NOT NULL DEFAULT '',
    family_name      text        NOT NULL DEFAULT '',
    password_hash    text,
    totp_secret_enc  bytea,
    totp_verified    boolean     NOT NULL DEFAULT false,
    failed_logins    integer     NOT NULL DEFAULT 0,
    locked           boolean     NOT NULL DEFAULT false,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, username)
);
CREATE INDEX users_org_email_idx ON users (org_id, lower(email));

-- Projects, roles, grants ---------------------------------------------------

CREATE TABLE projects (
    id            uuid PRIMARY KEY,
    owner_org_id  uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name          text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE project_roles (
    project_id    uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    key           text NOT NULL,
    display_name  text NOT NULL DEFAULT '',
    PRIMARY KEY (project_id, key)
);

-- A project grant makes a project (and a subset of its roles) available to another org.
CREATE TABLE project_grants (
    id              uuid PRIMARY KEY,
    project_id      uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    granted_org_id  uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    role_keys       text[]      NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (project_id, granted_org_id)
);

-- A user grant assigns project roles to a user.
CREATE TABLE user_grants (
    id          uuid PRIMARY KEY,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    project_id  uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    role_keys   text[]      NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, project_id)
);

-- OIDC applications (clients) -----------------------------------------------

CREATE TABLE apps (
    id                         uuid PRIMARY KEY,
    project_id                 uuid        NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    name                       text        NOT NULL,
    client_id                  text        NOT NULL UNIQUE,
    client_secret_hash         text,
    app_type                   text        NOT NULL, -- web | spa | native
    auth_method                text        NOT NULL, -- client_secret_basic | client_secret_post | none
    redirect_uris              text[]      NOT NULL DEFAULT '{}',
    post_logout_redirect_uris  text[]      NOT NULL DEFAULT '{}',
    access_token_type          text        NOT NULL DEFAULT 'jwt', -- jwt | bearer
    login_url                  text        NOT NULL,
    dev_mode                   boolean     NOT NULL DEFAULT false,
    created_at                 timestamptz NOT NULL DEFAULT now()
);

-- Management API keys. org_id NULL means an instance-wide admin key.
CREATE TABLE api_keys (
    id            uuid PRIMARY KEY,
    name          text        NOT NULL,
    key_hash      text        NOT NULL UNIQUE,
    org_id        uuid        REFERENCES orgs (id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);

-- Login sessions (headless session API) ---------------------------------------

CREATE TABLE sessions (
    id                   uuid PRIMARY KEY,
    token_hash           text        NOT NULL,
    org_id               uuid        NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    user_id              uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    password_checked_at  timestamptz,
    totp_checked_at      timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    expires_at           timestamptz NOT NULL
);

-- OIDC protocol state ---------------------------------------------------------

CREATE TABLE auth_requests (
    id                     uuid PRIMARY KEY,
    client_id              text        NOT NULL,
    redirect_uri           text        NOT NULL,
    state                  text        NOT NULL DEFAULT '',
    nonce                  text        NOT NULL DEFAULT '',
    scopes                 text[]      NOT NULL DEFAULT '{}',
    response_type          text        NOT NULL,
    response_mode          text        NOT NULL DEFAULT '',
    code_challenge         text        NOT NULL DEFAULT '',
    code_challenge_method  text        NOT NULL DEFAULT '',
    prompt                 text[]      NOT NULL DEFAULT '{}',
    login_hint             text        NOT NULL DEFAULT '',
    max_age_seconds        integer,
    user_id                uuid,
    auth_time              timestamptz,
    amr                    text[]      NOT NULL DEFAULT '{}',
    done                   boolean     NOT NULL DEFAULT false,
    code                   text UNIQUE,
    created_at             timestamptz NOT NULL DEFAULT now(),
    expires_at             timestamptz NOT NULL
);

CREATE TABLE access_tokens (
    id                uuid PRIMARY KEY,
    client_id         text        NOT NULL,
    subject           text        NOT NULL,
    audience          text[]      NOT NULL DEFAULT '{}',
    scopes            text[]      NOT NULL DEFAULT '{}',
    refresh_token_id  uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL
);
CREATE INDEX access_tokens_subject_client_idx ON access_tokens (subject, client_id);

CREATE TABLE refresh_tokens (
    id               uuid PRIMARY KEY,
    token_hash       text        NOT NULL UNIQUE,
    client_id        text        NOT NULL,
    subject          text        NOT NULL,
    audience         text[]      NOT NULL DEFAULT '{}',
    scopes           text[]      NOT NULL DEFAULT '{}',
    amr              text[]      NOT NULL DEFAULT '{}',
    auth_time        timestamptz NOT NULL,
    access_token_id  uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL
);
CREATE INDEX refresh_tokens_subject_client_idx ON refresh_tokens (subject, client_id);

-- Token signing keys. Private keys are encrypted with the master key.
CREATE TABLE signing_keys (
    id               text PRIMARY KEY,
    algorithm        text        NOT NULL,
    private_key_enc  bytea       NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    rotate_at        timestamptz NOT NULL, -- stop signing with it after this
    expires_at       timestamptz NOT NULL  -- drop from JWKS after this
);
