-- ============================================================
--  MekongTunnel — Initial Schema
--  Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
-- ============================================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── users ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email            TEXT        NOT NULL UNIQUE,
    name             TEXT        NOT NULL DEFAULT '',
    password_hash    TEXT,
    avatar_url       TEXT        NOT NULL DEFAULT '',
    plan             TEXT        NOT NULL DEFAULT 'free',
    account_type     TEXT        NOT NULL DEFAULT 'personal',
    email_verified   BOOLEAN     NOT NULL DEFAULT false,
    totp_secret      TEXT,
    totp_enabled     BOOLEAN     NOT NULL DEFAULT false,
    is_admin         BOOLEAN     NOT NULL DEFAULT false,
    suspended        BOOLEAN     NOT NULL DEFAULT false,
    github_id        TEXT        UNIQUE,
    github_login     TEXT        NOT NULL DEFAULT '',
    google_id        TEXT        UNIQUE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_users_email       ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_github_id   ON users (github_id) WHERE github_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_google_id   ON users (google_id) WHERE google_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_plan        ON users (plan);
CREATE INDEX IF NOT EXISTS idx_users_is_admin    ON users (is_admin) WHERE is_admin = true;

-- ─── api_tokens ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_tokens (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT        NOT NULL,
    token_hash   TEXT        NOT NULL UNIQUE,
    prefix       TEXT        NOT NULL,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id    ON api_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON api_tokens (token_hash);

-- ─── refresh_tokens ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id    ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON refresh_tokens (token_hash);

-- ─── password_reset_tokens ───────────────────────────────────
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_prt_token_hash ON password_reset_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_prt_user_id    ON password_reset_tokens (user_id);

-- ─── email_verify_tokens ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS email_verify_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evt_token_hash ON email_verify_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_evt_user_id    ON email_verify_tokens (user_id);

-- ─── totp_backup_codes ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT        NOT NULL,
    used_at   TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_totp_backup_user_id ON totp_backup_codes (user_id);

-- ─── tunnels ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tunnels (
    id             TEXT        PRIMARY KEY,
    user_id        UUID        REFERENCES users(id) ON DELETE SET NULL,
    subdomain      TEXT        NOT NULL,
    local_port     INT         NOT NULL,
    remote_ip      TEXT        NOT NULL DEFAULT '',
    status         TEXT        NOT NULL DEFAULT 'active',
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at       TIMESTAMPTZ,
    total_requests BIGINT      NOT NULL DEFAULT 0,
    total_bytes    BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_tunnels_user_id  ON tunnels (user_id);
CREATE INDEX IF NOT EXISTS idx_tunnels_status   ON tunnels (status);
CREATE INDEX IF NOT EXISTS idx_tunnels_subdomain ON tunnels (subdomain);

-- ─── teams ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS teams (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT        NOT NULL,
    type       TEXT        NOT NULL DEFAULT 'project',
    plan       TEXT        NOT NULL DEFAULT 'free',
    owner_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_teams_owner_id ON teams (owner_id);

-- ─── team_members ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS team_members (
    id        UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id   UUID        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role      TEXT        NOT NULL DEFAULT 'member',
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (team_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_team_members_team_id ON team_members (team_id);
CREATE INDEX IF NOT EXISTS idx_team_members_user_id ON team_members (user_id);

-- ─── invitations ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS invitations (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id     UUID        NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    email       TEXT        NOT NULL,
    role        TEXT        NOT NULL DEFAULT 'member',
    token_hash  TEXT        NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_invitations_team_id    ON invitations (team_id);
CREATE INDEX IF NOT EXISTS idx_invitations_email      ON invitations (email);
CREATE INDEX IF NOT EXISTS idx_invitations_token_hash ON invitations (token_hash);

-- ─── organizations ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS organizations (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name           TEXT        NOT NULL,
    domain         TEXT        NOT NULL DEFAULT '',
    plan           TEXT        NOT NULL DEFAULT 'student',
    owner_id       UUID        REFERENCES users(id) ON DELETE SET NULL,
    status         TEXT        NOT NULL DEFAULT 'active',
    member_count   INT         NOT NULL DEFAULT 0,
    active_tunnels INT         NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_orgs_owner_id ON organizations (owner_id);
CREATE INDEX IF NOT EXISTS idx_orgs_status   ON organizations (status);
CREATE INDEX IF NOT EXISTS idx_orgs_domain   ON organizations (domain);

-- ─── blocked_ips ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS blocked_ips (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    ip             TEXT        NOT NULL UNIQUE,
    reason         TEXT        NOT NULL DEFAULT '',
    blocked_by     UUID        REFERENCES users(id) ON DELETE SET NULL,
    violations     INT         NOT NULL DEFAULT 0,
    tunnels_killed INT         NOT NULL DEFAULT 0,
    auto_block     BOOLEAN     NOT NULL DEFAULT false,
    blocked_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    unblocked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip ON blocked_ips (ip);

-- ─── abuse_events ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS abuse_events (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    type       TEXT        NOT NULL,
    ip         TEXT        NOT NULL,
    subdomain  TEXT,
    detail     TEXT        NOT NULL DEFAULT '',
    severity   TEXT        NOT NULL DEFAULT 'low',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_abuse_events_ip       ON abuse_events (ip);
CREATE INDEX IF NOT EXISTS idx_abuse_events_severity ON abuse_events (severity);
CREATE INDEX IF NOT EXISTS idx_abuse_events_created  ON abuse_events (created_at DESC);

-- ─── newsletter_subscribers ──────────────────────────────────
CREATE TABLE IF NOT EXISTS newsletter_subscribers (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT        NOT NULL UNIQUE,
    subscribed_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    unsubscribed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_newsletter_email ON newsletter_subscribers (email);

-- ─── plan_configs ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS plan_configs (
    plan_id    TEXT        PRIMARY KEY,
    config     JSONB       NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID        REFERENCES users(id) ON DELETE SET NULL
);

-- ─── Default plan configs ─────────────────────────────────────
INSERT INTO plan_configs (plan_id, config) VALUES
('free', '{
    "max_tunnels": 1,
    "max_requests_per_min": 60,
    "max_bandwidth_gb": 1,
    "custom_subdomain": false,
    "team_members": 0,
    "price_monthly": 0,
    "price_yearly": 0
}'::jsonb),
('student', '{
    "max_tunnels": 3,
    "max_requests_per_min": 300,
    "max_bandwidth_gb": 10,
    "custom_subdomain": false,
    "team_members": 3,
    "price_monthly": 0,
    "price_yearly": 0
}'::jsonb),
('pro', '{
    "max_tunnels": 10,
    "max_requests_per_min": 1000,
    "max_bandwidth_gb": 100,
    "custom_subdomain": true,
    "team_members": 10,
    "price_monthly": 9,
    "price_yearly": 90
}'::jsonb),
('org', '{
    "max_tunnels": 100,
    "max_requests_per_min": 10000,
    "max_bandwidth_gb": 1000,
    "custom_subdomain": true,
    "team_members": 100,
    "price_monthly": 49,
    "price_yearly": 490
}'::jsonb)
ON CONFLICT (plan_id) DO NOTHING;
