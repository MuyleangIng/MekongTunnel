-- Static site deployments for student plan users.
-- Supports static HTML/CSS/JS, Next.js export, and PHP projects.
-- Each student gets 1 active deployment at a time.

CREATE TABLE IF NOT EXISTS deployments (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subdomain   TEXT        NOT NULL UNIQUE,
    domain      TEXT        NOT NULL,
    type        TEXT        NOT NULL CHECK (type IN ('static', 'nextjs', 'php')),
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'stopped')),
    files_path  TEXT        NOT NULL,
    size_bytes  BIGINT      NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ,
    stopped_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS deployments_user_id_idx ON deployments(user_id);
CREATE INDEX IF NOT EXISTS deployments_status_idx  ON deployments(status);
CREATE INDEX IF NOT EXISTS deployments_subdomain_idx ON deployments(subdomain);
