-- Student/Teacher quota increase requests.
-- Users can request more deploy slots, storage, or reserved subdomains.

CREATE TABLE IF NOT EXISTS quota_requests (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type         TEXT        NOT NULL CHECK (type IN ('deployments', 'storage', 'subdomains', 'tunnels', 'extension')),
    reason       TEXT        NOT NULL,
    requested    INT         NOT NULL DEFAULT 1,  -- how many extra units requested
    status       TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied')),
    admin_note   TEXT,
    reviewed_by  UUID        REFERENCES users(id) ON DELETE SET NULL,
    reviewed_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS quota_requests_user_id_idx  ON quota_requests(user_id);
CREATE INDEX IF NOT EXISTS quota_requests_status_idx   ON quota_requests(status);
