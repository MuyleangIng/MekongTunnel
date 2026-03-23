-- ============================================================
--  MekongTunnel — Add verify_requests table
--  Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
-- ============================================================

CREATE TABLE IF NOT EXISTS verify_requests (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type          TEXT        NOT NULL,           -- student | teacher | org
    status        TEXT        NOT NULL DEFAULT 'pending', -- pending | reviewing | approved | rejected
    org_name      TEXT        NOT NULL DEFAULT '',
    reject_reason TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_verify_requests_user_id ON verify_requests (user_id);
CREATE INDEX IF NOT EXISTS idx_verify_requests_status  ON verify_requests (status);
CREATE INDEX IF NOT EXISTS idx_verify_requests_type    ON verify_requests (type);
