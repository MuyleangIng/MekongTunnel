-- Deploy storage quota for student users.
-- Default quota is 100MB. Students can purchase additional storage
-- in 200MB increments (upgrades stored here).

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS deploy_quota_bytes BIGINT NOT NULL DEFAULT 104857600; -- 100MB default

-- Track purchased storage add-ons
CREATE TABLE IF NOT EXISTS deploy_storage_purchases (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    bytes_added  BIGINT      NOT NULL,   -- e.g. 209715200 = 200MB
    stripe_session_id TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS deploy_storage_purchases_user_idx ON deploy_storage_purchases(user_id);

-- Helper view: user's current quota and usage
CREATE OR REPLACE VIEW deploy_quota_summary AS
SELECT
    u.id                                    AS user_id,
    u.deploy_quota_bytes                    AS quota_bytes,
    COALESCE(SUM(d.size_bytes), 0)          AS used_bytes,
    u.deploy_quota_bytes - COALESCE(SUM(d.size_bytes), 0) AS free_bytes
FROM users u
LEFT JOIN deployments d ON d.user_id = u.id AND d.status = 'active'
GROUP BY u.id, u.deploy_quota_bytes;
