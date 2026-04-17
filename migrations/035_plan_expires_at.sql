-- Add plan expiry tracking for student/teacher accounts
-- Default: 6 months from approval date
-- Admin can extend via quota request reviews

ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_expires_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_approved_at TIMESTAMPTZ;

-- Index for efficient expiry queries
CREATE INDEX IF NOT EXISTS idx_users_plan_expires_at ON users(plan_expires_at) WHERE plan_expires_at IS NOT NULL;
