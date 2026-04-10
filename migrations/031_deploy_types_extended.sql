-- Expand deployments to support vue, react, react-vite, nextjs-api types.
-- Also adds redeploy tracking and per-plan deployment limits.

-- Drop old type constraint and replace with expanded set
ALTER TABLE deployments
    DROP CONSTRAINT IF EXISTS deployments_type_check;

ALTER TABLE deployments
    ADD CONSTRAINT deployments_type_check
        CHECK (type IN ('static', 'nextjs', 'nextjs-api', 'php', 'vue', 'react', 'react-vite'));

-- Track how many times a deployment has been updated in-place
ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS redeploy_count INT NOT NULL DEFAULT 0;

-- Track last redeploy time
ALTER TABLE deployments
    ADD COLUMN IF NOT EXISTS last_deployed_at TIMESTAMPTZ;

-- Index for expiry cleanup job
CREATE INDEX IF NOT EXISTS deployments_expires_at_idx ON deployments(expires_at)
    WHERE expires_at IS NOT NULL AND status = 'active';
