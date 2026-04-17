-- Add deployment limits and storage quota fields to plan_configs.
-- Also syncs existing users' deploy_quota_bytes to their plan's base quota
-- (only raises quota, never reduces it, so purchased storage is preserved).

-- ── 1. Update plan_configs JSON ──────────────────────────────────────────────

UPDATE plan_configs SET config = config || '{
  "maxDeployments": 0,
  "deployQuotaMB":  0
}'::jsonb WHERE plan_id = 'free';

UPDATE plan_configs SET config = config || '{
  "maxDeployments": 1,
  "deployQuotaMB":  100
}'::jsonb WHERE plan_id = 'student';

UPDATE plan_configs SET config = config || '{
  "maxDeployments": 3,
  "deployQuotaMB":  512
}'::jsonb WHERE plan_id = 'pro';

UPDATE plan_configs SET config = config || '{
  "maxDeployments": 10,
  "deployQuotaMB":  2048
}'::jsonb WHERE plan_id = 'org';

-- ── 2. Raise deploy_quota_bytes for existing users whose plan grants more ────
-- Only raises the value — purchased extra storage is never taken away.

UPDATE users SET deploy_quota_bytes = GREATEST(deploy_quota_bytes, 0)
    WHERE plan = 'free';

UPDATE users SET deploy_quota_bytes = GREATEST(deploy_quota_bytes, 104857600)   -- 100 MB
    WHERE plan = 'student';

UPDATE users SET deploy_quota_bytes = GREATEST(deploy_quota_bytes, 536870912)   -- 512 MB
    WHERE plan = 'pro';

UPDATE users SET deploy_quota_bytes = GREATEST(deploy_quota_bytes, 2147483648)  -- 2 GB
    WHERE plan = 'org';
