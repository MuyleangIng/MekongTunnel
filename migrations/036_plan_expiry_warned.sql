-- Track when expiry warning email was last sent so we don't spam the user.
ALTER TABLE users ADD COLUMN IF NOT EXISTS plan_expiry_warned_at TIMESTAMPTZ;
