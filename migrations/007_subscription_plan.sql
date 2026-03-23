-- Add subscription_plan to track the plan from Stripe billing separately from active plan.
-- This allows users with both a Stripe subscription and a verified plan to switch between them.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS subscription_plan TEXT NOT NULL DEFAULT '';
