-- Free trial per-user, newsletter preferences on users, newsletter campaigns, server_config additions

-- Per-user trial
ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ;

-- Per-user newsletter preference (opt-out by default stays subscribed)
ALTER TABLE users ADD COLUMN IF NOT EXISTS newsletter_subscribed BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS newsletter_unsubscribe_token UUID DEFAULT gen_random_uuid();

-- server_config additions
ALTER TABLE server_config ADD COLUMN IF NOT EXISTS free_trial_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE server_config ADD COLUMN IF NOT EXISTS trial_duration_days INT NOT NULL DEFAULT 7;
ALTER TABLE server_config ADD COLUMN IF NOT EXISTS bakong_discount_percent INT NOT NULL DEFAULT 10;

-- Newsletter campaigns (admin-sent broadcasts)
CREATE TABLE IF NOT EXISTS newsletter_campaigns (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject         TEXT NOT NULL,
    body_html       TEXT NOT NULL,
    sent_by         UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    recipient_count INT NOT NULL DEFAULT 0
);
