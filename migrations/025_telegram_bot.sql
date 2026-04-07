-- Telegram bot integration: durable chat→user links and short-lived approval sessions.

CREATE TABLE IF NOT EXISTS telegram_links (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    telegram_chat_id    BIGINT      NOT NULL,
    telegram_user_id    BIGINT      NOT NULL,
    telegram_username   TEXT,
    telegram_first_name TEXT,
    telegram_last_name  TEXT,
    status              TEXT        NOT NULL DEFAULT 'active',
    linked_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ,
    unlinked_at         TIMESTAMPTZ
);

ALTER TABLE telegram_links
    DROP CONSTRAINT IF EXISTS telegram_links_telegram_chat_id_key;

CREATE INDEX IF NOT EXISTS idx_telegram_links_user_id ON telegram_links(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_telegram_links_active_chat_id
    ON telegram_links(telegram_chat_id)
    WHERE status = 'active';
CREATE UNIQUE INDEX IF NOT EXISTS idx_telegram_links_active_user_id
    ON telegram_links(user_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS telegram_link_sessions (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    code                TEXT        NOT NULL UNIQUE,
    telegram_chat_id    BIGINT      NOT NULL,
    telegram_user_id    BIGINT      NOT NULL,
    telegram_username   TEXT,
    telegram_first_name TEXT,
    telegram_last_name  TEXT,
    status              TEXT        NOT NULL DEFAULT 'pending',
    approved_user_id    UUID        REFERENCES users(id),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    approved_at         TIMESTAMPTZ,
    cancelled_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_telegram_link_sessions_code ON telegram_link_sessions(code);
