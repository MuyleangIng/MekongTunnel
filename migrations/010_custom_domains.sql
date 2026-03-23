-- Custom domains: users can bring their own domain (e.g. app.mycompany.com)
-- and verify ownership via CNAME or TXT DNS record.
CREATE TABLE IF NOT EXISTS custom_domains (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain              TEXT        NOT NULL UNIQUE,
    -- verification
    status              TEXT        NOT NULL DEFAULT 'pending',  -- pending | verified | failed
    verification_token  TEXT        NOT NULL DEFAULT encode(gen_random_bytes(24), 'hex'),
    -- which tunnel subdomain to route to (set by user after verification)
    target_subdomain    TEXT        DEFAULT NULL,
    -- timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at         TIMESTAMPTZ DEFAULT NULL,
    last_checked_at     TIMESTAMPTZ DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_custom_domains_user   ON custom_domains(user_id);
CREATE INDEX IF NOT EXISTS idx_custom_domains_status ON custom_domains(status);
