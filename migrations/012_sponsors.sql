-- ── Sponsors / Support page entries ────────────────────────────────────────────
-- Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
--
-- Stores admin-editable sponsor / support-link entries shown on /sponsor page.
-- Types: 'github' | 'coffee' | 'bank' | 'referral' | 'other'
-- ──────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS sponsors (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    type           TEXT        NOT NULL DEFAULT 'other',
    title          TEXT        NOT NULL,
    description    TEXT        NOT NULL DEFAULT '',
    url            TEXT        NOT NULL DEFAULT '',
    button_text    TEXT        NOT NULL DEFAULT '',
    icon           TEXT        NOT NULL DEFAULT '',
    badge          TEXT        NOT NULL DEFAULT '',
    -- bank-transfer fields (populated when type = 'bank')
    bank_name      TEXT        NOT NULL DEFAULT '',
    account_name   TEXT        NOT NULL DEFAULT '',
    account_number TEXT        NOT NULL DEFAULT '',
    currency       TEXT        NOT NULL DEFAULT '',
    note           TEXT        NOT NULL DEFAULT '',
    -- display
    is_active      BOOLEAN     NOT NULL DEFAULT true,
    sort_order     INTEGER     NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed initial entries
INSERT INTO sponsors (type, title, description, url, button_text, icon, sort_order) VALUES
  ('github',   'GitHub Sponsors',   'Support MekongTunnel on GitHub with a monthly or one-time sponsorship.', 'https://github.com/sponsors/MuyleangIng', 'Sponsor on GitHub',        'github', 1),
  ('coffee',   'Buy Me a Coffee',   'Send a quick tip through Buy Me a Coffee if you want a simple card-friendly option.', 'https://buymeacoffee.com/muyleanging?l=uk', 'Open Buy Me a Coffee', 'coffee', 2),
  ('bank',     'ABA Bank Transfer', 'Local bank transfer via ABA — fastest option if you are in Cambodia.', '', '', '🏦', 3),
  ('referral', 'DigitalOcean',      'Sign up via our referral link — you get $200 in free credits and help keep the server running.', 'https://m.do.co/c/mekongtunnel', 'Get $200 in free credits', '🌊', 4)
ON CONFLICT DO NOTHING;

-- Fill in bank details
UPDATE sponsors SET
    bank_name      = 'ABA Bank (Advanced Bank of Asia)',
    account_name   = 'Ing Muyleang',
    account_number = '600 726 637',
    currency       = 'USD or KHR',
    note           = 'After transferring, feel free to email or open a GitHub issue so I can thank you properly.'
WHERE type = 'bank' AND account_number = '';
