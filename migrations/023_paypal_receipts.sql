-- 023: PayPal orders and manual payment receipts (ABA / Bakong)
-- Author: Ing Muyleang (អុឹង មួយលៀង)

-- PayPal automated orders
CREATE TABLE IF NOT EXISTS paypal_orders (
    id              TEXT PRIMARY KEY,           -- PayPal order ID (e.g. "5O190127TN364715T")
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan            TEXT NOT NULL,              -- "pro" | "org" | "student"
    amount_usd      NUMERIC(10,2) NOT NULL,
    discount_pct    INT NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'CREATED',  -- CREATED | APPROVED | COMPLETED | VOIDED | FAILED
    capture_id      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS paypal_orders_user_id ON paypal_orders(user_id);
CREATE INDEX IF NOT EXISTS paypal_orders_status  ON paypal_orders(status);

-- Manual payment receipts (ABA Pay / Bakong)
CREATE TABLE IF NOT EXISTS payment_receipts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan            TEXT NOT NULL,
    amount_usd      NUMERIC(10,2) NOT NULL,
    discount_pct    INT NOT NULL DEFAULT 0,
    method          TEXT NOT NULL,              -- "aba" | "bakong"
    receipt_url     TEXT NOT NULL,              -- uploaded file URL
    note            TEXT,                       -- user note
    status          TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
    admin_note      TEXT,
    reviewed_by     UUID REFERENCES users(id),
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS payment_receipts_user_id ON payment_receipts(user_id);
CREATE INDEX IF NOT EXISTS payment_receipts_status  ON payment_receipts(status);
