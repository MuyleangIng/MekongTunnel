-- Extend wallet orders for Koma QR checkout while preserving legacy manual review rows.

ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS payment_mode TEXT NOT NULL DEFAULT 'manual',
    ADD COLUMN IF NOT EXISTS provider_qr_code TEXT,
    ADD COLUMN IF NOT EXISTS provider_md5 TEXT,
    ADD COLUMN IF NOT EXISTS provider_poll_token TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'payment_orders_payment_mode_check'
    ) THEN
        ALTER TABLE payment_orders
            ADD CONSTRAINT payment_orders_payment_mode_check
            CHECK (payment_mode IN ('manual', 'koma_qr'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS payment_orders_mode_idx ON payment_orders(payment_mode);
