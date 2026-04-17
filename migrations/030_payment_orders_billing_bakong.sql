-- Extend payment_orders so Bakong can also activate subscription plans.

ALTER TABLE payment_orders
    ADD COLUMN IF NOT EXISTS order_purpose TEXT NOT NULL DEFAULT 'wallet_topup',
    ADD COLUMN IF NOT EXISTS plan_id TEXT,
    ADD COLUMN IF NOT EXISTS discount_pct INTEGER NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'payment_orders_order_purpose_check'
    ) THEN
        ALTER TABLE payment_orders
            ADD CONSTRAINT payment_orders_order_purpose_check
            CHECK (order_purpose IN ('wallet_topup', 'billing_plan'));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS payment_orders_purpose_idx ON payment_orders(order_purpose);
CREATE INDEX IF NOT EXISTS payment_orders_plan_idx ON payment_orders(plan_id);
