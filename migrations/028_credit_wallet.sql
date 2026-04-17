-- Credit wallet system for student deploy feature.
-- $1 USD = 1 credit. 100MB storage = 1 credit/month.
--
-- Lifecycle:
--   active → grace (7 days, email alert) → stopped (30 days) → deleted (admin)

-- ── Wallet ────────────────────────────────────────────────────────────────────
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS credit_balance INTEGER NOT NULL DEFAULT 0;

-- ── Credit transactions (top-ups + deductions) ────────────────────────────────
CREATE TABLE IF NOT EXISTS credit_transactions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount      INTEGER     NOT NULL,           -- positive = top-up, negative = deduction
    balance_after INTEGER   NOT NULL,
    description TEXT        NOT NULL,
    gateway     TEXT,                           -- stripe | aba | bakong | system
    gateway_ref TEXT,                           -- Stripe session ID / ABA tran ID / Bakong ref
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS credit_tx_user_idx ON credit_transactions(user_id);

-- ── Payment orders (pending top-ups) ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS payment_orders (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    gateway         TEXT        NOT NULL CHECK (gateway IN ('stripe', 'aba', 'bakong')),
    amount_usd      NUMERIC(10,2) NOT NULL,
    credits         INTEGER     NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'failed', 'expired')),
    gateway_ref     TEXT,                       -- Stripe checkout session / ABA tran ID / Bakong MD
    qr_code         TEXT,                       -- Bakong KHQR string or ABA QR
    expires_at      TIMESTAMPTZ NOT NULL,
    paid_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS payment_orders_user_idx    ON payment_orders(user_id);
CREATE INDEX IF NOT EXISTS payment_orders_ref_idx     ON payment_orders(gateway_ref);
CREATE INDEX IF NOT EXISTS payment_orders_status_idx  ON payment_orders(status);

-- ── Deploy subscriptions (monthly storage billing) ────────────────────────────
CREATE TABLE IF NOT EXISTS deploy_subscriptions (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    deployment_id       UUID        REFERENCES deployments(id) ON DELETE SET NULL,
    extra_mb            INTEGER     NOT NULL DEFAULT 0,    -- MB purchased above base quota
    credits_per_month   INTEGER     NOT NULL DEFAULT 0,    -- cost in credits/month
    status              TEXT        NOT NULL DEFAULT 'active'
                            CHECK (status IN ('active', 'grace', 'stopped', 'cancelled')),
    renews_at           TIMESTAMPTZ NOT NULL,
    grace_started_at    TIMESTAMPTZ,
    stopped_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS deploy_sub_user_idx   ON deploy_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS deploy_sub_renews_idx ON deploy_subscriptions(renews_at);
CREATE INDEX IF NOT EXISTS deploy_sub_status_idx ON deploy_subscriptions(status);
