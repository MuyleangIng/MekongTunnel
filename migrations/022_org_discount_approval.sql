-- Extend org approval flow with contract discount metadata
ALTER TABLE verify_requests
    ADD COLUMN IF NOT EXISTS approved_discount_percent INT NOT NULL DEFAULT 0;

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS billing_discount_percent INT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS billing_discount_note TEXT NOT NULL DEFAULT '';

ALTER TABLE resource_requests
    ADD COLUMN IF NOT EXISTS amount_approved INT NOT NULL DEFAULT 0;

UPDATE verify_requests
SET approved_discount_percent = 0
WHERE approved_discount_percent IS NULL;

UPDATE organizations
SET billing_discount_percent = 0
WHERE billing_discount_percent IS NULL;

UPDATE resource_requests
SET amount_approved = 0
WHERE amount_approved IS NULL;
