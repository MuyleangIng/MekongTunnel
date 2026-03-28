-- Migration 024: add resubmit / refund fields to payment_receipts
ALTER TABLE payment_receipts
  ADD COLUMN IF NOT EXISTS allow_resubmit BOOLEAN      NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS refund_bank    TEXT,
  ADD COLUMN IF NOT EXISTS refund_amount  NUMERIC(10,2),
  ADD COLUMN IF NOT EXISTS refund_note    TEXT;
