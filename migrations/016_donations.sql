CREATE TABLE IF NOT EXISTS donation_submissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255),
  amount VARCHAR(100) NOT NULL,
  currency VARCHAR(20) NOT NULL DEFAULT 'KHR',
  payment_method VARCHAR(50) NOT NULL,
  receipt_url TEXT,
  social_url TEXT,
  message TEXT,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  show_on_home BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
