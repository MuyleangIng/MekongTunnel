-- Extend organizations table with org-system columns
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS slug       TEXT,
    ADD COLUMN IF NOT EXISTS type       TEXT NOT NULL DEFAULT 'school',
    ADD COLUMN IF NOT EXISTS seat_limit INT  NOT NULL DEFAULT 100,
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id);

-- Generate slugs for any existing orgs
UPDATE organizations
SET slug = LOWER(REGEXP_REPLACE(REGEXP_REPLACE(name, '[^a-zA-Z0-9]+', '-', 'g'), '^-|-$', '', 'g'))
WHERE slug IS NULL;

-- Extend users table
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS provisioned_by_org_id UUID REFERENCES organizations(id),
    ADD COLUMN IF NOT EXISTS force_password_reset   BOOLEAN NOT NULL DEFAULT false;

-- Org members
CREATE TABLE IF NOT EXISTS org_members (
    id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id   UUID NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
    role      TEXT NOT NULL DEFAULT 'member'
              CHECK (role IN ('owner', 'admin', 'member')),
    joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, user_id)
);

-- Resource allocations per org member
CREATE TABLE IF NOT EXISTS org_allocations (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id               UUID NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
    tunnel_limit          INT     NOT NULL DEFAULT 1,
    subdomain_limit       INT     NOT NULL DEFAULT 0,
    custom_domain_allowed BOOLEAN NOT NULL DEFAULT false,
    bandwidth_gb          INT     NOT NULL DEFAULT 1,
    updated_by            UUID REFERENCES users(id),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, user_id)
);

-- Resource requests from members to org admins
CREATE TABLE IF NOT EXISTS resource_requests (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id          UUID NOT NULL REFERENCES users(id)         ON DELETE CASCADE,
    type             TEXT NOT NULL CHECK (type IN ('tunnel', 'subdomain', 'domain', 'bandwidth')),
    amount_requested INT  NOT NULL DEFAULT 1,
    reason           TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'approved', 'denied')),
    reviewed_by      UUID REFERENCES users(id),
    reviewed_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_org_members_org_id       ON org_members (org_id);
CREATE INDEX IF NOT EXISTS idx_org_members_user_id      ON org_members (user_id);
CREATE INDEX IF NOT EXISTS idx_resource_requests_org_id ON resource_requests (org_id);
CREATE INDEX IF NOT EXISTS idx_resource_requests_status ON resource_requests (status);
