-- Extend resource requests with richer workflow fields
ALTER TABLE resource_requests
    ADD COLUMN IF NOT EXISTS reviewer_note TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS resolved_by UUID REFERENCES users(id),
    ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_commented_at TIMESTAMPTZ NOT NULL DEFAULT now();

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'resource_requests_type_check'
    ) THEN
        ALTER TABLE resource_requests DROP CONSTRAINT resource_requests_type_check;
    END IF;
END $$;

ALTER TABLE resource_requests
    ADD CONSTRAINT resource_requests_type_check
    CHECK (type IN ('tunnel', 'subdomain', 'domain', 'custom_domain', 'team', 'bandwidth', 'plan', 'billing'));

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'resource_requests_status_check'
    ) THEN
        ALTER TABLE resource_requests DROP CONSTRAINT resource_requests_status_check;
    END IF;
END $$;

ALTER TABLE resource_requests
    ADD CONSTRAINT resource_requests_status_check
    CHECK (status IN ('pending', 'approved', 'denied', 'needs_discussion'));

UPDATE resource_requests
SET last_commented_at = created_at
WHERE last_commented_at IS NULL;

CREATE TABLE IF NOT EXISTS resource_request_comments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id   UUID NOT NULL REFERENCES resource_requests(id) ON DELETE CASCADE,
    user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    author_role  TEXT NOT NULL DEFAULT 'member'
                 CHECK (author_role IN ('member', 'org_admin', 'owner', 'admin', 'system')),
    kind         TEXT NOT NULL DEFAULT 'comment'
                 CHECK (kind IN ('comment', 'review_note', 'system')),
    body         TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_resource_request_comments_request_id
    ON resource_request_comments (request_id, created_at ASC);

-- Extend organizations with admin lifecycle metadata
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS admin_note TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS approved_verify_request_id UUID REFERENCES verify_requests(id) ON DELETE SET NULL;

-- Extend verify requests with org approval metadata
ALTER TABLE verify_requests
    ADD COLUMN IF NOT EXISTS requested_org_domain TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS requested_org_seat_limit INT NOT NULL DEFAULT 25,
    ADD COLUMN IF NOT EXISTS approved_org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS approval_note TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_verify_requests_approved_org_id
    ON verify_requests (approved_org_id);
