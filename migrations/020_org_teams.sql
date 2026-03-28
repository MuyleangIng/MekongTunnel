ALTER TABLE org_allocations
    ADD COLUMN IF NOT EXISTS team_limit INT NOT NULL DEFAULT 1;

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL;

UPDATE teams
SET created_by = owner_id
WHERE created_by IS NULL;

CREATE INDEX IF NOT EXISTS idx_teams_org_id ON teams (org_id);
CREATE INDEX IF NOT EXISTS idx_teams_owner_org_id ON teams (owner_id, org_id);
