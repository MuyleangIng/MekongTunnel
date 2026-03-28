ALTER TABLE reserved_subdomains
    ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE reserved_subdomains
    ADD COLUMN IF NOT EXISTS team_id UUID REFERENCES teams(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_reserved_subdomains_team ON reserved_subdomains(team_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'reserved_subdomains_owner_check'
    ) THEN
        ALTER TABLE reserved_subdomains
            ADD CONSTRAINT reserved_subdomains_owner_check
            CHECK (
                (user_id IS NOT NULL AND team_id IS NULL) OR
                (user_id IS NULL AND team_id IS NOT NULL)
            );
    END IF;
END$$;

ALTER TABLE custom_domains
    ALTER COLUMN user_id DROP NOT NULL;

ALTER TABLE custom_domains
    ADD COLUMN IF NOT EXISTS team_id UUID REFERENCES teams(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_custom_domains_team ON custom_domains(team_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'custom_domains_owner_check'
    ) THEN
        ALTER TABLE custom_domains
            ADD CONSTRAINT custom_domains_owner_check
            CHECK (
                (user_id IS NOT NULL AND team_id IS NULL) OR
                (user_id IS NULL AND team_id IS NOT NULL)
            );
    END IF;
END$$;
