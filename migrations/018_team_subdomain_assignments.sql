ALTER TABLE reserved_subdomains
    ADD COLUMN IF NOT EXISTS assigned_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_reserved_subdomains_assigned_user
    ON reserved_subdomains(assigned_user_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'reserved_subdomains_assignment_scope_check'
    ) THEN
        ALTER TABLE reserved_subdomains
            ADD CONSTRAINT reserved_subdomains_assignment_scope_check
            CHECK (
                assigned_user_id IS NULL OR team_id IS NOT NULL
            );
    END IF;
END$$;
