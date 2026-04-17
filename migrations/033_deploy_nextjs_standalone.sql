-- Add nextjs-standalone to the deployments type constraint.

ALTER TABLE deployments
    DROP CONSTRAINT IF EXISTS deployments_type_check;

ALTER TABLE deployments
    ADD CONSTRAINT deployments_type_check
        CHECK (type IN ('static', 'nextjs', 'nextjs-standalone', 'nextjs-api', 'php', 'vue', 'react', 'react-vite'));
