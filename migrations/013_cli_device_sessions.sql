-- CLI device authentication sessions.
-- Implements the OAuth2-style device flow so `mekong login` can authenticate
-- a user without embedding credentials in the binary.
--
-- Flow:
--   1. CLI  → POST /api/cli/device          → creates a session row, returns session_id + login URL
--   2. User → visits mekongtunnel.dev/cli-auth?session=<id>  → approves via web
--   3. Web  → POST /api/cli/device/approve  → creates an api_token, stores hash here, marks approved_at
--   4. CLI  → GET  /api/cli/device?session_id=<id>           → polls until approved, receives full token once

CREATE TABLE IF NOT EXISTS cli_device_sessions (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- set after the user approves
    user_id      UUID        REFERENCES users(id) ON DELETE CASCADE,
    token_hash   TEXT,           -- SHA-256 of the generated API token
    token_prefix TEXT,           -- first 10 chars for display
    raw_token    TEXT,           -- full token, readable exactly once (cleared after first poll)
    approved_at  TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- clean up expired sessions automatically (run manually / via cron)
CREATE INDEX IF NOT EXISTS cli_device_sessions_expires_idx ON cli_device_sessions(expires_at);
