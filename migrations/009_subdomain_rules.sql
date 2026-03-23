-- Reserved subdomains + per-subdomain access control rules
CREATE TABLE IF NOT EXISTS reserved_subdomains (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subdomain   TEXT        NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reserved_subdomains_user ON reserved_subdomains(user_id);

CREATE TABLE IF NOT EXISTS subdomain_rules (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    subdomain_id    UUID        NOT NULL REFERENCES reserved_subdomains(id) ON DELETE CASCADE,
    -- IP allowlist: NULL = allow all
    allowed_ips     TEXT[]      DEFAULT NULL,
    -- User-agent patterns: NULL = allow all
    allowed_agents  TEXT[]      DEFAULT NULL,
    -- Rate limit: 0 = no limit
    rate_limit_rpm  INT         NOT NULL DEFAULT 0,
    -- Max concurrent connections: 0 = no limit
    max_connections INT         NOT NULL DEFAULT 0,
    -- Block Tor/VPN exit nodes (best-effort via known CIDR lists)
    block_tor       BOOLEAN     NOT NULL DEFAULT false,
    -- Require HTTPS redirect
    force_https     BOOLEAN     NOT NULL DEFAULT true,
    -- Custom response headers (JSON object)
    custom_headers  JSONB       DEFAULT '{}',
    -- Enable/disable the rule set
    enabled         BOOLEAN     NOT NULL DEFAULT true,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_subdomain_rules_subdomain ON subdomain_rules(subdomain_id);
