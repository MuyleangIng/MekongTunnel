-- Server config: single-row table admin can edit via /admin/server-limits
CREATE TABLE IF NOT EXISTS server_config (
    id                            INT PRIMARY KEY DEFAULT 1,
    max_tunnels_per_ip            INT NOT NULL DEFAULT 1000,
    max_total_tunnels             INT NOT NULL DEFAULT 0,
    max_connections_per_minute    INT NOT NULL DEFAULT 0,
    requests_per_second           FLOAT NOT NULL DEFAULT 0,
    max_request_body_bytes        BIGINT NOT NULL DEFAULT 1073741824,
    max_websocket_transfer_bytes  BIGINT NOT NULL DEFAULT 0,
    inactivity_timeout_seconds    INT NOT NULL DEFAULT 7200,
    max_tunnel_lifetime_hours     INT NOT NULL DEFAULT 168,
    ssh_handshake_timeout_seconds INT NOT NULL DEFAULT 30,
    block_duration_minutes        INT NOT NULL DEFAULT 0,
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT server_config_single_row CHECK (id = 1)
);

INSERT INTO server_config (id) VALUES (1) ON CONFLICT DO NOTHING;
