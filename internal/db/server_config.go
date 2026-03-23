package db

import (
	"context"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// GetServerConfig returns the single server_config row, seeding it if missing.
func (db *DB) GetServerConfig(ctx context.Context) (*models.ServerConfig, error) {
	// Ensure the seed row exists (migration does this too, but belt-and-suspenders).
	_, _ = db.Pool.Exec(ctx, `INSERT INTO server_config (id) VALUES (1) ON CONFLICT DO NOTHING`)

	row := db.Pool.QueryRow(ctx, `
		SELECT
			max_tunnels_per_ip, max_total_tunnels, max_connections_per_minute,
			requests_per_second, max_request_body_bytes, max_websocket_transfer_bytes,
			inactivity_timeout_seconds, max_tunnel_lifetime_hours,
			ssh_handshake_timeout_seconds, block_duration_minutes, updated_at
		FROM server_config WHERE id = 1
	`)
	return scanServerConfig(row)
}

// UpdateServerConfig overwrites the single server_config row.
func (db *DB) UpdateServerConfig(ctx context.Context, cfg models.ServerConfig) (*models.ServerConfig, error) {
	row := db.Pool.QueryRow(ctx, `
		UPDATE server_config SET
			max_tunnels_per_ip            = $1,
			max_total_tunnels             = $2,
			max_connections_per_minute    = $3,
			requests_per_second           = $4,
			max_request_body_bytes        = $5,
			max_websocket_transfer_bytes  = $6,
			inactivity_timeout_seconds    = $7,
			max_tunnel_lifetime_hours     = $8,
			ssh_handshake_timeout_seconds = $9,
			block_duration_minutes        = $10,
			updated_at                    = NOW()
		WHERE id = 1
		RETURNING
			max_tunnels_per_ip, max_total_tunnels, max_connections_per_minute,
			requests_per_second, max_request_body_bytes, max_websocket_transfer_bytes,
			inactivity_timeout_seconds, max_tunnel_lifetime_hours,
			ssh_handshake_timeout_seconds, block_duration_minutes, updated_at
	`,
		cfg.MaxTunnelsPerIP,
		cfg.MaxTotalTunnels,
		cfg.MaxConnectionsPerMinute,
		cfg.RequestsPerSecond,
		cfg.MaxRequestBodyBytes,
		cfg.MaxWebSocketTransferBytes,
		cfg.InactivityTimeoutSeconds,
		cfg.MaxTunnelLifetimeHours,
		cfg.SSHHandshakeTimeoutSeconds,
		cfg.BlockDurationMinutes,
	)
	return scanServerConfig(row)
}

type serverConfigScanner interface {
	Scan(dest ...any) error
}

func scanServerConfig(row serverConfigScanner) (*models.ServerConfig, error) {
	var c models.ServerConfig
	err := row.Scan(
		&c.MaxTunnelsPerIP,
		&c.MaxTotalTunnels,
		&c.MaxConnectionsPerMinute,
		&c.RequestsPerSecond,
		&c.MaxRequestBodyBytes,
		&c.MaxWebSocketTransferBytes,
		&c.InactivityTimeoutSeconds,
		&c.MaxTunnelLifetimeHours,
		&c.SSHHandshakeTimeoutSeconds,
		&c.BlockDurationMinutes,
		&c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
