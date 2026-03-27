package db

import (
	"context"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// EnsureServerConfig inserts the singleton config row when it is missing.
func (db *DB) EnsureServerConfig(ctx context.Context) error {
	_, err := db.Pool.Exec(ctx, `INSERT INTO server_config (id) VALUES (1) ON CONFLICT DO NOTHING`)
	return err
}

// GetServerConfig returns the single server_config row.
func (db *DB) GetServerConfig(ctx context.Context) (*models.ServerConfig, error) {
	if db.redis != nil {
		cfg, ok, err := db.redis.GetServerConfig(ctx)
		if err == nil && ok {
			return cfg, nil
		}
	}

	row := db.Pool.QueryRow(ctx, `
		SELECT
			max_tunnels_per_ip, max_total_tunnels, max_connections_per_minute,
			requests_per_second, max_request_body_bytes, max_websocket_transfer_bytes,
			inactivity_timeout_seconds, max_tunnel_lifetime_hours,
			ssh_handshake_timeout_seconds, block_duration_minutes,
			free_trial_enabled, trial_duration_days, bakong_discount_percent,
			announcement_enabled, announcement_text, announcement_color,
			announcement_link, announcement_link_label,
			updated_at
		FROM server_config WHERE id = 1
	`)
	cfg, err := scanServerConfig(row)
	if err != nil {
		return nil, err
	}
	if db.redis != nil {
		_ = db.redis.SetServerConfig(ctx, cfg)
	}
	return cfg, nil
}

// UpdateServerConfig overwrites the single server_config row.
func (db *DB) UpdateServerConfig(ctx context.Context, cfg models.ServerConfig) (*models.ServerConfig, error) {
	if err := db.EnsureServerConfig(ctx); err != nil {
		return nil, err
	}
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
			free_trial_enabled            = $11,
			trial_duration_days           = $12,
			bakong_discount_percent       = $13,
			announcement_enabled          = $14,
			announcement_text             = $15,
			announcement_color            = $16,
			announcement_link             = $17,
			announcement_link_label       = $18,
			updated_at                    = NOW()
		WHERE id = 1
		RETURNING
			max_tunnels_per_ip, max_total_tunnels, max_connections_per_minute,
			requests_per_second, max_request_body_bytes, max_websocket_transfer_bytes,
			inactivity_timeout_seconds, max_tunnel_lifetime_hours,
			ssh_handshake_timeout_seconds, block_duration_minutes,
			free_trial_enabled, trial_duration_days, bakong_discount_percent,
			announcement_enabled, announcement_text, announcement_color,
			announcement_link, announcement_link_label,
			updated_at
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
		cfg.FreeTrialEnabled,
		cfg.TrialDurationDays,
		cfg.BakongDiscountPercent,
		cfg.AnnouncementEnabled,
		cfg.AnnouncementText,
		cfg.AnnouncementColor,
		cfg.AnnouncementLink,
		cfg.AnnouncementLinkLabel,
	)
	updated, err := scanServerConfig(row)
	if err != nil {
		return nil, err
	}
	if db.redis != nil {
		_ = db.redis.SetServerConfig(ctx, updated)
	}
	return updated, nil
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
		&c.FreeTrialEnabled,
		&c.TrialDurationDays,
		&c.BakongDiscountPercent,
		&c.AnnouncementEnabled,
		&c.AnnouncementText,
		&c.AnnouncementColor,
		&c.AnnouncementLink,
		&c.AnnouncementLinkLabel,
		&c.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &c, nil
}
