package db

import (
	"context"
	"fmt"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// UpsertTunnel inserts or updates a tunnel record.
func (db *DB) UpsertTunnel(ctx context.Context, t *models.Tunnel) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO tunnels (id, user_id, subdomain, local_port, remote_ip, status, started_at, ended_at, total_requests, total_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			user_id        = EXCLUDED.user_id,
			subdomain      = EXCLUDED.subdomain,
			local_port     = EXCLUDED.local_port,
			remote_ip      = EXCLUDED.remote_ip,
			status         = EXCLUDED.status,
			started_at     = EXCLUDED.started_at,
			ended_at       = EXCLUDED.ended_at,
			total_requests = EXCLUDED.total_requests,
			total_bytes    = EXCLUDED.total_bytes`,
		t.ID, t.UserID, t.Subdomain, t.LocalPort, t.RemoteIP,
		t.Status, t.StartedAt, t.EndedAt, t.TotalRequests, t.TotalBytes)
	return err
}

// GetTunnelByID fetches a tunnel by its ID.
func (db *DB) GetTunnelByID(ctx context.Context, id string) (*models.Tunnel, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, subdomain, local_port, remote_ip, status,
		       started_at, ended_at, total_requests, total_bytes
		FROM tunnels WHERE id = $1`, id)
	return scanTunnel(row)
}

// ListTunnelsByUser returns tunnels owned by a user, optionally filtered by status.
func (db *DB) ListTunnelsByUser(ctx context.Context, userID string, status string) ([]*models.Tunnel, error) {
	query := `
		SELECT id, user_id, subdomain, local_port, remote_ip, status,
		       started_at, ended_at, total_requests, total_bytes
		FROM tunnels WHERE user_id = $1`
	args := []any{userID}

	if status != "" {
		query += " AND status = $2"
		args = append(args, status)
	}
	query += " ORDER BY started_at DESC"

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTunnelRows(rows)
}

// ListTunnelsByUserPage returns a paginated tunnel history plus the total row count.
func (db *DB) ListTunnelsByUserPage(ctx context.Context, userID string, status string, limit, offset int) ([]*models.Tunnel, int, error) {
	countQuery := `SELECT COUNT(*) FROM tunnels WHERE user_id = $1`
	query := `
		SELECT id, user_id, subdomain, local_port, remote_ip, status,
		       started_at, ended_at, total_requests, total_bytes
		FROM tunnels WHERE user_id = $1`
	args := []any{userID}

	if status != "" {
		countQuery += ` AND status = $2`
		query += ` AND status = $2`
		args = append(args, status)
	}

	var total int
	if err := db.Pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	query += fmt.Sprintf(" ORDER BY started_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	tunnels, err := scanTunnelRows(rows)
	if err != nil {
		return nil, 0, err
	}
	return tunnels, total, nil
}

// ListAllTunnels returns tunnels with optional status filter, paginated.
func (db *DB) ListAllTunnels(ctx context.Context, status string, limit, offset int) ([]*models.Tunnel, error) {
	query := `
		SELECT id, user_id, subdomain, local_port, remote_ip, status,
		       started_at, ended_at, total_requests, total_bytes
		FROM tunnels`
	args := []any{}
	i := 1

	if status != "" {
		query += fmt.Sprintf(" WHERE status = $%d", i)
		args = append(args, status)
		i++
	}
	query += fmt.Sprintf(" ORDER BY started_at DESC LIMIT $%d OFFSET $%d", i, i+1)
	args = append(args, limit, offset)

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTunnelRows(rows)
}

// UpdateTunnelStatus updates the status and optional ended_at for a tunnel.
func (db *DB) UpdateTunnelStatus(ctx context.Context, id, status string, endedAt *time.Time) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE tunnels SET status = $1, ended_at = $2 WHERE id = $3`,
		status, endedAt, id)
	return err
}

// UpdateTunnelStats increments total_requests and total_bytes for a tunnel.
func (db *DB) UpdateTunnelStats(ctx context.Context, id string, requests, bytes int64) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE tunnels
		SET total_requests = total_requests + $1, total_bytes = total_bytes + $2
		WHERE id = $3`,
		requests, bytes, id)
	return err
}

// KillExcessTunnels marks the oldest active tunnels as "stopped" for a user
// when they have more than maxAllowed active tunnels (e.g. after a plan downgrade).
// Returns the number of tunnels stopped.
func (db *DB) KillExcessTunnels(ctx context.Context, userID string, maxAllowed int) (int, error) {
	now := time.Now()
	tag, err := db.Pool.Exec(ctx, `
		UPDATE tunnels SET status = 'stopped', ended_at = $1
		WHERE id IN (
			SELECT id FROM tunnels
			WHERE user_id = $2 AND status = 'active'
			ORDER BY started_at ASC
			OFFSET $3
		)`, now, userID, maxAllowed)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// DeleteTunnel removes a tunnel record.
func (db *DB) DeleteTunnel(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM tunnels WHERE id = $1`, id)
	return err
}

// ─── scan helpers ─────────────────────────────────────────────

func scanTunnel(row interface{ Scan(...any) error }) (*models.Tunnel, error) {
	t := &models.Tunnel{}
	err := row.Scan(
		&t.ID, &t.UserID, &t.Subdomain, &t.LocalPort, &t.RemoteIP, &t.Status,
		&t.StartedAt, &t.EndedAt, &t.TotalRequests, &t.TotalBytes,
	)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func scanTunnelRows(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*models.Tunnel, error) {
	var tunnels []*models.Tunnel
	for rows.Next() {
		t := &models.Tunnel{}
		if err := rows.Scan(
			&t.ID, &t.UserID, &t.Subdomain, &t.LocalPort, &t.RemoteIP, &t.Status,
			&t.StartedAt, &t.EndedAt, &t.TotalRequests, &t.TotalBytes,
		); err != nil {
			return nil, err
		}
		tunnels = append(tunnels, t)
	}
	return tunnels, rows.Err()
}
