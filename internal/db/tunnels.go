package db

import (
	"context"
	"fmt"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// UpsertTunnel inserts or updates a tunnel record.
func (db *DB) UpsertTunnel(ctx context.Context, t *models.Tunnel) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if t.Status == string(models.TunnelActive) && t.Subdomain != "" {
		endedAt := t.StartedAt
		if endedAt.IsZero() {
			endedAt = time.Now()
		}
		if _, err := tx.Exec(ctx, `
			UPDATE tunnels
			SET status = 'stopped',
			    ended_at = COALESCE(ended_at, $3)
			WHERE subdomain = $1
			  AND status = 'active'
			  AND id <> $2`,
			t.Subdomain, t.ID, endedAt); err != nil {
			return err
		}
	}

	_, err = tx.Exec(ctx, `
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
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
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
	tunnels, err := scanTunnelRows(rows)
	if err != nil {
		return nil, err
	}
	return dedupeActiveTunnels(tunnels), nil
}

// ListTunnelsByUserAndTeam returns only tunnel sessions for team-owned reserved subdomains.
func (db *DB) ListTunnelsByUserAndTeam(ctx context.Context, userID, teamID, status string) ([]*models.Tunnel, error) {
	query := `
		SELECT t.id, t.user_id, t.subdomain, t.local_port, t.remote_ip, t.status,
		       t.started_at, t.ended_at, t.total_requests, t.total_bytes
		FROM tunnels t
		JOIN reserved_subdomains rs ON rs.subdomain = t.subdomain
		WHERE t.user_id = $1 AND rs.team_id = $2`
	args := []any{userID, teamID}

	if status != "" {
		query += " AND t.status = $3"
		args = append(args, status)
	}
	query += " ORDER BY t.started_at DESC"

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tunnels, err := scanTunnelRows(rows)
	if err != nil {
		return nil, err
	}
	return dedupeActiveTunnels(tunnels), nil
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
	return dedupeActiveTunnels(tunnels), total, nil
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
	tunnels, err := scanTunnelRows(rows)
	if err != nil {
		return nil, err
	}
	return dedupeActiveTunnels(tunnels), nil
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

// DeleteStoppedTunnelsByUser removes all stopped tunnel history rows for a user.
func (db *DB) DeleteStoppedTunnelsByUser(ctx context.Context, userID string) (int64, error) {
	tag, err := db.Pool.Exec(ctx,
		`DELETE FROM tunnels WHERE user_id = $1 AND status = 'stopped'`,
		userID,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteStoppedTunnelsByUserAndTeam removes stopped tunnel history rows for one
// user, limited to tunnels on reserved subdomains owned by the team.
func (db *DB) DeleteStoppedTunnelsByUserAndTeam(ctx context.Context, userID, teamID string) (int64, error) {
	tag, err := db.Pool.Exec(ctx, `
		DELETE FROM tunnels t
		USING reserved_subdomains rs
		WHERE t.subdomain = rs.subdomain
		  AND t.user_id = $1
		  AND t.status = 'stopped'
		  AND rs.team_id = $2`,
		userID, teamID,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// GetTunnelLastSeen returns the most recent ended/start timestamp for a subdomain.
func (db *DB) GetTunnelLastSeen(ctx context.Context, subdomain string) (*time.Time, error) {
	var lastSeen *time.Time
	err := db.Pool.QueryRow(ctx, `
		SELECT MAX(COALESCE(ended_at, started_at))
		FROM tunnels
		WHERE subdomain = $1`, subdomain).Scan(&lastSeen)
	if err != nil {
		return nil, err
	}
	return lastSeen, nil
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

func dedupeActiveTunnels(tunnels []*models.Tunnel) []*models.Tunnel {
	if len(tunnels) < 2 {
		return tunnels
	}

	out := make([]*models.Tunnel, 0, len(tunnels))
	seenActiveSubdomains := make(map[string]struct{}, len(tunnels))

	for _, tunnelRecord := range tunnels {
		if tunnelRecord == nil {
			continue
		}
		if tunnelRecord.Status == string(models.TunnelActive) {
			key := tunnelRecord.Subdomain
			if key == "" {
				key = tunnelRecord.ID
			}
			if _, exists := seenActiveSubdomains[key]; exists {
				continue
			}
			seenActiveSubdomains[key] = struct{}{}
		}
		out = append(out, tunnelRecord)
	}

	return out
}
