package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// ─── Organizations ────────────────────────────────────────────

func (db *DB) ListOrganizations(ctx context.Context, search, plan string, limit, offset int) ([]*models.Organization, error) {
	conditions := []string{"1=1"}
	args := []any{}
	i := 1

	if search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR domain ILIKE $%d)", i, i+1))
		pattern := "%" + search + "%"
		args = append(args, pattern, pattern)
		i += 2
	}
	if plan != "" {
		conditions = append(conditions, fmt.Sprintf("plan = $%d", i))
		args = append(args, plan)
		i++
	}

	where := strings.Join(conditions, " AND ")
	args = append(args, limit, offset)

	rows, err := db.Pool.Query(ctx,
		fmt.Sprintf(`SELECT id, name, domain, plan, owner_id, status, member_count, active_tunnels, created_at
		FROM organizations WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
			where, i, i+1), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanOrgRows(rows)
}

func (db *DB) CreateOrganization(ctx context.Context, name, domain, plan, ownerID string) (*models.Organization, error) {
	var oid *string
	if ownerID != "" {
		oid = &ownerID
	}
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO organizations (name, domain, plan, owner_id)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, domain, plan, owner_id, status, member_count, active_tunnels, created_at`,
		name, domain, plan, oid)
	return scanOrg(row)
}

func (db *DB) GetOrganizationByID(ctx context.Context, id string) (*models.Organization, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, name, domain, plan, owner_id, status, member_count, active_tunnels, created_at
		FROM organizations WHERE id = $1`, id)
	return scanOrg(row)
}

func (db *DB) UpdateOrganizationStatus(ctx context.Context, id, status string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE organizations SET status = $1 WHERE id = $2`, status, id)
	return err
}

func (db *DB) DeleteOrganization(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	return err
}

func (db *DB) GetOrgMembers(ctx context.Context, orgID string) ([]*models.User, error) {
	org, err := db.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if org.OwnerID == nil {
		return []*models.User{}, nil
	}
	rows, err := db.Pool.Query(ctx, `
		SELECT DISTINCT u.id, u.email, u.name, u.avatar_url, u.plan, u.is_admin
		FROM users u
		JOIN team_members tm ON tm.user_id = u.id
		JOIN teams t ON t.id = tm.team_id
		WHERE t.owner_id = $1
		ORDER BY u.name ASC`, *org.OwnerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*models.User
	for rows.Next() {
		u := &models.User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.AvatarURL, &u.Plan, &u.IsAdmin); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// ─── Blocked IPs ──────────────────────────────────────────────

func (db *DB) ListBlockedIPs(ctx context.Context) ([]*models.BlockedIP, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, ip, reason, blocked_by, violations, tunnels_killed, auto_block, blocked_at, unblocked_at
		FROM blocked_ips WHERE unblocked_at IS NULL ORDER BY blocked_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []*models.BlockedIP
	for rows.Next() {
		b := &models.BlockedIP{}
		if err := rows.Scan(&b.ID, &b.IP, &b.Reason, &b.BlockedBy,
			&b.Violations, &b.TunnelsKilled, &b.AutoBlock, &b.BlockedAt, &b.UnblockedAt); err != nil {
			return nil, err
		}
		ips = append(ips, b)
	}
	return ips, rows.Err()
}

func (db *DB) CreateBlockedIP(ctx context.Context, ip, reason string, autoBlock bool, violations, tunnelsKilled int, blockedBy *string) (*models.BlockedIP, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO blocked_ips (ip, reason, auto_block, violations, tunnels_killed, blocked_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (ip) DO UPDATE SET
			reason         = EXCLUDED.reason,
			auto_block     = EXCLUDED.auto_block,
			violations     = EXCLUDED.violations,
			tunnels_killed = EXCLUDED.tunnels_killed,
			blocked_by     = EXCLUDED.blocked_by,
			unblocked_at   = NULL,
			blocked_at     = now()
		RETURNING id, ip, reason, blocked_by, violations, tunnels_killed, auto_block, blocked_at, unblocked_at`,
		ip, reason, autoBlock, violations, tunnelsKilled, blockedBy)
	b := &models.BlockedIP{}
	err := row.Scan(&b.ID, &b.IP, &b.Reason, &b.BlockedBy,
		&b.Violations, &b.TunnelsKilled, &b.AutoBlock, &b.BlockedAt, &b.UnblockedAt)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (db *DB) UnblockIP(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE blocked_ips SET unblocked_at = now() WHERE id = $1`, id)
	return err
}

// ─── Abuse Events ─────────────────────────────────────────────

func (db *DB) ListAbuseEvents(ctx context.Context, severity string, limit int) ([]*models.AbuseEvent, error) {
	query := `
		SELECT id, type, ip, subdomain, detail, severity, created_at
		FROM abuse_events`
	args := []any{}
	i := 1

	if severity != "" {
		query += fmt.Sprintf(" WHERE severity = $%d", i)
		args = append(args, severity)
		i++
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*models.AbuseEvent
	for rows.Next() {
		e := &models.AbuseEvent{}
		if err := rows.Scan(&e.ID, &e.Type, &e.IP, &e.Subdomain,
			&e.Detail, &e.Severity, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func (db *DB) CreateAbuseEvent(ctx context.Context, eventType, ip, subdomain, detail, severity string) error {
	var sub *string
	if subdomain != "" {
		sub = &subdomain
	}
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO abuse_events (type, ip, subdomain, detail, severity)
		VALUES ($1, $2, $3, $4, $5)`,
		eventType, ip, sub, detail, severity)
	return err
}

// ─── Plan configs ─────────────────────────────────────────────

func (db *DB) GetPlanConfigs(ctx context.Context) ([]*models.PlanConfig, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT plan_id, config, updated_at, updated_by FROM plan_configs ORDER BY plan_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var configs []*models.PlanConfig
	for rows.Next() {
		pc := &models.PlanConfig{}
		var rawConfig []byte
		if err := rows.Scan(&pc.PlanID, &rawConfig, &pc.UpdatedAt, &pc.UpdatedBy); err != nil {
			return nil, err
		}
		pc.Config = json.RawMessage(rawConfig)
		configs = append(configs, pc)
	}
	return configs, rows.Err()
}

func (db *DB) UpsertPlanConfig(ctx context.Context, planID string, config map[string]any, updatedBy string) error {
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	var ub *string
	if updatedBy != "" {
		ub = &updatedBy
	}
	now := time.Now()
	_, err = db.Pool.Exec(ctx, `
		INSERT INTO plan_configs (plan_id, config, updated_at, updated_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (plan_id) DO UPDATE SET
			config     = EXCLUDED.config,
			updated_at = EXCLUDED.updated_at,
			updated_by = EXCLUDED.updated_by`,
		planID, raw, now, ub)
	return err
}

// ─── helpers ─────────────────────────────────────────────────

func scanOrg(row interface{ Scan(...any) error }) (*models.Organization, error) {
	o := &models.Organization{}
	err := row.Scan(&o.ID, &o.Name, &o.Domain, &o.Plan, &o.OwnerID,
		&o.Status, &o.MemberCount, &o.ActiveTunnels, &o.CreatedAt)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func scanOrgRows(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]*models.Organization, error) {
	var orgs []*models.Organization
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}
