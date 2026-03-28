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
		fmt.Sprintf(`SELECT id, name, domain, plan, owner_id, status, member_count, active_tunnels, created_at,
		COALESCE(slug,''), COALESCE(type,'school'), seat_limit, created_by,
		COALESCE(admin_note,''), status_changed_at, archived_at, approved_verify_request_id,
		COALESCE(billing_discount_percent, 0), COALESCE(billing_discount_note, '')
		FROM organizations WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
			where, i, i+1), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanOrgRows(rows)
}

func (db *DB) CreateOrganization(ctx context.Context, name, domain, plan, ownerID, orgType string, seatLimit int, createdBy *string) (*models.Organization, error) {
	var oid *string
	if ownerID != "" {
		oid = &ownerID
	}
	slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	initialMembers := 0
	if ownerID != "" {
		initialMembers = 1
	}
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO organizations (name, domain, plan, owner_id, type, seat_limit, created_by, slug, member_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, name, domain, plan, owner_id, status, member_count, active_tunnels, created_at, slug, type, seat_limit, created_by,
		          COALESCE(admin_note,''), status_changed_at, archived_at, approved_verify_request_id,
		          COALESCE(billing_discount_percent, 0), COALESCE(billing_discount_note, '')`,
		name, domain, plan, oid, orgType, seatLimit, createdBy, slug, initialMembers)
	return scanOrg(row)
}

func (db *DB) GetOrganizationByID(ctx context.Context, id string) (*models.Organization, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, name, domain, plan, owner_id, status, member_count, active_tunnels, created_at,
		       COALESCE(slug,''), COALESCE(type,'school'), seat_limit, created_by,
		       COALESCE(admin_note,''), status_changed_at, archived_at, approved_verify_request_id,
		       COALESCE(billing_discount_percent, 0), COALESCE(billing_discount_note, '')
		FROM organizations WHERE id = $1`, id)
	return scanOrg(row)
}

func (db *DB) UpdateOrganizationStatus(ctx context.Context, id, status string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE organizations
		SET status = $1,
		    status_changed_at = now(),
		    archived_at = CASE WHEN $1 = 'archived' THEN now() ELSE NULL END
		WHERE id = $2`, status, id)
	return err
}

func (db *DB) DeleteOrganization(ctx context.Context, id string) error {
	if _, err := db.Pool.Exec(ctx, `UPDATE users SET provisioned_by_org_id = NULL WHERE provisioned_by_org_id = $1`, id); err != nil {
		return err
	}
	_, err := db.Pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, id)
	return err
}

func (db *DB) GetOrgMembers(ctx context.Context, orgID string) ([]*models.OrgMember, error) {
	return db.ListOrgMembers(ctx, orgID)
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
		&o.Status, &o.MemberCount, &o.ActiveTunnels, &o.CreatedAt,
		&o.Slug, &o.Type, &o.SeatLimit, &o.CreatedBy,
		&o.AdminNote, &o.StatusChangedAt, &o.ArchivedAt, &o.ApprovedVerifyRequestID,
		&o.BillingDiscountPercent, &o.BillingDiscountNote)
	if err != nil {
		return nil, err
	}
	return o, nil
}

func (db *DB) UpdateOrgSeatLimit(ctx context.Context, id string, seatLimit int) error {
	_, err := db.Pool.Exec(ctx, `UPDATE organizations SET seat_limit = $1 WHERE id = $2`, seatLimit, id)
	return err
}

func (db *DB) UpdateOrgPlan(ctx context.Context, id, plan string) error {
	_, err := db.Pool.Exec(ctx, `UPDATE organizations SET plan = $1 WHERE id = $2`, plan, id)
	return err
}

func (db *DB) SetOrganizationAdminNote(ctx context.Context, id, adminNote string) error {
	_, err := db.Pool.Exec(ctx, `UPDATE organizations SET admin_note = $1 WHERE id = $2`, adminNote, id)
	return err
}

func (db *DB) SetOrganizationDomain(ctx context.Context, id, domain string) error {
	_, err := db.Pool.Exec(ctx, `UPDATE organizations SET domain = $1 WHERE id = $2`, domain, id)
	return err
}

func (db *DB) SetOrganizationOwner(ctx context.Context, id, ownerID string) error {
	_, err := db.Pool.Exec(ctx, `UPDATE organizations SET owner_id = $1 WHERE id = $2`, ownerID, id)
	return err
}

func (db *DB) SetOrganizationApprovedVerifyRequest(ctx context.Context, id, verifyRequestID string) error {
	_, err := db.Pool.Exec(ctx, `UPDATE organizations SET approved_verify_request_id = $1 WHERE id = $2`, verifyRequestID, id)
	return err
}

func (db *DB) SetOrganizationBillingDiscount(ctx context.Context, id string, percent int, note string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE organizations SET billing_discount_percent = $1, billing_discount_note = $2 WHERE id = $3`,
		percent, note, id)
	return err
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
