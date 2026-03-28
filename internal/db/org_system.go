package db

import (
	"context"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// ─── Org membership ───────────────────────────────────────────

// AddOrgMember adds a user to an org with the given role (upserts on conflict).
func (db *DB) AddOrgMember(ctx context.Context, orgID, userID, role string) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO org_members (org_id, user_id, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		orgID, userID, role)
	if err != nil {
		return err
	}
	return db.syncOrganizationMemberCount(ctx, orgID)
}

// RemoveOrgMember removes a user from an org.
func (db *DB) RemoveOrgMember(ctx context.Context, orgID, userID string) error {
	if _, err := db.Pool.Exec(ctx,
		`DELETE FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, userID); err != nil {
		return err
	}
	if _, err := db.Pool.Exec(ctx,
		`DELETE FROM org_allocations WHERE org_id = $1 AND user_id = $2`, orgID, userID); err != nil {
		return err
	}
	if _, err := db.Pool.Exec(ctx,
		`UPDATE users SET provisioned_by_org_id = NULL WHERE id = $1 AND provisioned_by_org_id = $2`, userID, orgID); err != nil {
		return err
	}
	return db.syncOrganizationMemberCount(ctx, orgID)
}

func (db *DB) syncOrganizationMemberCount(ctx context.Context, orgID string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE organizations o
		SET member_count = (
			SELECT COUNT(*)
			FROM org_members om
			WHERE om.org_id = o.id
		) + CASE WHEN o.owner_id IS NULL THEN 0 ELSE 1 END
		WHERE o.id = $1`, orgID)
	return err
}

// GetOrgMembership returns a user's org membership, or an error if not a member.
func (db *DB) GetOrgMembership(ctx context.Context, orgID, userID string) (*models.OrgMember, error) {
	m := &models.OrgMember{}
	err := db.Pool.QueryRow(ctx,
		`SELECT id, org_id, user_id, role, joined_at FROM org_members WHERE org_id = $1 AND user_id = $2`,
		orgID, userID).Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.JoinedAt)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// CountOrgMembers returns the current member count for an org.
func (db *DB) CountOrgMembers(ctx context.Context, orgID string) (int, error) {
	var n int
	err := db.Pool.QueryRow(ctx,
		`SELECT member_count FROM organizations WHERE id = $1`, orgID).Scan(&n)
	return n, err
}

// ListOrgMembers returns all members of an org with user details and allocation.
func (db *DB) ListOrgMembers(ctx context.Context, orgID string) ([]*models.OrgMember, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT om.id, om.org_id, om.user_id, om.role, om.joined_at,
		       u.id, u.email, u.name, u.avatar_url, u.plan, u.provisioned_by_org_id, u.force_password_reset,
		       COALESCE(oa.tunnel_limit, 1),
		       COALESCE(oa.team_limit, 1),
		       COALESCE(oa.subdomain_limit, 0),
		       COALESCE(oa.custom_domain_allowed, false),
		       COALESCE(oa.bandwidth_gb, 1)
		FROM org_members om
		JOIN users u ON u.id = om.user_id
		LEFT JOIN org_allocations oa ON oa.org_id = om.org_id AND oa.user_id = om.user_id
		WHERE om.org_id = $1
		ORDER BY om.joined_at ASC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []*models.OrgMember
	for rows.Next() {
		m := &models.OrgMember{
			User:       &models.User{},
			Allocation: &models.OrgAllocation{},
		}
		if err := rows.Scan(
			&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.JoinedAt,
			&m.User.ID, &m.User.Email, &m.User.Name, &m.User.AvatarURL, &m.User.Plan, &m.User.ProvisionedByOrgID, &m.User.ForcePasswordReset,
			&m.Allocation.TunnelLimit, &m.Allocation.TeamLimit, &m.Allocation.SubdomainLimit,
			&m.Allocation.CustomDomainAllowed, &m.Allocation.BandwidthGB,
		); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// ListOrgMembersPage returns a paginated slice of org members plus the total count.
// limit <= 0 is treated as 100; offset < 0 is treated as 0.
func (db *DB) ListOrgMembersPage(ctx context.Context, orgID string, limit, offset int) ([]*models.OrgMember, int, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM org_members WHERE org_id = $1`, orgID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := db.Pool.Query(ctx, `
		SELECT om.id, om.org_id, om.user_id, om.role, om.joined_at,
		       u.id, u.email, u.name, u.avatar_url, u.plan, u.provisioned_by_org_id, u.force_password_reset,
		       COALESCE(oa.tunnel_limit, 1),
		       COALESCE(oa.team_limit, 1),
		       COALESCE(oa.subdomain_limit, 0),
		       COALESCE(oa.custom_domain_allowed, false),
		       COALESCE(oa.bandwidth_gb, 1)
		FROM org_members om
		JOIN users u ON u.id = om.user_id
		LEFT JOIN org_allocations oa ON oa.org_id = om.org_id AND oa.user_id = om.user_id
		WHERE om.org_id = $1
		ORDER BY om.joined_at ASC
		LIMIT $2 OFFSET $3`, orgID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var members []*models.OrgMember
	for rows.Next() {
		m := &models.OrgMember{
			User:       &models.User{},
			Allocation: &models.OrgAllocation{},
		}
		if err := rows.Scan(
			&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.JoinedAt,
			&m.User.ID, &m.User.Email, &m.User.Name, &m.User.AvatarURL, &m.User.Plan, &m.User.ProvisionedByOrgID, &m.User.ForcePasswordReset,
			&m.Allocation.TunnelLimit, &m.Allocation.TeamLimit, &m.Allocation.SubdomainLimit,
			&m.Allocation.CustomDomainAllowed, &m.Allocation.BandwidthGB,
		); err != nil {
			return nil, 0, err
		}
		members = append(members, m)
	}
	return members, total, rows.Err()
}

// GetMyOrg returns the org a user belongs to (as member or owner).
func (db *DB) GetMyOrg(ctx context.Context, userID string) (*models.Organization, *models.OrgMember, error) {
	// Check if owner
	row := db.Pool.QueryRow(ctx, `
		SELECT id, name, domain, plan, owner_id, status, member_count, active_tunnels, created_at,
		       COALESCE(slug,''), COALESCE(type,'school'), seat_limit, created_by,
		       COALESCE(admin_note,''), status_changed_at, archived_at, approved_verify_request_id,
		       COALESCE(billing_discount_percent, 0), COALESCE(billing_discount_note, '')
		FROM organizations WHERE owner_id = $1 LIMIT 1`, userID)
	org, err := scanOrg(row)
	if err == nil {
		member := &models.OrgMember{OrgID: org.ID, UserID: userID, Role: "owner"}
		return org, member, nil
	}
	// Check if member
	var orgID string
	var memberRole string
	err = db.Pool.QueryRow(ctx,
		`SELECT org_id, role FROM org_members WHERE user_id = $1 LIMIT 1`, userID).
		Scan(&orgID, &memberRole)
	if err != nil {
		return nil, nil, err
	}
	row2 := db.Pool.QueryRow(ctx, `
		SELECT id, name, domain, plan, owner_id, status, member_count, active_tunnels, created_at,
		       COALESCE(slug,''), COALESCE(type,'school'), seat_limit, created_by,
		       COALESCE(admin_note,''), status_changed_at, archived_at, approved_verify_request_id,
		       COALESCE(billing_discount_percent, 0), COALESCE(billing_discount_note, '')
		FROM organizations WHERE id = $1`, orgID)
	org2, err := scanOrg(row2)
	if err != nil {
		return nil, nil, err
	}
	member2 := &models.OrgMember{OrgID: orgID, UserID: userID, Role: memberRole}
	return org2, member2, nil
}

// ─── Org allocations ──────────────────────────────────────────

// UpsertAllocation sets the resource allocation for a member of an org.
func (db *DB) UpsertAllocation(ctx context.Context, orgID, userID string, tunnelLimit, teamLimit, subdomainLimit, bandwidthGB int, customDomain bool, updatedBy string) error {
	var ub *string
	if updatedBy != "" {
		ub = &updatedBy
	}
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO org_allocations (org_id, user_id, tunnel_limit, team_limit, subdomain_limit, custom_domain_allowed, bandwidth_gb, updated_by, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (org_id, user_id) DO UPDATE SET
			tunnel_limit          = EXCLUDED.tunnel_limit,
			team_limit            = EXCLUDED.team_limit,
			subdomain_limit       = EXCLUDED.subdomain_limit,
			custom_domain_allowed = EXCLUDED.custom_domain_allowed,
			bandwidth_gb          = EXCLUDED.bandwidth_gb,
			updated_by            = EXCLUDED.updated_by,
			updated_at            = now()`,
		orgID, userID, tunnelLimit, teamLimit, subdomainLimit, customDomain, bandwidthGB, ub)
	return err
}

// GetAllocation returns the current allocation for a member, or defaults if none.
func (db *DB) GetAllocation(ctx context.Context, orgID, userID string) (*models.OrgAllocation, error) {
	a := &models.OrgAllocation{OrgID: orgID, UserID: userID}
	err := db.Pool.QueryRow(ctx, `
		SELECT id, tunnel_limit, team_limit, subdomain_limit, custom_domain_allowed, bandwidth_gb, updated_by, updated_at
		FROM org_allocations WHERE org_id = $1 AND user_id = $2`, orgID, userID).
		Scan(&a.ID, &a.TunnelLimit, &a.TeamLimit, &a.SubdomainLimit, &a.CustomDomainAllowed, &a.BandwidthGB, &a.UpdatedBy, &a.UpdatedAt)
	if err != nil {
		// Return defaults
		a.TunnelLimit = 1
		a.TeamLimit = 1
		a.SubdomainLimit = 0
		a.BandwidthGB = 1
		return a, nil
	}
	return a, nil
}

// ─── Resource requests ────────────────────────────────────────

// CreateResourceRequest submits a resource request from a member.
func (db *DB) CreateResourceRequest(ctx context.Context, orgID, userID, reqType, reason string, amount int) (*models.ResourceRequest, error) {
	rr := &models.ResourceRequest{}
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO resource_requests (org_id, user_id, type, reason, amount_requested, amount_approved, reviewer_note, last_commented_at)
		VALUES ($1, $2, $3, $4, $5, 0, '', now())
		RETURNING id, org_id, user_id, type, amount_requested, amount_approved, reason, status, reviewer_note, reviewed_by, reviewed_at, resolved_by, resolved_at, last_commented_at, created_at`,
		orgID, userID, reqType, reason, amount).
		Scan(&rr.ID, &rr.OrgID, &rr.UserID, &rr.Type, &rr.AmountRequested, &rr.AmountApproved,
			&rr.Reason, &rr.Status, &rr.ReviewerNote, &rr.ReviewedBy, &rr.ReviewedAt, &rr.ResolvedBy, &rr.ResolvedAt, &rr.LastCommentAt, &rr.CreatedAt)
	return rr, err
}

// ListResourceRequests returns all requests for an org (with user details).
func (db *DB) ListResourceRequests(ctx context.Context, orgID, status string) ([]*models.ResourceRequest, error) {
	query := `
		SELECT rr.id, rr.org_id, rr.user_id, rr.type, rr.amount_requested,
		       rr.amount_approved,
		       rr.reason, rr.status, rr.reviewer_note, rr.reviewed_by, rr.reviewed_at,
		       rr.resolved_by, rr.resolved_at, rr.last_commented_at, rr.created_at,
		       u.name, u.email
		FROM resource_requests rr
		JOIN users u ON u.id = rr.user_id
		WHERE rr.org_id = $1`
	args := []any{orgID}
	if status != "" {
		query += ` AND rr.status = $2`
		args = append(args, status)
	}
	query += ` ORDER BY rr.created_at DESC`
	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.ResourceRequest
	for rows.Next() {
		rr := &models.ResourceRequest{}
		if err := rows.Scan(&rr.ID, &rr.OrgID, &rr.UserID, &rr.Type, &rr.AmountRequested, &rr.AmountApproved,
			&rr.Reason, &rr.Status, &rr.ReviewerNote, &rr.ReviewedBy, &rr.ReviewedAt,
			&rr.ResolvedBy, &rr.ResolvedAt, &rr.LastCommentAt, &rr.CreatedAt,
			&rr.UserName, &rr.UserEmail); err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := db.AttachResourceRequestComments(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ReviewResourceRequest approves or denies a request.
func (db *DB) ReviewResourceRequest(ctx context.Context, id, status, reviewedBy, reviewerNote string, approvedAmount int) error {
	var rb *string
	if reviewedBy != "" {
		rb = &reviewedBy
	}
	var resolvedBy *string
	var resolvedAt *time.Time
	now := time.Now()
	if status == "approved" || status == "denied" {
		resolvedBy = rb
		resolvedAt = &now
	}
	_, err := db.Pool.Exec(ctx, `
		UPDATE resource_requests
		SET status = $1,
		    reviewer_note = $2,
		    reviewed_by = $3,
		    reviewed_at = now(),
		    amount_approved = $4,
		    resolved_by = $5,
		    resolved_at = $6,
		    last_commented_at = now()
		WHERE id = $7`, status, reviewerNote, rb, approvedAmount, resolvedBy, resolvedAt, id)
	return err
}

// GetMyResourceRequests returns all requests submitted by a user.
func (db *DB) GetMyResourceRequests(ctx context.Context, userID string) ([]*models.ResourceRequest, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, org_id, user_id, type, amount_requested, amount_approved, reason, status,
		       reviewer_note, reviewed_by, reviewed_at, resolved_by, resolved_at, last_commented_at, created_at, '', ''
		FROM resource_requests WHERE user_id = $1
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.ResourceRequest
	for rows.Next() {
		rr := &models.ResourceRequest{}
		if err := rows.Scan(&rr.ID, &rr.OrgID, &rr.UserID, &rr.Type, &rr.AmountRequested, &rr.AmountApproved,
			&rr.Reason, &rr.Status, &rr.ReviewerNote, &rr.ReviewedBy, &rr.ReviewedAt,
			&rr.ResolvedBy, &rr.ResolvedAt, &rr.LastCommentAt, &rr.CreatedAt,
			&rr.UserName, &rr.UserEmail); err != nil {
			return nil, err
		}
		out = append(out, rr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := db.AttachResourceRequestComments(ctx, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (db *DB) GetResourceRequestByID(ctx context.Context, id string) (*models.ResourceRequest, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT rr.id, rr.org_id, rr.user_id, rr.type, rr.amount_requested, rr.amount_approved,
		       rr.reason, rr.status, rr.reviewer_note, rr.reviewed_by, rr.reviewed_at,
		       rr.resolved_by, rr.resolved_at, rr.last_commented_at, rr.created_at,
		       u.name, u.email
		FROM resource_requests rr
		JOIN users u ON u.id = rr.user_id
		WHERE rr.id = $1`, id)
	rr := &models.ResourceRequest{}
	if err := row.Scan(&rr.ID, &rr.OrgID, &rr.UserID, &rr.Type, &rr.AmountRequested, &rr.AmountApproved,
		&rr.Reason, &rr.Status, &rr.ReviewerNote, &rr.ReviewedBy, &rr.ReviewedAt,
		&rr.ResolvedBy, &rr.ResolvedAt, &rr.LastCommentAt, &rr.CreatedAt,
		&rr.UserName, &rr.UserEmail); err != nil {
		return nil, err
	}
	if err := db.AttachResourceRequestComments(ctx, []*models.ResourceRequest{rr}); err != nil {
		return nil, err
	}
	return rr, nil
}

func (db *DB) AddResourceRequestComment(ctx context.Context, requestID, userID, authorRole, kind, body string) (*models.ResourceRequestComment, error) {
	var uid *string
	if userID != "" {
		uid = &userID
	}
	comment := &models.ResourceRequestComment{}
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO resource_request_comments (request_id, user_id, author_role, kind, body)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, request_id, user_id, author_role, kind, body, created_at`,
		requestID, uid, authorRole, kind, body).
		Scan(&comment.ID, &comment.RequestID, &comment.UserID, &comment.AuthorRole, &comment.Kind, &comment.Body, &comment.CreatedAt)
	if err != nil {
		return nil, err
	}
	_, _ = db.Pool.Exec(ctx, `UPDATE resource_requests SET last_commented_at = now() WHERE id = $1`, requestID)
	return comment, nil
}

func (db *DB) ListResourceRequestComments(ctx context.Context, requestID string) ([]*models.ResourceRequestComment, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT c.id, c.request_id, c.user_id, c.author_role, c.kind, c.body, c.created_at,
		       COALESCE(u.name, ''), COALESCE(u.email, '')
		FROM resource_request_comments c
		LEFT JOIN users u ON u.id = c.user_id
		WHERE c.request_id = $1
		ORDER BY c.created_at ASC`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var comments []*models.ResourceRequestComment
	for rows.Next() {
		comment := &models.ResourceRequestComment{}
		if err := rows.Scan(&comment.ID, &comment.RequestID, &comment.UserID, &comment.AuthorRole, &comment.Kind, &comment.Body, &comment.CreatedAt,
			&comment.AuthorName, &comment.AuthorEmail); err != nil {
			return nil, err
		}
		comments = append(comments, comment)
	}
	return comments, rows.Err()
}

func (db *DB) AttachResourceRequestComments(ctx context.Context, requests []*models.ResourceRequest) error {
	for _, rr := range requests {
		if rr == nil {
			continue
		}
		comments, err := db.ListResourceRequestComments(ctx, rr.ID)
		if err != nil {
			return err
		}
		rr.Comments = comments
	}
	return nil
}

func (db *DB) CountPendingResourceRequests(ctx context.Context, orgID string) (int, error) {
	var n int
	err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM resource_requests WHERE org_id = $1 AND status IN ('pending', 'needs_discussion')`, orgID).
		Scan(&n)
	return n, err
}

func (db *DB) CountOrgManagers(ctx context.Context, orgID string) (int, error) {
	var n int
	err := db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM org_members
		WHERE org_id = $1 AND role = 'admin'`, orgID).Scan(&n)
	if err != nil {
		return 0, err
	}
	org, err := db.GetOrganizationByID(ctx, orgID)
	if err != nil {
		return 0, err
	}
	if org.OwnerID != nil {
		n++
	}
	return n, nil
}

func (db *DB) ListOrgManagerUserIDs(ctx context.Context, orgID string) ([]string, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT user_id FROM org_members
		WHERE org_id = $1 AND role = 'admin'`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	org, err := db.GetOrganizationByID(ctx, orgID)
	if err == nil && org.OwnerID != nil {
		ids = append(ids, *org.OwnerID)
	}
	return ids, rows.Err()
}

func (db *DB) CountOrgPendingFirstLogin(ctx context.Context, orgID string) (int, error) {
	var n int
	err := db.Pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM org_members om
		JOIN users u ON u.id = om.user_id
		WHERE om.org_id = $1 AND u.force_password_reset = true`, orgID).Scan(&n)
	return n, err
}

// SetForcePasswordReset sets or clears the force_password_reset flag for a user.
func (db *DB) SetForcePasswordReset(ctx context.Context, userID string, value bool) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET force_password_reset = $1 WHERE id = $2`, value, userID)
	return err
}
