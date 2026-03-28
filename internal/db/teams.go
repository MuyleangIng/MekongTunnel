package db

import (
	"context"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// ─── Teams ────────────────────────────────────────────────────

func (db *DB) CreateTeam(ctx context.Context, name, teamType, plan, ownerID string) (*models.Team, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO teams (name, type, plan, owner_id, created_by)
		VALUES ($1, $2, $3, $4, $4)
		RETURNING id, name, type, plan, owner_id, org_id, created_by, created_at`,
		name, teamType, plan, ownerID)
	t := &models.Team{}
	err := row.Scan(&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.OrgID, &t.CreatedBy, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (db *DB) CreateOrgTeam(ctx context.Context, name, teamType, plan, ownerID, orgID, createdBy string) (*models.Team, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO teams (name, type, plan, owner_id, org_id, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, name, type, plan, owner_id, org_id, created_by, created_at`,
		name, teamType, plan, ownerID, orgID, createdBy)
	t := &models.Team{}
	err := row.Scan(&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.OrgID, &t.CreatedBy, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (db *DB) GetTeamByID(ctx context.Context, id string) (*models.Team, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, name, type, plan, owner_id, org_id, created_by, created_at FROM teams WHERE id = $1`, id)
	t := &models.Team{}
	err := row.Scan(&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.OrgID, &t.CreatedBy, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (db *DB) GetTeamByOwner(ctx context.Context, ownerID string) (*models.Team, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, name, type, plan, owner_id, org_id, created_by, created_at FROM teams WHERE owner_id = $1 ORDER BY created_at ASC LIMIT 1`, ownerID)
	t := &models.Team{}
	err := row.Scan(&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.OrgID, &t.CreatedBy, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (db *DB) ListTeamsByOwner(ctx context.Context, ownerID string) ([]*models.Team, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, name, type, plan, owner_id, org_id, created_by, created_at FROM teams
		WHERE owner_id = $1 ORDER BY created_at ASC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var teams []*models.Team
	for rows.Next() {
		t := &models.Team{}
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.OrgID, &t.CreatedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		teams = append(teams, t)
	}
	return teams, rows.Err()
}

func (db *DB) CountTeamsByOwner(ctx context.Context, ownerID string) (int, error) {
	var count int
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM teams WHERE owner_id = $1 AND org_id IS NULL`, ownerID).Scan(&count)
	return count, err
}

func (db *DB) CountOrgTeamsByOwner(ctx context.Context, orgID, ownerID string) (int, error) {
	var count int
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM teams WHERE owner_id = $1 AND org_id = $2`, ownerID, orgID).Scan(&count)
	return count, err
}

func (db *DB) RenameTeam(ctx context.Context, id, name string) error {
	_, err := db.Pool.Exec(ctx, `UPDATE teams SET name = $1 WHERE id = $2`, name, id)
	return err
}

func (db *DB) DeleteTeam(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM teams WHERE id = $1`, id)
	return err
}

// ─── Team members ─────────────────────────────────────────────

func (db *DB) AddTeamMember(ctx context.Context, teamID, userID, role string) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO team_members (team_id, user_id, role)
		VALUES ($1, $2, $3)
		ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		teamID, userID, role)
	return err
}

func (db *DB) RemoveTeamMember(ctx context.Context, teamID, userID string) error {
	if _, err := db.Pool.Exec(ctx,
		`UPDATE reserved_subdomains
		 SET assigned_user_id = NULL
		 WHERE team_id = $1 AND assigned_user_id = $2`,
		teamID, userID); err != nil {
		return err
	}
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM team_members WHERE team_id = $1 AND user_id = $2`, teamID, userID)
	return err
}

func (db *DB) ListTeamMembers(ctx context.Context, teamID string) ([]*models.TeamMember, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT tm.id, tm.team_id, tm.user_id, tm.role, tm.joined_at,
		       u.id, u.email, u.name, u.avatar_url, u.plan
		FROM team_members tm
		JOIN users u ON u.id = tm.user_id
		WHERE tm.team_id = $1
		ORDER BY tm.joined_at ASC`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []*models.TeamMember
	for rows.Next() {
		m := &models.TeamMember{User: &models.User{}}
		if err := rows.Scan(
			&m.ID, &m.TeamID, &m.UserID, &m.Role, &m.JoinedAt,
			&m.User.ID, &m.User.Email, &m.User.Name, &m.User.AvatarURL, &m.User.Plan,
		); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// ─── Invitations ──────────────────────────────────────────────

func (db *DB) CreateInvitation(ctx context.Context, teamID, email, role, tokenHash string, expiresAt time.Time) (*models.Invitation, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO invitations (team_id, email, role, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, team_id, email, role, token_hash, created_at, expires_at, accepted_at`,
		teamID, email, role, tokenHash, expiresAt)
	inv := &models.Invitation{}
	err := row.Scan(&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.TokenHash,
		&inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt)
	if err != nil {
		return nil, err
	}
	return inv, nil
}

func (db *DB) GetInvitationByToken(ctx context.Context, tokenHash string) (*models.Invitation, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, team_id, email, role, token_hash, created_at, expires_at, accepted_at
		FROM invitations WHERE token_hash = $1`, tokenHash)
	inv := &models.Invitation{}
	err := row.Scan(&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.TokenHash,
		&inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt)
	if err != nil {
		return nil, err
	}
	return inv, nil
}

func (db *DB) AcceptInvitation(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE invitations SET accepted_at = now() WHERE id = $1`, id)
	return err
}

// ListTeamsAsMember returns all teams where the user is a member but not the owner.
func (db *DB) ListTeamsAsMember(ctx context.Context, userID string) ([]*models.Team, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT t.id, t.name, t.type, t.plan, t.owner_id, t.org_id, t.created_by, t.created_at, tm.role
		FROM team_members tm
		JOIN teams t ON t.id = tm.team_id
		WHERE tm.user_id = $1 AND t.owner_id != $1
		ORDER BY tm.joined_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var teams []*models.Team
	for rows.Next() {
		t := &models.Team{}
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.OrgID, &t.CreatedBy, &t.CreatedAt, &t.Role); err != nil {
			return nil, err
		}
		teams = append(teams, t)
	}
	return teams, rows.Err()
}

func (db *DB) ListTeamsByOrg(ctx context.Context, orgID string) ([]*models.Team, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT t.id, t.name, t.type, t.plan, t.owner_id, t.org_id, t.created_by, t.created_at,
		       COALESCE((SELECT COUNT(*) FROM team_members tm WHERE tm.team_id = t.id), 0),
		       u.id, u.email, u.name, u.avatar_url, u.plan
		FROM teams t
		JOIN users u ON u.id = t.owner_id
		WHERE t.org_id = $1
		ORDER BY t.created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var teams []*models.Team
	for rows.Next() {
		t := &models.Team{Owner: &models.User{}}
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.OrgID, &t.CreatedBy, &t.CreatedAt,
			&t.MemberCount,
			&t.Owner.ID, &t.Owner.Email, &t.Owner.Name, &t.Owner.AvatarURL, &t.Owner.Plan,
		); err != nil {
			return nil, err
		}
		teams = append(teams, t)
	}
	return teams, rows.Err()
}

// GetPendingInvitationsByEmail returns open invitations sent to the given email address,
// including the team name from a JOIN so the UI can show which team is inviting.
func (db *DB) GetPendingInvitationsByEmail(ctx context.Context, email string) ([]*models.Invitation, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT i.id, i.team_id, i.email, i.role, i.token_hash, i.created_at, i.expires_at, i.accepted_at, t.name
		FROM invitations i
		JOIN teams t ON t.id = i.team_id
		WHERE i.email = $1 AND i.accepted_at IS NULL AND i.expires_at > now()
		ORDER BY i.created_at DESC`, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var invs []*models.Invitation
	for rows.Next() {
		inv := &models.Invitation{}
		if err := rows.Scan(&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.TokenHash,
			&inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt, &inv.TeamName); err != nil {
			return nil, err
		}
		invs = append(invs, inv)
	}
	return invs, rows.Err()
}

// LeaveTeam removes the user from a team they joined (not the owner).
func (db *DB) LeaveTeam(ctx context.Context, teamID, userID string) error {
	if _, err := db.Pool.Exec(ctx,
		`UPDATE reserved_subdomains
		 SET assigned_user_id = NULL
		 WHERE team_id = $1 AND assigned_user_id = $2`,
		teamID, userID); err != nil {
		return err
	}
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM team_members WHERE team_id = $1 AND user_id = $2`, teamID, userID)
	return err
}

// GetTeamMembership returns a member's record in a team, or an error if not a member.
func (db *DB) GetTeamMembership(ctx context.Context, teamID, userID string) (*models.TeamMember, error) {
	m := &models.TeamMember{User: &models.User{}}
	err := db.Pool.QueryRow(ctx, `
		SELECT tm.id, tm.team_id, tm.user_id, tm.role, tm.joined_at,
		       u.id, u.email, u.name, u.avatar_url, u.plan
		FROM team_members tm
		JOIN users u ON u.id = tm.user_id
		WHERE tm.team_id = $1 AND tm.user_id = $2`, teamID, userID).Scan(
		&m.ID, &m.TeamID, &m.UserID, &m.Role, &m.JoinedAt,
		&m.User.ID, &m.User.Email, &m.User.Name, &m.User.AvatarURL, &m.User.Plan,
	)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// UpdateMemberRole changes an existing team member's role.
func (db *DB) UpdateMemberRole(ctx context.Context, teamID, userID, role string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE team_members SET role = $1 WHERE team_id = $2 AND user_id = $3`,
		role, teamID, userID)
	return err
}

// CountTeamMembers returns the number of members in a team.
func (db *DB) CountTeamMembers(ctx context.Context, teamID string) (int, error) {
	var n int
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM team_members WHERE team_id = $1`, teamID).Scan(&n)
	return n, err
}

func (db *DB) GetInvitationByID(ctx context.Context, id string) (*models.Invitation, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, team_id, email, role, token_hash, created_at, expires_at, accepted_at
		FROM invitations WHERE id = $1`, id)
	inv := &models.Invitation{}
	err := row.Scan(&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.TokenHash,
		&inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt)
	if err != nil {
		return nil, err
	}
	return inv, nil
}

func (db *DB) RefreshInvitation(ctx context.Context, id, newTokenHash string, expiresAt time.Time) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE invitations SET token_hash = $1, expires_at = $2 WHERE id = $3`,
		newTokenHash, expiresAt, id)
	return err
}

// ─── Member usage stats ────────────────────────────────────────

// MemberUsage holds aggregated tunnel + subdomain stats for one team member.
type MemberUsage struct {
	UserID         string `json:"user_id"`
	ActiveTunnels  int    `json:"active_tunnels"`
	TotalTunnels   int    `json:"total_tunnels"`
	TotalRequests  int64  `json:"total_requests"`
	TotalBytes     int64  `json:"total_bytes"`
	SubdomainCount int    `json:"subdomain_count"`
}

// GetTeamMemberUsage returns tunnel + subdomain stats for every member of a team
// in a single query. Non-members with zero activity are still included.
func (db *DB) GetTeamMemberUsage(ctx context.Context, teamID string) ([]*MemberUsage, error) {
	rows, err := db.Pool.Query(ctx, `
		WITH team_users AS (
			SELECT owner_id AS user_id FROM teams WHERE id = $1
			UNION
			SELECT user_id FROM team_members WHERE team_id = $1
		),
		team_tunnels AS (
			SELECT t.id, t.user_id, t.subdomain, t.status, t.total_requests, t.total_bytes
			FROM tunnels t
			JOIN reserved_subdomains rs ON rs.subdomain = t.subdomain
			WHERE rs.team_id = $1
		)
		SELECT
			tu.user_id,
			COUNT(tt.id) FILTER (WHERE tt.status = 'active')::int AS active_tunnels,
			COUNT(tt.id)::int                                     AS total_tunnels,
			COALESCE(SUM(tt.total_requests), 0)::bigint          AS total_requests,
			COALESCE(SUM(tt.total_bytes),    0)::bigint          AS total_bytes,
			COUNT(DISTINCT tt.subdomain)::int                    AS subdomain_count
		FROM team_users tu
		LEFT JOIN team_tunnels tt ON tt.user_id = tu.user_id
		GROUP BY tu.user_id
		ORDER BY tu.user_id`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*MemberUsage
	for rows.Next() {
		u := &MemberUsage{}
		if err := rows.Scan(&u.UserID, &u.ActiveTunnels, &u.TotalTunnels,
			&u.TotalRequests, &u.TotalBytes, &u.SubdomainCount); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (db *DB) ListPendingInvitations(ctx context.Context, teamID string) ([]*models.Invitation, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, team_id, email, role, token_hash, created_at, expires_at, accepted_at
		FROM invitations
		WHERE team_id = $1 AND accepted_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invs []*models.Invitation
	for rows.Next() {
		inv := &models.Invitation{}
		if err := rows.Scan(&inv.ID, &inv.TeamID, &inv.Email, &inv.Role, &inv.TokenHash,
			&inv.CreatedAt, &inv.ExpiresAt, &inv.AcceptedAt); err != nil {
			return nil, err
		}
		invs = append(invs, inv)
	}
	return invs, rows.Err()
}
