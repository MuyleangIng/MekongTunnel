package db

import (
	"context"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// ─── Teams ────────────────────────────────────────────────────

func (db *DB) CreateTeam(ctx context.Context, name, teamType, plan, ownerID string) (*models.Team, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO teams (name, type, plan, owner_id)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, type, plan, owner_id, created_at`,
		name, teamType, plan, ownerID)
	t := &models.Team{}
	err := row.Scan(&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (db *DB) GetTeamByID(ctx context.Context, id string) (*models.Team, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, name, type, plan, owner_id, created_at FROM teams WHERE id = $1`, id)
	t := &models.Team{}
	err := row.Scan(&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (db *DB) GetTeamByOwner(ctx context.Context, ownerID string) (*models.Team, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, name, type, plan, owner_id, created_at FROM teams WHERE owner_id = $1`, ownerID)
	t := &models.Team{}
	err := row.Scan(&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (db *DB) ListTeamsByOwner(ctx context.Context, ownerID string) ([]*models.Team, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, name, type, plan, owner_id, created_at FROM teams
		WHERE owner_id = $1 ORDER BY created_at ASC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var teams []*models.Team
	for rows.Next() {
		t := &models.Team{}
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &t.Plan, &t.OwnerID, &t.CreatedAt); err != nil {
			return nil, err
		}
		teams = append(teams, t)
	}
	return teams, rows.Err()
}

func (db *DB) CountTeamsByOwner(ctx context.Context, ownerID string) (int, error) {
	var count int
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM teams WHERE owner_id = $1`, ownerID).Scan(&count)
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
