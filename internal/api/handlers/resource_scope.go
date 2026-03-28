package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

var (
	errResourceTeamNotFound = errors.New("team not found")
	errResourceTeamAccess   = errors.New("not a member of team")
)

type resourceScope struct {
	UserID string
	TeamID string
	Team   *models.Team
	Role   string
}

func requestedTeamID(r *http.Request) string {
	return strings.TrimSpace(r.URL.Query().Get("team_id"))
}

func resolveResourceScope(ctx context.Context, database *db.DB, userID, teamID string) (*resourceScope, error) {
	scope := &resourceScope{UserID: userID}
	if strings.TrimSpace(teamID) == "" {
		return scope, nil
	}

	team, err := database.GetTeamByID(ctx, teamID)
	if err != nil {
		return nil, errResourceTeamNotFound
	}
	scope.Team = team
	scope.TeamID = team.ID

	if team.OwnerID == userID {
		scope.Role = "owner"
		return scope, nil
	}

	membership, err := database.GetTeamMembership(ctx, team.ID, userID)
	if err != nil {
		return nil, errResourceTeamAccess
	}
	scope.Role = membership.Role
	return scope, nil
}

func (s *resourceScope) IsTeam() bool {
	return s != nil && s.TeamID != ""
}

func (s *resourceScope) CanManage() bool {
	if s == nil || !s.IsTeam() {
		return true
	}
	return canInvite(s.Role)
}

func (s *resourceScope) OwnerDescription() string {
	if s == nil || !s.IsTeam() {
		return "your account"
	}
	return "this team"
}
