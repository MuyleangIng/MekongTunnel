package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// TeamHandler handles /api/team/* endpoints.
type TeamHandler struct {
	DB *db.DB
}

// GetTeam handles GET /api/team — returns all teams owned by the user.
func (h *TeamHandler) GetTeam(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	teams, err := h.DB.ListTeamsByOwner(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if teams == nil {
		teams = []*models.Team{}
	}

	limit := teamLimit(claims.Plan, claims.IsAdmin)
	response.Success(w, map[string]any{
		"teams": teams,
		"limit": limit,
	})
}

// teamLimit returns the max number of teams allowed for a plan.
// -1 = unlimited, 0 = no teams allowed
func teamLimit(plan string, isAdmin bool) int {
	if isAdmin {
		return -1 // unlimited
	}
	switch plan {
	case "org":
		return -1 // unlimited
	case "pro":
		return 5
	case "student":
		return 1
	default:
		return 0
	}
}

// CreateTeam handles POST /api/team.
func (h *TeamHandler) CreateTeam(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if body.Name == "" {
		response.BadRequest(w, "name is required")
		return
	}
	if body.Type == "" {
		body.Type = "project"
	}

	// Check plan limits.
	limit := teamLimit(claims.Plan, claims.IsAdmin)
	if limit == 0 {
		response.Error(w, http.StatusForbidden, "team features require a Pro or Org plan")
		return
	}
	if limit > 0 {
		count, err := h.DB.CountTeamsByOwner(r.Context(), claims.UserID)
		if err != nil {
			response.InternalError(w, err)
			return
		}
		if count >= limit {
			response.Error(w, http.StatusConflict, fmt.Sprintf("plan limit reached (%d/%d teams)", count, limit))
			return
		}
	}

	team, err := h.DB.CreateTeam(r.Context(), body.Name, body.Type, claims.Plan, claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	// Auto-add owner as member with owner role.
	_ = h.DB.AddTeamMember(r.Context(), team.ID, claims.UserID, "owner")

	response.Created(w, team)
}

// DeleteTeam handles DELETE /api/team/{id}.
func (h *TeamHandler) DeleteTeam(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "team id is required")
		return
	}
	team, err := h.DB.GetTeamByID(r.Context(), id)
	if err != nil || team.OwnerID != claims.UserID {
		response.Forbidden(w, "you do not own this team")
		return
	}
	if err := h.DB.DeleteTeam(r.Context(), id); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"message": "team deleted"})
}

// RenameTeam handles PATCH /api/team/{id}.
func (h *TeamHandler) RenameTeam(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "team id is required")
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		response.BadRequest(w, "name is required")
		return
	}

	// Verify ownership.
	team, err := h.DB.GetTeamByID(r.Context(), id)
	if err != nil || team.OwnerID != claims.UserID {
		response.Forbidden(w, "you do not own this team")
		return
	}

	if err := h.DB.RenameTeam(r.Context(), id, body.Name); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "team renamed", "name": body.Name})
}

// resolveTeam returns the team for the request: team_id param if given, else first owned team.
func (h *TeamHandler) resolveTeam(r *http.Request, ownerID string) (*models.Team, error) {
	if id := r.URL.Query().Get("team_id"); id != "" {
		team, err := h.DB.GetTeamByID(r.Context(), id)
		if err != nil || team.OwnerID != ownerID {
			return nil, fmt.Errorf("team not found")
		}
		return team, nil
	}
	return h.DB.GetTeamByOwner(r.Context(), ownerID)
}

// ListMembers handles GET /api/team/members.
func (h *TeamHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	team, err := h.resolveTeam(r, claims.UserID)
	if err != nil {
		response.NotFound(w, "no team found")
		return
	}

	members, err := h.DB.ListTeamMembers(r.Context(), team.ID)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, members)
}

// RemoveMember handles DELETE /api/team/members/{userId}.
func (h *TeamHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	userID := r.PathValue("userId")
	if userID == "" {
		response.BadRequest(w, "userId is required")
		return
	}

	team, err := h.resolveTeam(r, claims.UserID)
	if err != nil {
		response.NotFound(w, "no team found")
		return
	}

	// Owner cannot remove themselves.
	if userID == claims.UserID {
		response.BadRequest(w, "owner cannot remove themselves")
		return
	}

	if err := h.DB.RemoveTeamMember(r.Context(), team.ID, userID); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "member removed"})
}

// Invite handles POST /api/team/invite.
func (h *TeamHandler) Invite(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if body.Email == "" {
		response.BadRequest(w, "email is required")
		return
	}
	if body.Role == "" {
		body.Role = "member"
	}

	team, err := h.resolveTeam(r, claims.UserID)
	if err != nil {
		response.NotFound(w, "no team found — create a team first")
		return
	}

	token, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	tokenHash := auth.HashToken(token)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	inv, err := h.DB.CreateInvitation(r.Context(), team.ID, body.Email, body.Role, tokenHash, expiresAt)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	log.Printf("[team] invitation link for %s: https://mekongtunnel.dev/invite/%s", body.Email, token)

	response.Created(w, inv)
}

// AcceptInvite handles POST /api/team/invite/accept.
func (h *TeamHandler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if body.Token == "" {
		response.BadRequest(w, "token is required")
		return
	}

	tokenHash := auth.HashToken(body.Token)
	inv, err := h.DB.GetInvitationByToken(r.Context(), tokenHash)
	if err != nil {
		response.NotFound(w, "invitation not found or expired")
		return
	}

	if inv.AcceptedAt != nil {
		response.BadRequest(w, "invitation already accepted")
		return
	}
	if time.Now().After(inv.ExpiresAt) {
		response.BadRequest(w, "invitation expired")
		return
	}

	if err := h.DB.AddTeamMember(r.Context(), inv.TeamID, claims.UserID, inv.Role); err != nil {
		response.InternalError(w, err)
		return
	}

	if err := h.DB.AcceptInvitation(r.Context(), inv.ID); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "joined team"})
}

// ListInvitations handles GET /api/team/invitations.
func (h *TeamHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	team, err := h.resolveTeam(r, claims.UserID)
	if err != nil {
		response.NotFound(w, "no team found")
		return
	}
	invs, err := h.DB.ListPendingInvitations(r.Context(), team.ID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if invs == nil {
		invs = []*models.Invitation{}
	}
	response.Success(w, invs)
}

// GenerateInviteCode handles POST /api/team/invite/code.
func (h *TeamHandler) GenerateInviteCode(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	team, err := h.resolveTeam(r, claims.UserID)
	if err != nil {
		response.NotFound(w, "no team found")
		return
	}
	token, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	tokenHash := auth.HashToken(token)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	inv, err := h.DB.CreateInvitation(r.Context(), team.ID, "", "member", tokenHash, expiresAt)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	_ = inv
	response.Created(w, map[string]any{
		"code":       token,
		"expires_at": expiresAt,
	})
}

// RevokeInvite handles DELETE /api/team/invite/{id}.
func (h *TeamHandler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "invitation id is required")
		return
	}

	team, err := h.resolveTeam(r, claims.UserID)
	if err != nil {
		response.NotFound(w, "no team found")
		return
	}

	// Mark accepted_at to effectively revoke (simpler than deleting).
	// We reuse AcceptInvitation to close the token; ideally we'd have a DeleteInvitation.
	// Verify ownership by checking pending invitations.
	pending, err := h.DB.ListPendingInvitations(r.Context(), team.ID)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	found := false
	for _, inv := range pending {
		if inv.ID == id {
			found = true
			break
		}
	}
	if !found {
		response.NotFound(w, "invitation not found in your team")
		return
	}

	if err := h.DB.AcceptInvitation(r.Context(), id); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "invitation revoked"})
}
