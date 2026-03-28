package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
)

// TeamHandler handles /api/team/* endpoints.
type TeamHandler struct {
	DB          *db.DB
	Mailer      *mailer.Mailer
	Notify      *notify.Service
	FrontendURL string
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

// memberSizeLimit returns the max number of members allowed per team based on the team's plan.
// -1 = unlimited.
func memberSizeLimit(plan string) int {
	switch plan {
	case "org":
		return -1
	case "pro":
		return 50
	case "student":
		return 10
	default:
		return 5
	}
}

// roleRank returns a numeric rank so we can compare role power.
// Higher = more powerful.
func roleRank(role string) int {
	switch role {
	case "owner":
		return 4
	case "admin":
		return 3
	case "teacher":
		return 2
	case "member":
		return 1
	}
	return 0
}

// canManageMembers returns true if the role can remove/invite/change other members.
func canManageMembers(role string) bool {
	return role == "owner" || role == "admin"
}

// canInvite returns true if the role can send invitations.
func canInvite(role string) bool {
	return role == "owner" || role == "admin" || role == "teacher"
}

func teamContainsUser(ctx context.Context, database *db.DB, team *models.Team, userID string) bool {
	if team == nil || userID == "" {
		return false
	}
	if team.OwnerID == userID {
		return true
	}
	_, err := database.GetTeamMembership(ctx, team.ID, userID)
	return err == nil
}

// GetMyTunnels handles GET /api/team/{id}/my-tunnels.
// Any team member can call this — returns their own tunnel history.
func (h *TeamHandler) GetMyTunnels(w http.ResponseWriter, r *http.Request) {
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
	// Verify caller is a member of this team.
	team, err := h.DB.GetTeamByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "team not found")
		return
	}
	if team.OwnerID != claims.UserID {
		if _, err := h.DB.GetTeamMembership(r.Context(), id, claims.UserID); err != nil {
			response.Forbidden(w, "you are not a member of this team")
			return
		}
	}
	tunnels, err := h.DB.ListTunnelsByUserAndTeam(r.Context(), claims.UserID, id, r.URL.Query().Get("status"))
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if tunnels == nil {
		tunnels = []*models.Tunnel{}
	}
	response.Success(w, tunnels)
}

// GetMemberTunnels handles GET /api/team/{id}/members/{userId}/tunnels.
// Only owner, admin, or teacher can view another member's tunnel history.
func (h *TeamHandler) GetMemberTunnels(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	teamID := r.PathValue("id")
	targetUserID := r.PathValue("userId")
	if teamID == "" || targetUserID == "" {
		response.BadRequest(w, "team id and user id are required")
		return
	}

	team, err := h.DB.GetTeamByID(r.Context(), teamID)
	if err != nil {
		response.NotFound(w, "team not found")
		return
	}

	if !teamContainsUser(r.Context(), h.DB, team, targetUserID) {
		response.NotFound(w, "team member not found")
		return
	}

	if team.OwnerID != claims.UserID {
		membership, err := h.DB.GetTeamMembership(r.Context(), teamID, claims.UserID)
		if err != nil {
			response.Forbidden(w, "you are not a member of this team")
			return
		}
		if !canInvite(membership.Role) {
			response.Forbidden(w, "only owner, admin, or teacher can view member tunnels")
			return
		}
	}

	tunnels, err := h.DB.ListTunnelsByUserAndTeam(r.Context(), targetUserID, teamID, r.URL.Query().Get("status"))
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if tunnels == nil {
		tunnels = []*models.Tunnel{}
	}
	response.Success(w, tunnels)
}

// GetTeamStats handles GET /api/team/{id}/stats.
// Accessible by owner, admin, or teacher. Returns per-member tunnel + subdomain usage.
func (h *TeamHandler) GetTeamStats(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		response.NotFound(w, "team not found")
		return
	}

	// Determine caller role — only owner/admin/teacher can view stats.
	var callerRole string
	if team.OwnerID == claims.UserID {
		callerRole = "owner"
	} else {
		m, err := h.DB.GetTeamMembership(r.Context(), id, claims.UserID)
		if err != nil {
			response.Forbidden(w, "you are not a member of this team")
			return
		}
		callerRole = m.Role
	}
	if !canInvite(callerRole) { // teacher+ can view stats
		response.Forbidden(w, "only owner, admin, or teacher can view usage stats")
		return
	}

	usage, err := h.DB.GetTeamMemberUsage(r.Context(), id)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if usage == nil {
		usage = []*db.MemberUsage{} //nolint
	}

	// Plan limits for context.
	tunnelLimit := planTunnelLimit(team.Plan)
	subdomainLimit := planSubdomainLimit(team.Plan)

	response.Success(w, map[string]any{
		"usage":           usage,
		"tunnel_limit":    tunnelLimit,
		"subdomain_limit": subdomainLimit,
		"member_limit":    memberSizeLimit(team.Plan),
	})
}

// planTunnelLimit returns max active tunnels per member for a team plan.
func planTunnelLimit(plan string) int {
	switch plan {
	case "org":
		return -1
	case "pro":
		return 10
	case "student":
		return 3
	default:
		return 1
	}
}

// planSubdomainLimit returns max assigned team-owned reserved subdomains per member.
func planSubdomainLimit(plan string) int {
	switch plan {
	case "org":
		return -1
	case "pro":
		return 3
	case "student":
		return 1
	default:
		return 0
	}
}

// teamRouteLimit returns the total team-owned reserved routes allowed for a team.
func teamRouteLimit(plan string) int {
	switch plan {
	case "org":
		return -1
	case "pro":
		return 10
	case "student":
		return 3
	default:
		return 0
	}
}

// GetTeamDetail handles GET /api/team/{id}/detail.
// Accessible by any member of the team (not just the owner).
// Returns team info, all members, and the caller's own role.
func (h *TeamHandler) GetTeamDetail(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		response.NotFound(w, "team not found")
		return
	}

	// Determine the caller's role: owner always has full rights.
	var myRole string
	if team.OwnerID == claims.UserID {
		myRole = "owner"
	} else {
		membership, err := h.DB.GetTeamMembership(r.Context(), id, claims.UserID)
		if err != nil {
			response.Forbidden(w, "you are not a member of this team")
			return
		}
		myRole = membership.Role
	}

	members, err := h.DB.ListTeamMembers(r.Context(), id)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if members == nil {
		members = []*models.TeamMember{}
	}

	limit := memberSizeLimit(team.Plan)
	response.Success(w, map[string]any{
		"team":         team,
		"members":      members,
		"my_role":      myRole,
		"member_limit": limit,
	})
}

// ChangeRole handles PATCH /api/team/members/{userId}/role.
// Owner can set any role. Admin can set up to admin (cannot promote above themselves).
func (h *TeamHandler) ChangeRole(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	targetUserID := r.PathValue("userId")
	if targetUserID == "" {
		response.BadRequest(w, "userId is required")
		return
	}

	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Role == "" {
		response.BadRequest(w, "role is required")
		return
	}

	validRoles := map[string]bool{"admin": true, "teacher": true, "member": true}
	if !validRoles[body.Role] {
		response.BadRequest(w, "role must be admin, teacher, or member")
		return
	}

	team, err := h.resolveTeam(r, claims.UserID)
	if err != nil {
		response.NotFound(w, "no team found")
		return
	}

	// Determine caller's effective role.
	callerRole := "member"
	if team.OwnerID == claims.UserID {
		callerRole = "owner"
	} else {
		m, err := h.DB.GetTeamMembership(r.Context(), team.ID, claims.UserID)
		if err != nil {
			response.Forbidden(w, "you are not a member of this team")
			return
		}
		callerRole = m.Role
	}

	if !canManageMembers(callerRole) {
		response.Forbidden(w, "only owner or admin can change roles")
		return
	}

	// Cannot change owner's role.
	if targetUserID == team.OwnerID {
		response.BadRequest(w, "cannot change the team owner's role")
		return
	}

	// Admin cannot promote someone to a rank above themselves.
	if callerRole == "admin" && roleRank(body.Role) >= roleRank("admin") {
		response.Forbidden(w, "admin cannot promote to admin or higher")
		return
	}

	if err := h.DB.UpdateMemberRole(r.Context(), team.ID, targetUserID, body.Role); err != nil {
		response.InternalError(w, err)
		return
	}

	// Notify the affected user.
	if h.Notify != nil {
		go func() {
			u, err := h.DB.GetUserByID(context.Background(), targetUserID)
			if err == nil {
				h.Notify.Send(context.Background(), u.ID, "team_role_changed",
					"Role updated",
					"Your role in "+team.Name+" has been changed to "+body.Role,
					"/dashboard/team",
				)
			}
		}()
	}

	response.Success(w, map[string]any{"message": "role updated", "role": body.Role})
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
		// Also allow admin/teacher to invite on teams they're a member of.
		response.NotFound(w, "no team found — create a team first")
		return
	}

	// Check caller's role — teacher can only invite as member.
	callerRole := "owner"
	if team.OwnerID != claims.UserID {
		m, merr := h.DB.GetTeamMembership(r.Context(), team.ID, claims.UserID)
		if merr != nil || !canInvite(m.Role) {
			response.Forbidden(w, "only owner, admin, or teacher can invite")
			return
		}
		callerRole = m.Role
	}
	if callerRole == "teacher" && body.Role != "member" {
		body.Role = "member" // teachers can only invite as member
	}

	// Enforce member limit.
	memberCount, err := h.DB.CountTeamMembers(r.Context(), team.ID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if lim := memberSizeLimit(team.Plan); lim >= 0 && memberCount >= lim {
		response.Error(w, http.StatusConflict, fmt.Sprintf("team member limit reached (%d/%d)", memberCount, lim))
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

	go h.Mailer.SendInvitation(body.Email, claims.Email, team.Name, token, h.FrontendURL)
	log.Printf("[team] invitation sent to %s for team %s", body.Email, team.Name)

	// If the invited email already has an account, send a real-time notification.
	if h.Notify != nil {
		go func() {
			u, err := h.DB.GetUserByEmail(context.Background(), body.Email)
			if err == nil && u != nil {
				h.Notify.Send(context.Background(), u.ID, "team_invite",
					"Team invitation",
					"You've been invited to join "+team.Name,
					"/dashboard/team",
				)
			}
		}()
	}

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
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	// Accept either "token" or "code" field — both are the same plaintext invite token.
	if body.Token == "" {
		body.Token = body.Code
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

	// Enforce member limit before accepting.
	memberCount, err := h.DB.CountTeamMembers(r.Context(), inv.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	team, err := h.DB.GetTeamByID(r.Context(), inv.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if lim := memberSizeLimit(team.Plan); lim >= 0 && memberCount >= lim {
		response.Error(w, http.StatusConflict, fmt.Sprintf("team member limit reached (%d/%d)", memberCount, lim))
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

// AcceptInviteByID handles POST /api/team/invite/accept-by-id.
// Lets an authenticated user accept an invitation sent to their email, without needing the plaintext token.
func (h *TeamHandler) AcceptInviteByID(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		InvID string `json:"inv_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.InvID == "" {
		response.BadRequest(w, "inv_id is required")
		return
	}

	inv, err := h.DB.GetInvitationByID(r.Context(), body.InvID)
	if err != nil {
		response.NotFound(w, "invitation not found")
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
	// Security: only allow if the invitation email matches the authenticated user's email.
	if inv.Email != claims.Email {
		response.Forbidden(w, "this invitation was not sent to your email address")
		return
	}

	// Enforce member limit.
	memberCount, err := h.DB.CountTeamMembers(r.Context(), inv.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	invTeam, err := h.DB.GetTeamByID(r.Context(), inv.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if lim := memberSizeLimit(invTeam.Plan); lim >= 0 && memberCount >= lim {
		response.Error(w, http.StatusConflict, fmt.Sprintf("team member limit reached (%d/%d)", memberCount, lim))
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

// GetJoinedTeams handles GET /api/team/joined — teams the user is a member of (not owner).
func (h *TeamHandler) GetJoinedTeams(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	teams, err := h.DB.ListTeamsAsMember(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if teams == nil {
		teams = []*models.Team{}
	}
	response.Success(w, teams)
}

// GetMyInvitations handles GET /api/team/my-invitations — pending email invites for the current user.
func (h *TeamHandler) GetMyInvitations(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	invs, err := h.DB.GetPendingInvitationsByEmail(r.Context(), claims.Email)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if invs == nil {
		invs = []*models.Invitation{}
	}
	response.Success(w, invs)
}

// LeaveTeam handles DELETE /api/team/{id}/leave — remove yourself from a team you joined.
func (h *TeamHandler) LeaveTeam(w http.ResponseWriter, r *http.Request) {
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
	// Prevent owner from leaving their own team via this endpoint.
	team, err := h.DB.GetTeamByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "team not found")
		return
	}
	if team.OwnerID == claims.UserID {
		response.BadRequest(w, "owner cannot leave their own team — delete it instead")
		return
	}
	if err := h.DB.LeaveTeam(r.Context(), id, claims.UserID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"message": "left team"})
}

// ResendInvite handles POST /api/team/invite/{id}/resend.
// Generates a fresh token, extends expiry by 7 days, and re-sends the invitation email.
func (h *TeamHandler) ResendInvite(w http.ResponseWriter, r *http.Request) {
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

	inv, err := h.DB.GetInvitationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "invitation not found")
		return
	}
	if inv.TeamID != team.ID {
		response.Forbidden(w, "invitation does not belong to your team")
		return
	}
	if inv.AcceptedAt != nil {
		response.BadRequest(w, "invitation already accepted")
		return
	}
	if inv.Email == "" {
		response.BadRequest(w, "cannot resend a link-based invitation")
		return
	}

	token, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	tokenHash := auth.HashToken(token)
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	if err := h.DB.RefreshInvitation(r.Context(), id, tokenHash, expiresAt); err != nil {
		response.InternalError(w, err)
		return
	}

	go h.Mailer.SendInvitation(inv.Email, claims.Email, team.Name, token, h.FrontendURL)
	log.Printf("[team] invitation resent to %s for team %s", inv.Email, team.Name)

	response.Success(w, map[string]any{"message": "invitation resent", "expires_at": expiresAt})
}
