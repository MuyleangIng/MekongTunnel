package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// SubdomainHandler handles reserved subdomains and per-subdomain access-control rules.
type SubdomainHandler struct {
	DB *db.DB
}

// deploymentSubdomain is a lightweight view of a deployment used in subdomain list responses.
type deploymentSubdomain struct {
	ID        string `json:"id"`
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	Source    string `json:"source"` // always "deployment"
}

// countActiveDeploymentSubdomains returns how many active (non-deleted) deployments a user has.
// Deployment subdomains occupy a real subdomain slot and count toward the plan quota.
func (h *SubdomainHandler) countActiveDeploymentSubdomains(ctx context.Context, userID string) int {
	var n int
	_ = h.DB.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM deployments WHERE user_id=$1 AND status != 'deleted'`, userID).Scan(&n)
	return n
}

// listDeploymentSubdomains returns the deployment subdomain details for a user.
func (h *SubdomainHandler) listDeploymentSubdomains(ctx context.Context, userID string) []deploymentSubdomain {
	rows, err := h.DB.Pool.Query(ctx,
		`SELECT id, subdomain, type, status, created_at FROM deployments WHERE user_id=$1 AND status != 'deleted' ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []deploymentSubdomain
	for rows.Next() {
		var d deploymentSubdomain
		var createdAt time.Time
		if err := rows.Scan(&d.ID, &d.Subdomain, &d.Type, &d.Status, &createdAt); err != nil {
			continue
		}
		d.CreatedAt = createdAt.UTC().Format("2006-01-02T15:04:05Z")
		d.Source = "deployment"
		out = append(out, d)
	}
	return out
}

func (h *SubdomainHandler) userFromAPIToken(r *http.Request) (*models.User, error) {
	hdr := r.Header.Get("Authorization")
	if len(hdr) < 8 || hdr[:7] != "Bearer " {
		return nil, fmt.Errorf("Bearer token required")
	}
	userID, err := h.DB.ValidateToken(r.Context(), hdr[7:])
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token")
	}
	return h.DB.GetUserByID(r.Context(), userID)
}

// List handles GET /api/subdomains
func (h *SubdomainHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}

	list, err := h.DB.ListReservedSubdomainsByScope(r.Context(), claims.UserID, scope.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if list == nil {
		list = []*models.ReservedSubdomain{}
	}

	limit := 0
	if scope.IsTeam() {
		limit = teamRouteLimit(scope.Team.Plan)
	} else {
		limit, _ = h.DB.GetSubdomainLimit(r.Context(), claims.Plan)
	}
	// Deployment subdomains also count toward the quota (they occupy real subdomain slots).
	deployItems := h.listDeploymentSubdomains(r.Context(), claims.UserID)
	deployCount := len(deployItems)
	count := len(list) + deployCount
	response.Success(w, map[string]any{
		"subdomains":              list,
		"deployment_subdomains":   deployItems,
		"count":                   count,
		"limit":                   limit,
		"deployment_count":        deployCount,
	})
}

// ListCLI handles GET /api/cli/subdomains using an API token.
func (h *SubdomainHandler) ListCLI(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromAPIToken(r)
	if err != nil {
		response.Unauthorized(w, err.Error())
		return
	}

	scope, err := resolveResourceScope(r.Context(), h.DB, user.ID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}

	list, err := h.DB.ListReservedSubdomainsByScope(r.Context(), user.ID, scope.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if list == nil {
		list = []*models.ReservedSubdomain{}
	}

	limit := 0
	if scope.IsTeam() {
		limit = teamRouteLimit(scope.Team.Plan)
	} else {
		limit, _ = h.DB.GetSubdomainLimit(r.Context(), user.Plan)
	}
	deployItems := h.listDeploymentSubdomains(r.Context(), user.ID)
	response.Success(w, map[string]any{
		"subdomains":            list,
		"deployment_subdomains": deployItems,
		"count":                 len(list) + len(deployItems),
		"limit":                 limit,
		"deployment_count":      len(deployItems),
	})
}

// Create handles POST /api/subdomains
func (h *SubdomainHandler) Create(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if scope.IsTeam() && !claims.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can manage team subdomains")
		return
	}

	// Check plan limit
	if !claims.IsAdmin {
		if scope.IsTeam() {
			limit := teamRouteLimit(scope.Team.Plan)
			if limit == 0 {
				response.Error(w, http.StatusPaymentRequired,
					"this team plan does not include reserved subdomains")
				return
			}
			if limit > 0 {
				count, _ := h.DB.GetSubdomainCountByScope(r.Context(), claims.UserID, scope.TeamID)
				if count >= limit {
					response.Error(w, http.StatusPaymentRequired,
						fmt.Sprintf("team plan limit reached: this %s team allows %d reserved subdomain(s)", scope.Team.Plan, limit))
					return
				}
			}
		} else {
			limit, err := h.DB.GetSubdomainLimit(r.Context(), claims.Plan)
			if err == nil && limit == 0 {
				response.Error(w, http.StatusPaymentRequired,
					"your plan does not include reserved subdomains — upgrade to Student, Pro, or Org")
				return
			}
			if err == nil && limit > 0 {
				reserved, _ := h.DB.GetSubdomainCountByScope(r.Context(), claims.UserID, "")
				deployments := h.countActiveDeploymentSubdomains(r.Context(), claims.UserID)
				if reserved+deployments >= limit {
					response.Error(w, http.StatusPaymentRequired,
						fmt.Sprintf("subdomain limit reached: your %s plan allows %d subdomain(s) total (including deployments)", claims.Plan, limit))
					return
				}
			}
		}
	}

	var body struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid request body")
		return
	}
	subdomain := strings.ToLower(strings.TrimSpace(body.Subdomain))
	if subdomain == "" {
		response.BadRequest(w, "subdomain is required")
		return
	}
	for _, c := range subdomain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			response.BadRequest(w, "subdomain may only contain lowercase letters, digits, and hyphens")
			return
		}
	}

	ownerUserID := claims.UserID
	if scope.IsTeam() {
		ownerUserID = ""
	}
	s, err := h.DB.CreateReservedSubdomainByScope(r.Context(), ownerUserID, scope.TeamID, subdomain)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			response.Conflict(w, "subdomain already reserved")
			return
		}
		response.InternalError(w, err)
		return
	}
	response.Created(w, s)
}

// CreateCLI handles POST /api/cli/subdomains using an API token.
func (h *SubdomainHandler) CreateCLI(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromAPIToken(r)
	if err != nil {
		response.Unauthorized(w, err.Error())
		return
	}

	scope, err := resolveResourceScope(r.Context(), h.DB, user.ID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if scope.IsTeam() && !user.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can manage team subdomains")
		return
	}

	if !user.IsAdmin {
		if scope.IsTeam() {
			limit := teamRouteLimit(scope.Team.Plan)
			if limit == 0 {
				response.Error(w, http.StatusPaymentRequired,
					"this team plan does not include reserved subdomains")
				return
			}
			if limit > 0 {
				count, _ := h.DB.GetSubdomainCountByScope(r.Context(), user.ID, scope.TeamID)
				if count >= limit {
					response.Error(w, http.StatusPaymentRequired,
						fmt.Sprintf("team plan limit reached: this %s team allows %d reserved subdomain(s)", scope.Team.Plan, limit))
					return
				}
			}
		} else {
			limit, err := h.DB.GetSubdomainLimit(r.Context(), user.Plan)
			if err == nil && limit == 0 {
				response.Error(w, http.StatusPaymentRequired,
					"your plan does not include reserved subdomains — upgrade to Student, Pro, or Org")
				return
			}
			if err == nil && limit > 0 {
				count, _ := h.DB.GetSubdomainCountByScope(r.Context(), user.ID, "")
				if count >= limit {
					response.Error(w, http.StatusPaymentRequired,
						fmt.Sprintf("plan limit reached: your %s plan allows %d reserved subdomain(s)", user.Plan, limit))
					return
				}
			}
		}
	}

	var body struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid request body")
		return
	}
	subdomain := strings.ToLower(strings.TrimSpace(body.Subdomain))
	if subdomain == "" {
		response.BadRequest(w, "subdomain is required")
		return
	}
	for _, c := range subdomain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			response.BadRequest(w, "subdomain may only contain lowercase letters, digits, and hyphens")
			return
		}
	}

	ownerUserID := user.ID
	if scope.IsTeam() {
		ownerUserID = ""
	}
	s, err := h.DB.CreateReservedSubdomainByScope(r.Context(), ownerUserID, scope.TeamID, subdomain)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			response.Conflict(w, "subdomain already reserved")
			return
		}
		response.InternalError(w, err)
		return
	}
	response.Created(w, s)
}

// DeleteCLI handles DELETE /api/cli/subdomains/{id} using an API token.
func (h *SubdomainHandler) DeleteCLI(w http.ResponseWriter, r *http.Request) {
	user, err := h.userFromAPIToken(r)
	if err != nil {
		response.Unauthorized(w, err.Error())
		return
	}
	scope, err := resolveResourceScope(r.Context(), h.DB, user.ID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if scope.IsTeam() && !user.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can manage team subdomains")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}

	s, err := h.DB.GetReservedSubdomain(r.Context(), id)
	if err != nil {
		response.NotFound(w, "subdomain not found")
		return
	}
	if scope.IsTeam() {
		if s.TeamID == nil || *s.TeamID != scope.TeamID {
			response.NotFound(w, "subdomain not found")
			return
		}
	} else if s.TeamID != nil || (s.UserID != user.ID && !user.IsAdmin) {
		response.Forbidden(w, "not your subdomain")
		return
	}

	if err := h.DB.DeleteReservedSubdomainByScope(r.Context(), id, user.ID, scope.TeamID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.NoContent(w)
}

// Delete handles DELETE /api/subdomains/{id}
func (h *SubdomainHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if scope.IsTeam() && !claims.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can manage team subdomains")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}
	s, err := h.DB.GetReservedSubdomain(r.Context(), id)
	if err != nil {
		response.NotFound(w, "subdomain not found")
		return
	}
	if scope.IsTeam() {
		if s.TeamID == nil || *s.TeamID != scope.TeamID {
			response.NotFound(w, "subdomain not found")
			return
		}
	} else if s.TeamID != nil || s.UserID != claims.UserID {
		response.Forbidden(w, "not your subdomain")
		return
	}
	if err := h.DB.DeleteReservedSubdomainByScope(r.Context(), id, claims.UserID, scope.TeamID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.NoContent(w)
}

// UpdateAssignment handles PATCH /api/subdomains/{id}/assignment.
// Team-only endpoint for owner/admin/teacher to assign a reserved subdomain to one member.
func (h *SubdomainHandler) UpdateAssignment(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if !scope.IsTeam() {
		response.BadRequest(w, "team_id is required for subdomain assignment")
		return
	}
	if !claims.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can assign team subdomains")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}

	s, err := h.DB.GetReservedSubdomain(r.Context(), id)
	if err != nil {
		response.NotFound(w, "subdomain not found")
		return
	}
	if s.TeamID == nil || *s.TeamID != scope.TeamID {
		response.NotFound(w, "subdomain not found")
		return
	}

	var body struct {
		AssignedUserID *string `json:"assigned_user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid request body")
		return
	}

	assignedUserID := ""
	if body.AssignedUserID != nil {
		assignedUserID = strings.TrimSpace(*body.AssignedUserID)
	}
	if assignedUserID != "" && scope.Team.OwnerID != assignedUserID {
		if _, err := h.DB.GetTeamMembership(r.Context(), scope.TeamID, assignedUserID); err != nil {
			response.BadRequest(w, "assigned_user_id must belong to this team")
			return
		}
	}

	updated, err := h.DB.UpdateReservedSubdomainAssignment(r.Context(), id, scope.TeamID, assignedUserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, updated)
}

// UpsertRule handles PUT /api/subdomains/{id}/rule
func (h *SubdomainHandler) UpsertRule(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	if scope.IsTeam() && !claims.IsAdmin && !scope.CanManage() {
		response.Forbidden(w, "only owner, admin, or teacher can manage team subdomains")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}

	s, err := h.DB.GetReservedSubdomain(r.Context(), id)
	if err != nil {
		response.NotFound(w, "subdomain not found")
		return
	}
	if scope.IsTeam() {
		if s.TeamID == nil || *s.TeamID != scope.TeamID {
			response.NotFound(w, "subdomain not found")
			return
		}
	} else if s.TeamID != nil || (s.UserID != claims.UserID && !claims.IsAdmin) {
		response.Forbidden(w, "not your subdomain")
		return
	}

	var body models.SubdomainRule
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid request body")
		return
	}
	body.SubdomainID = id

	rule, err := h.DB.UpsertSubdomainRule(r.Context(), &body)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, rule)
}

// Analytics handles GET /api/subdomains/analytics
func (h *SubdomainHandler) Analytics(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	scope, err := resolveResourceScope(r.Context(), h.DB, claims.UserID, requestedTeamID(r))
	if err != nil {
		if err == errResourceTeamNotFound {
			response.NotFound(w, "team not found")
			return
		}
		response.Forbidden(w, "you are not a member of this team")
		return
	}
	data, err := h.DB.GetSubdomainAnalyticsByScope(r.Context(), claims.UserID, scope.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if data == nil {
		data = []*db.SubdomainAnalytics{}
	}
	response.Success(w, data)
}
