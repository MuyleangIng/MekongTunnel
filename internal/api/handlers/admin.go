package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
)

// AdminHandler handles all /api/admin/* endpoints (admin only).
type AdminHandler struct {
	DB          *db.DB
	Notify      *notify.Service
	Mailer      *mailer.Mailer
	FrontendURL string
}

type adminOrgMemberResponse struct {
	ID         string         `json:"id"`
	OrgID      string         `json:"org_id"`
	UserID     string         `json:"user_id"`
	Role       string         `json:"role"`
	JoinedAt   time.Time      `json:"joined_at"`
	Name       string         `json:"name"`
	Email      string         `json:"email"`
	AvatarURL  string         `json:"avatar_url,omitempty"`
	Plan       string         `json:"plan"`
	IsAdmin    bool           `json:"is_admin"`
	Allocation map[string]any `json:"allocation,omitempty"`
	User       map[string]any `json:"user,omitempty"`
}

func serializeAdminOrgMembers(members []*models.OrgMember) []adminOrgMemberResponse {
	out := make([]adminOrgMemberResponse, 0, len(members))
	for _, member := range members {
		if member == nil {
			continue
		}
		resp := adminOrgMemberResponse{
			ID:       member.ID,
			OrgID:    member.OrgID,
			UserID:   member.UserID,
			Role:     member.Role,
			JoinedAt: member.JoinedAt,
		}
		if member.User != nil {
			resp.Name = member.User.Name
			resp.Email = member.User.Email
			resp.AvatarURL = member.User.AvatarURL
			resp.Plan = member.User.Plan
			resp.IsAdmin = member.User.IsAdmin
			resp.User = map[string]any{
				"id":                    member.User.ID,
				"email":                 member.User.Email,
				"name":                  member.User.Name,
				"avatar_url":            member.User.AvatarURL,
				"plan":                  member.User.Plan,
				"is_admin":              member.User.IsAdmin,
				"provisioned_by_org_id": member.User.ProvisionedByOrgID,
				"force_password_reset":  member.User.ForcePasswordReset,
			}
		}
		if member.Allocation != nil {
			resp.Allocation = map[string]any{
				"tunnel_limit":          member.Allocation.TunnelLimit,
				"team_limit":            member.Allocation.TeamLimit,
				"subdomain_limit":       member.Allocation.SubdomainLimit,
				"custom_domain_allowed": member.Allocation.CustomDomainAllowed,
				"bandwidth_gb":          member.Allocation.BandwidthGB,
			}
		}
		out = append(out, resp)
	}
	return out
}

func (h *AdminHandler) notifyUsers(ctx context.Context, userIDs []string, notifType, title, body, link string) {
	if h.Notify == nil {
		return
	}
	for _, userID := range dedupeUserIDs(userIDs) {
		go h.Notify.Send(ctx, userID, notifType, title, body, link)
	}
}

func (h *AdminHandler) emailUsers(ctx context.Context, userIDs []string, subject, title, body, link string) {
	if h.Mailer == nil || !h.Mailer.Enabled() {
		return
	}
	htmlBody := `<div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#111827">` +
		`<h2 style="margin:0 0 12px;">` + title + `</h2>` +
		`<p style="line-height:1.6;margin:0 0 16px;">` + body + `</p>`
	if link != "" {
		htmlBody += `<p style="margin:0 0 16px;"><a href="` + strings.TrimRight(h.FrontendURL, "/") + link + `" style="display:inline-block;padding:10px 16px;background:#ca8a04;color:#111827;text-decoration:none;border-radius:10px;font-weight:700">Open Mekong Tunnel</a></p>`
	}
	htmlBody += `</div>`
	for _, userID := range dedupeUserIDs(userIDs) {
		user, err := h.DB.GetUserByID(ctx, userID)
		if err != nil || user == nil || strings.TrimSpace(user.Email) == "" {
			continue
		}
		go func(email string) {
			if err := h.Mailer.Send(email, subject, htmlBody); err != nil {
				log.Printf("[admin] email %s: %v", email, err)
			}
		}(user.Email)
	}
}

// ─── Stats ────────────────────────────────────────────────────

// GetStats handles GET /api/admin/stats.
func (h *AdminHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.DB.GetAdminStats(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, stats)
}

// ─── Users ────────────────────────────────────────────────────

// ListUsers handles GET /api/admin/users.
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	plan := r.URL.Query().Get("plan")
	limit := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)

	users, total, err := h.DB.ListUsers(r.Context(), search, plan, limit, offset)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	sanitized := make([]map[string]any, len(users))
	for i, u := range users {
		sanitized[i] = sanitizeUser(u)
	}

	response.Success(w, map[string]any{
		"users":  sanitized,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// GetUser handles GET /api/admin/users/{id}.
func (h *AdminHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "user id required")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	response.Success(w, sanitizeUser(user))
}

// UpdateUser handles PATCH /api/admin/users/{id}.
func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "user id required")
		return
	}

	var body struct {
		Plan          *string `json:"plan"`
		Suspended     *bool   `json:"suspended"`
		IsAdmin       *bool   `json:"is_admin"`
		EmailVerified *bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	fields := map[string]any{}
	if body.Plan != nil {
		fields["plan"] = *body.Plan
	}
	if body.Suspended != nil {
		fields["suspended"] = *body.Suspended
	}
	if body.IsAdmin != nil {
		fields["is_admin"] = *body.IsAdmin
	}
	if body.EmailVerified != nil {
		fields["email_verified"] = *body.EmailVerified
	}

	if len(fields) == 0 {
		response.BadRequest(w, "nothing to update")
		return
	}

	user, err := h.DB.UpdateUser(r.Context(), id, fields)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, sanitizeUser(user))
}

// ResendVerification handles POST /api/admin/users/{id}/resend-verify.
// Generates a fresh email-verification token and sends it to the user.
func (h *AdminHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "user id required")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	if user.EmailVerified {
		response.BadRequest(w, "user email is already verified")
		return
	}

	token, err := auth.GenerateSecureToken()
	if err != nil {
		response.InternalError(w, err)
		return
	}
	tokenHash := auth.HashToken(token)
	if err := h.DB.CreateEmailVerifyToken(r.Context(), user.ID, tokenHash, time.Now().Add(24*time.Hour)); err != nil {
		response.InternalError(w, err)
		return
	}

	frontendURL := h.FrontendURL
	if frontendURL == "" {
		frontendURL = "https://angkorsearch.dev"
	}

	if h.Mailer != nil {
		go h.Mailer.SendVerification(user.Email, user.Name, token, frontendURL)
		log.Printf("[admin] resend verification email → %s", user.Email)
	} else {
		log.Printf("[admin] resend verify token for %s: %s", user.Email, token)
	}

	response.Success(w, map[string]any{
		"message":       "verification email sent",
		"email":         user.Email,
		"mailer_active": h.Mailer != nil && h.Mailer.Enabled(),
	})
}

// DeleteUser handles DELETE /api/admin/users/{id}.
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "user id required")
		return
	}

	// Prevent admin from deleting themselves.
	claims := middleware.GetClaims(r)
	if claims != nil && claims.UserID == id {
		response.BadRequest(w, "cannot delete your own account via admin endpoint")
		return
	}

	if err := h.DB.DeleteUser(r.Context(), id); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "user deleted"})
}

// ─── Tunnels ──────────────────────────────────────────────────

// ListTunnels handles GET /api/admin/tunnels.
func (h *AdminHandler) ListTunnels(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	userID := r.URL.Query().Get("user_id")
	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	// If user_id is specified, return only that user's tunnels.
	if userID != "" {
		userTunnels, err := h.DB.ListTunnelsByUser(r.Context(), userID, status)
		if err != nil {
			response.InternalError(w, err)
			return
		}
		if userTunnels == nil {
			userTunnels = []*models.Tunnel{}
		}
		response.Success(w, map[string]any{"tunnels": userTunnels, "limit": -1, "offset": 0})
		return
	}

	tunnels, err := h.DB.ListAllTunnels(r.Context(), status, limit, offset)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"tunnels": tunnels,
		"limit":   limit,
		"offset":  offset,
	})
}

// KillTunnel handles DELETE /api/admin/tunnels/{id}.
func (h *AdminHandler) KillTunnel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "tunnel id required")
		return
	}

	now := time.Now()
	if err := h.DB.UpdateTunnelStatus(r.Context(), id, "stopped", &now); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "tunnel killed"})
}

// ─── Custom Domains ───────────────────────────────────────────

// ListDomains handles GET /api/admin/domains.
func (h *AdminHandler) ListDomains(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	status := r.URL.Query().Get("status")
	search := r.URL.Query().Get("search")
	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	list, err := h.DB.ListAllCustomDomains(r.Context(), userID, status, search, limit, offset)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	out := make([]enrichedCustomDomain, 0, len(list))
	for _, d := range list {
		out = append(out, enrichCustomDomain(d))
	}
	response.Success(w, map[string]any{
		"domains": out,
		"limit":   limit,
		"offset":  offset,
	})
}

// GetDomain handles GET /api/admin/domains/{id}.
func (h *AdminHandler) GetDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "domain id required")
		return
	}

	d, err := h.DB.GetCustomDomainByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}

	response.Success(w, enrichCustomDomain(d))
}

// VerifyDomain handles POST /api/admin/domains/{id}/verify.
func (h *AdminHandler) VerifyDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "domain id required")
		return
	}

	d, err := h.DB.GetCustomDomainByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}

	dh := &DomainsHandler{DB: h.DB}
	dh.respondVerification(w, r, d)
}

// SetDomainTarget handles PATCH /api/admin/domains/{id}/target.
func (h *AdminHandler) SetDomainTarget(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "domain id required")
		return
	}

	d, err := h.DB.GetCustomDomainByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}

	var body struct {
		TargetSubdomain string `json:"target_subdomain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	targetSubdomain := body.TargetSubdomain
	targetSubdomain = strings.ToLower(strings.TrimSpace(targetSubdomain))
	if targetSubdomain == "" {
		response.BadRequest(w, "target_subdomain is required")
		return
	}

	scopeUserID := d.UserID
	scopeTeamID := ""
	if d.TeamID != nil {
		scopeUserID = ""
		scopeTeamID = *d.TeamID
	}

	reserved, err := h.DB.GetReservedSubdomainForScope(r.Context(), scopeUserID, scopeTeamID, targetSubdomain)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if reserved == "" {
		if scopeTeamID != "" {
			response.BadRequest(w, "target_subdomain must belong to the domain's team")
		} else {
			response.BadRequest(w, "target_subdomain must belong to the domain owner")
		}
		return
	}

	if err := h.DB.SetCustomDomainTargetByID(r.Context(), id, targetSubdomain); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"ok": true})
}

// DeleteDomain handles DELETE /api/admin/domains/{id}.
func (h *AdminHandler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "domain id required")
		return
	}

	d, err := h.DB.GetCustomDomainByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}
	if err := h.DB.DeleteCustomDomainByID(r.Context(), id); err != nil {
		response.InternalError(w, err)
		return
	}
	result := deleteResultForDomain(d)
	response.Success(w, map[string]any{
		"message": "domain deleted",
		"domain":  result,
		"user_id": d.UserID,
	})
}

// ─── Plans ────────────────────────────────────────────────────

// GetPlans handles GET /api/admin/plans — returns full PlanLimits objects.
func (h *AdminHandler) GetPlans(w http.ResponseWriter, r *http.Request) {
	configs, err := h.DB.GetPlanConfigs(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	// Return raw config JSON objects (already in PlanLimits format)
	result := make([]json.RawMessage, 0, len(configs))
	for _, c := range configs {
		result = append(result, c.Config)
	}
	response.Success(w, result)
}

// GetPublicPlans handles GET /api/plans — public endpoint, returns only enabled plans.
func (h *AdminHandler) GetPublicPlans(w http.ResponseWriter, r *http.Request) {
	configs, err := h.DB.GetPlanConfigs(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	result := make([]json.RawMessage, 0, len(configs))
	for _, c := range configs {
		// Check if enabled field is false; if so skip
		var m map[string]any
		if json.Unmarshal(c.Config, &m) == nil {
			if enabled, ok := m["enabled"]; ok {
				if b, ok := enabled.(bool); ok && !b {
					continue
				}
			}
		}
		result = append(result, c.Config)
	}
	response.Success(w, result)
}

// UpdatePlans handles PUT /api/admin/plans — accepts array of PlanLimits objects.
func (h *AdminHandler) UpdatePlans(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var plans []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&plans); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	for _, p := range plans {
		planID, _ := p["id"].(string)
		if planID == "" {
			continue
		}
		if err := h.DB.UpsertPlanConfig(r.Context(), planID, p, claims.UserID); err != nil {
			response.InternalError(w, err)
			return
		}
	}

	response.Success(w, map[string]any{"message": "plans updated"})
}

// ─── Organizations ────────────────────────────────────────────

// ListOrgs handles GET /api/admin/organizations.
func (h *AdminHandler) ListOrgs(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	plan := r.URL.Query().Get("plan")
	limit := queryInt(r, "limit", 20)
	offset := queryInt(r, "offset", 0)

	orgs, err := h.DB.ListOrganizations(r.Context(), search, plan, limit, offset)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"organizations": orgs,
		"limit":         limit,
		"offset":        offset,
	})
}

// CreateOrg handles POST /api/admin/organizations.
func (h *AdminHandler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name       string `json:"name"`
		Domain     string `json:"domain"`
		Plan       string `json:"plan"`
		OwnerEmail string `json:"owner_email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if body.Name == "" {
		response.BadRequest(w, "name is required")
		return
	}
	if body.Plan == "" {
		body.Plan = "student"
	}

	ownerID := ""
	if body.OwnerEmail != "" {
		owner, err := h.DB.GetUserByEmail(r.Context(), body.OwnerEmail)
		if err == nil && owner != nil {
			ownerID = owner.ID
		}
	}

	org, err := h.DB.CreateOrganization(r.Context(), body.Name, body.Domain, body.Plan, ownerID, "school", 100, nil)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Created(w, org)
}

// GetOrg handles GET /api/admin/organizations/{id}.
func (h *AdminHandler) GetOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "org id required")
		return
	}

	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	members, _ := h.DB.ListOrgMembers(r.Context(), id)
	teams, _ := h.DB.ListTeamsByOrg(r.Context(), id)
	managerCount, _ := h.DB.CountOrgManagers(r.Context(), id)
	pendingRequestCount, _ := h.DB.CountPendingResourceRequests(r.Context(), id)
	pendingFirstLoginCount, _ := h.DB.CountOrgPendingFirstLogin(r.Context(), id)
	var owner any
	if org.OwnerID != nil {
		if ownerUser, err := h.DB.GetUserByID(r.Context(), *org.OwnerID); err == nil && ownerUser != nil {
			if ownerUser.ForcePasswordReset {
				pendingFirstLoginCount++
			}
			owner = sanitizeUser(ownerUser)
		}
	}
	var createdBy any
	if org.CreatedBy != nil {
		if createdUser, err := h.DB.GetUserByID(r.Context(), *org.CreatedBy); err == nil && createdUser != nil {
			createdBy = sanitizeUser(createdUser)
		}
	}

	response.Success(w, map[string]any{
		"org":             org,
		"owner":           owner,
		"created_by_user": createdBy,
		"members":         serializeAdminOrgMembers(members),
		"teams":           teams,
		"summary": map[string]any{
			"seat_usage":                org.MemberCount,
			"seat_limit":                org.SeatLimit,
			"manager_count":             managerCount,
			"team_count":                len(teams),
			"pending_request_count":     pendingRequestCount,
			"pending_first_login_count": pendingFirstLoginCount,
			"active_tunnels":            org.ActiveTunnels,
			"status_changed_at":         org.StatusChangedAt,
		},
	})
}

// ListOrgMembers handles GET /api/admin/organizations/{id}/members.
func (h *AdminHandler) ListOrgMembers(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "org id required")
		return
	}

	members, err := h.DB.GetOrgMembers(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}

	response.Success(w, map[string]any{"members": serializeAdminOrgMembers(members)})
}

// UpdateOrg handles PATCH /api/admin/organizations/{id}.
func (h *AdminHandler) UpdateOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "org id required")
		return
	}

	var body struct {
		Status    *string `json:"status"`
		Plan      *string `json:"plan"`
		SeatLimit *int    `json:"seat_limit"`
		AdminNote *string `json:"admin_note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if _, err := h.DB.GetOrganizationByID(r.Context(), id); err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	changes := make([]string, 0, 4)
	if body.Status != nil {
		status := strings.TrimSpace(*body.Status)
		switch status {
		case "pending", "active", "suspended", "archived":
		default:
			response.BadRequest(w, "status must be pending, active, suspended, or archived")
			return
		}
		if err := h.DB.UpdateOrganizationStatus(r.Context(), id, status); err != nil {
			response.InternalError(w, err)
			return
		}
		changes = append(changes, fmt.Sprintf("status changed to %s", status))
	}
	if body.Plan != nil {
		plan := strings.ToLower(strings.TrimSpace(*body.Plan))
		switch plan {
		case "free", "student", "pro", "org":
		default:
			response.BadRequest(w, "plan must be free, student, pro, or org")
			return
		}
		if err := h.DB.UpdateOrgPlan(r.Context(), id, plan); err != nil {
			response.InternalError(w, err)
			return
		}
		changes = append(changes, fmt.Sprintf("plan changed to %s", strings.ToUpper(plan)))
	}
	if body.SeatLimit != nil {
		if *body.SeatLimit < 1 {
			response.BadRequest(w, "seat_limit must be at least 1")
			return
		}
		if err := h.DB.UpdateOrgSeatLimit(r.Context(), id, *body.SeatLimit); err != nil {
			response.InternalError(w, err)
			return
		}
		changes = append(changes, fmt.Sprintf("seat limit set to %d", *body.SeatLimit))
	}
	if body.AdminNote != nil {
		if err := h.DB.SetOrganizationAdminNote(r.Context(), id, strings.TrimSpace(*body.AdminNote)); err != nil {
			response.InternalError(w, err)
			return
		}
		changes = append(changes, "admin note updated")
	}
	updatedOrg, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if len(changes) > 0 {
		recipients, _ := h.DB.ListOrgManagerUserIDs(r.Context(), id)
		message := fmt.Sprintf("Organization %s was updated: %s.", updatedOrg.Name, strings.Join(changes, "; "))
		h.notifyUsers(r.Context(), recipients, "org_lifecycle_updated", "Organization updated", message, "/dashboard/org")
		h.emailUsers(r.Context(), recipients, "Organization updated", "Organization updated", message, "/dashboard/org")
	}

	response.Success(w, map[string]any{"message": "organization updated", "org": updatedOrg})
}

// DeleteOrg handles DELETE /api/admin/organizations/{id}.
func (h *AdminHandler) DeleteOrg(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil || !claims.IsAdmin {
		response.Forbidden(w, "admin only")
		return
	}

	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "org id required")
		return
	}

	if err := h.DB.DeleteOrganization(r.Context(), id); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "organization deleted"})
}

// ─── Abuse ────────────────────────────────────────────────────

// ListAbuseEvents handles GET /api/admin/abuse/events.
func (h *AdminHandler) ListAbuseEvents(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	limit := queryInt(r, "limit", 50)

	events, err := h.DB.ListAbuseEvents(r.Context(), severity, limit)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, events)
}

// ListBlockedIPs handles GET /api/admin/abuse/blocked.
func (h *AdminHandler) ListBlockedIPs(w http.ResponseWriter, r *http.Request) {
	ips, err := h.DB.ListBlockedIPs(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, ips)
}

// BlockIP handles POST /api/admin/abuse/blocked.
func (h *AdminHandler) BlockIP(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if body.IP == "" {
		response.BadRequest(w, "ip is required")
		return
	}

	blockedBy := claims.UserID
	blocked, err := h.DB.CreateBlockedIP(r.Context(), body.IP, body.Reason, false, 0, 0, &blockedBy)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Created(w, blocked)
}

// UnblockIP handles DELETE /api/admin/abuse/blocked/{id}.
func (h *AdminHandler) UnblockIP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "blocked ip id required")
		return
	}

	if err := h.DB.UnblockIP(r.Context(), id); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "IP unblocked"})
}

// ─── Verify Requests ─────────────────────────────────────────

// ListVerifyRequests handles GET /api/admin/verify-requests.
func (h *AdminHandler) ListVerifyRequests(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status") // optional filter: pending, reviewing, approved, rejected
	list, err := h.DB.ListVerifyRequests(r.Context(), status)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if list == nil {
		response.Success(w, []any{})
		return
	}
	response.Success(w, list)
}

// GetVerifyRequest handles GET /api/admin/verify-requests/{id}.
func (h *AdminHandler) GetVerifyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id is required")
		return
	}
	vr, err := h.DB.GetVerifyRequestByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "verify request not found")
		return
	}
	response.Success(w, vr)
}

// UpdateVerifyRequest handles PATCH /api/admin/verify-requests/{id}.
func (h *AdminHandler) UpdateVerifyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id is required")
		return
	}

	var body struct {
		Status                  string `json:"status"`
		RejectReason            string `json:"reject_reason"`
		ApprovalNote            string `json:"approval_note"`
		ApprovedDiscountPercent int    `json:"approved_discount_percent"`
		OrgDomain               string `json:"org_domain"`
		OrgSeatLimit            int    `json:"org_seat_limit"`
		OrgName                 string `json:"org_name"`
		ForceOverride           bool   `json:"force_override"` // set true to downgrade even paid subscribers
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	current, err := h.DB.GetVerifyRequestByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "verify request not found")
		return
	}

	allowed := map[string]bool{"reviewing": true, "approved": true, "rejected": true}
	if !allowed[body.Status] {
		response.BadRequest(w, "status must be one of: reviewing, approved, rejected")
		return
	}
	if body.ApprovedDiscountPercent < 0 || body.ApprovedDiscountPercent > 100 {
		response.BadRequest(w, "approved_discount_percent must be between 0 and 100")
		return
	}

	vr, planSkipped, err := h.DB.UpdateVerifyRequest(
		r.Context(),
		id,
		body.Status,
		body.RejectReason,
		body.ApprovalNote,
		body.ApprovedDiscountPercent,
		body.ForceOverride,
	)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	var approvedOrg *models.Organization
	if body.Status == "approved" && current.Type == "org" {
		user, err := h.DB.GetUserByID(r.Context(), current.UserID)
		if err != nil {
			response.InternalError(w, err)
			return
		}
		orgName := strings.TrimSpace(body.OrgName)
		if orgName == "" {
			orgName = strings.TrimSpace(current.OrgName)
		}
		if orgName == "" {
			orgName = strings.TrimSpace(user.Name)
		}
		if orgName == "" {
			orgName = "Organization"
		}
		orgDomain := strings.ToLower(strings.TrimSpace(body.OrgDomain))
		if orgDomain == "" {
			orgDomain = strings.ToLower(strings.TrimSpace(current.RequestedOrgDomain))
		}
		orgSeatLimit := body.OrgSeatLimit
		if orgSeatLimit < 1 {
			orgSeatLimit = current.RequestedOrgSeatLimit
		}
		if orgSeatLimit < 1 {
			orgSeatLimit = 25
		}

		switch {
		case current.ApprovedOrgID != nil:
			approvedOrg, err = h.DB.GetOrganizationByID(r.Context(), *current.ApprovedOrgID)
		default:
			existingOrg, _, getErr := h.DB.GetMyOrg(r.Context(), current.UserID)
			if getErr == nil && existingOrg != nil && existingOrg.OwnerID != nil && *existingOrg.OwnerID == current.UserID {
				approvedOrg = existingOrg
			} else {
				createdBy := current.UserID
				approvedOrg, err = h.DB.CreateOrganization(r.Context(), orgName, orgDomain, "org", current.UserID, "organization", orgSeatLimit, &createdBy)
			}
		}
		if err != nil {
			response.InternalError(w, err)
			return
		}
		if approvedOrg.OwnerID == nil || *approvedOrg.OwnerID != current.UserID {
			if err := h.DB.SetOrganizationOwner(r.Context(), approvedOrg.ID, current.UserID); err != nil {
				response.InternalError(w, err)
				return
			}
		}
		if orgDomain != "" && approvedOrg.Domain != orgDomain {
			if err := h.DB.SetOrganizationDomain(r.Context(), approvedOrg.ID, orgDomain); err != nil {
				response.InternalError(w, err)
				return
			}
		}
		if approvedOrg.Plan != "org" {
			if err := h.DB.UpdateOrgPlan(r.Context(), approvedOrg.ID, "org"); err != nil {
				response.InternalError(w, err)
				return
			}
		}
		if approvedOrg.SeatLimit != orgSeatLimit {
			if err := h.DB.UpdateOrgSeatLimit(r.Context(), approvedOrg.ID, orgSeatLimit); err != nil {
				response.InternalError(w, err)
				return
			}
		}
		if err := h.DB.SetOrganizationApprovedVerifyRequest(r.Context(), approvedOrg.ID, current.ID); err != nil {
			response.InternalError(w, err)
			return
		}
		if err := h.DB.SetOrganizationBillingDiscount(r.Context(), approvedOrg.ID, body.ApprovedDiscountPercent, strings.TrimSpace(body.ApprovalNote)); err != nil {
			response.InternalError(w, err)
			return
		}
		orgStatus := "pending"
		if user.SubscriptionPlan == "org" || user.Plan == "org" {
			orgStatus = "active"
			if user.Plan != "org" {
				if _, err := h.DB.UpdateUser(r.Context(), user.ID, map[string]any{"plan": "org"}); err != nil {
					response.InternalError(w, err)
					return
				}
				planSkipped = false
			}
		}
		if err := h.DB.UpdateOrganizationStatus(r.Context(), approvedOrg.ID, orgStatus); err != nil {
			response.InternalError(w, err)
			return
		}
		vr, err = h.DB.SetVerifyRequestApprovedOrg(r.Context(), current.ID, approvedOrg.ID, body.ApprovalNote, body.ApprovedDiscountPercent)
		if err != nil {
			response.InternalError(w, err)
			return
		}
		approvedOrg, _ = h.DB.GetOrganizationByID(r.Context(), approvedOrg.ID)
	}

	// Notify user about status change.
	link := "/dashboard/billing"
	title := "Verification updated"
	message := ""
	notifType := "verify_reviewing"
	switch body.Status {
	case "reviewing":
		title = "Your verification is being reviewed"
		message = "An admin is reviewing your " + vr.Type + " verification request."
		notifType = "verify_reviewing"
	case "approved":
		notifType = "verify_approved"
		if vr.Type == "org" {
			title = "Organization application approved"
			if approvedOrg != nil && approvedOrg.Status == "active" {
				message = "Your organization application was approved and your Organization workspace is active."
				link = "/dashboard/org"
			} else {
				message = "Your organization application was approved. Your workspace is prepared and will activate when your ORG plan is active."
				link = "/dashboard/org"
			}
			if body.ApprovalNote != "" {
				message += " Note: " + strings.TrimSpace(body.ApprovalNote)
			}
			if body.ApprovedDiscountPercent > 0 {
				message += fmt.Sprintf(" Approved contract discount: %d%%.", body.ApprovedDiscountPercent)
			}
		} else {
			title = "Verification approved"
			message = "Your " + vr.Type + " verification was approved."
			if !planSkipped {
				message += " Your plan has been updated."
			} else {
				message += " Your higher plan was kept unchanged."
			}
		}
	case "rejected":
		notifType = "verify_rejected"
		title = "Verification rejected"
		message = "Your " + vr.Type + " verification request was rejected."
		if body.RejectReason != "" {
			message += " Reason: " + body.RejectReason
		}
	}
	h.notifyUsers(context.Background(), []string{vr.UserID}, notifType, title, message, link)
	h.emailUsers(context.Background(), []string{vr.UserID}, title, title, message, link)

	response.Success(w, map[string]any{
		"verify_request": vr,
		"plan_skipped":   planSkipped,
		"organization":   approvedOrg,
	})
}

// DeleteVerifyRequest handles DELETE /api/admin/verify-requests/{id}.
// If the request was approved and the user's active plan matches the verified type,
// the user is automatically switched: to their subscription_plan if they have one, else free.
func (h *AdminHandler) DeleteVerifyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id is required")
		return
	}

	// Fetch the request before deleting so we know user + type + status.
	vr, err := h.DB.GetVerifyRequestByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "verify request not found")
		return
	}

	if err := h.DB.DeleteVerifyRequest(r.Context(), id); err != nil {
		response.InternalError(w, err)
		return
	}

	// If this was an approved request and the user's active plan is the verified type,
	// auto-fall-back: subscription_plan if available, otherwise free.
	if vr.Status == "approved" {
		user, err := h.DB.GetUserByID(r.Context(), vr.UserID)
		if err == nil && user.Plan == vr.Type {
			newPlan := "free"
			if user.SubscriptionPlan != "" {
				newPlan = user.SubscriptionPlan
			}
			if _, err := h.DB.UpdateUser(r.Context(), vr.UserID, map[string]any{"plan": newPlan}); err != nil {
				log.Printf("[admin] auto-plan fallback for user %s: %v", vr.UserID, err)
			} else {
				log.Printf("[admin] deleted approved verify (%s) for user %s — plan set to %s", vr.Type, vr.UserID, newPlan)
			}
		}
	}

	// Notify user their verification was removed.
	if h.Notify != nil {
		go h.Notify.Send(context.Background(), vr.UserID, "verify_deleted",
			"Verification removed",
			"Your "+vr.Type+" verification record was removed by an admin.",
			"/dashboard/billing")
	}

	response.Success(w, map[string]any{"message": "verify request deleted"})
}

// NotifyVerifyRequest handles POST /api/admin/verify-requests/{id}/notify.
// Stores an admin note and logs an email (sends when SMTP configured).
func (h *AdminHandler) NotifyVerifyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id is required")
		return
	}

	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Message == "" {
		response.BadRequest(w, "message is required")
		return
	}

	vr, err := h.DB.SetAdminNote(r.Context(), id, body.Message)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	// Fetch user email and push real-time notification.
	user, _ := h.DB.GetUserByID(r.Context(), vr.UserID)
	if user != nil {
		log.Printf("[verify] admin note for %s (%s): %s", user.Email, vr.Type, body.Message)
	}
	if h.Notify != nil {
		go h.Notify.Send(context.Background(), vr.UserID, "verify_message",
			"Message from admin",
			body.Message,
			"/dashboard/billing")
	}

	response.Success(w, map[string]any{
		"message":        "notification sent",
		"verify_request": vr,
	})
}

// ResetVerifyRequest handles POST /api/admin/verify-requests/{id}/reset.
// Resets any request (including approved) back to pending and clears document_url,
// so the user must upload a fresh document.
func (h *AdminHandler) ResetVerifyRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id is required")
		return
	}

	var body struct {
		Note string `json:"note"` // optional message to the user
	}
	json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck — note is optional

	vr, err := h.DB.ResetVerifyRequest(r.Context(), id, body.Note)
	if err != nil {
		response.NotFound(w, "verify request not found")
		return
	}

	// Notify the user to resubmit.
	if h.Notify != nil {
		msg := body.Note
		if msg == "" {
			msg = "An admin has requested that you resubmit your verification documents."
		}
		go h.Notify.Send(context.Background(), vr.UserID, "verify_resubmit",
			"Resubmission required",
			msg,
			"/auth/verify-account?type="+vr.Type)
	}

	response.Success(w, vr)
}

// ─── Server Config ───────────────────────────────────────────

// GetServerConfig handles GET /api/admin/server-limits.
func (h *AdminHandler) GetServerConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.DB.GetServerConfig(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, cfg)
}

// UpdateServerConfig handles PATCH /api/admin/server-limits.
func (h *AdminHandler) UpdateServerConfig(w http.ResponseWriter, r *http.Request) {
	var body models.ServerConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	cfg, err := h.DB.UpdateServerConfig(r.Context(), body)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, cfg)
}

// ─── Trial management ─────────────────────────────────────────

// SetUserTrial handles POST /api/admin/users/{id}/trial — grants or clears a free trial.
func (h *AdminHandler) SetUserTrial(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	var body struct {
		Days int `json:"days"` // 0 = clear trial
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	var endsAt *time.Time
	if body.Days > 0 {
		t := time.Now().Add(time.Duration(body.Days) * 24 * time.Hour)
		endsAt = &t
	}
	if err := h.DB.SetTrial(r.Context(), userID, endsAt); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"trial_ends_at": endsAt})
}

// ─── helpers ─────────────────────────────────────────────────

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}
