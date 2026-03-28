package handlers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	jwtauth "github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
	"github.com/jackc/pgx/v5"
)

// OrgHandler handles all org-management endpoints.
type OrgHandler struct {
	DB          *db.DB
	Mailer      *mailer.Mailer
	Notify      *notify.Service
	FrontendURL string
}

type importRow struct {
	Email               string `json:"email"`
	Name                string `json:"name"`
	Role                string `json:"role"`
	Plan                string `json:"plan"`
	IsAdmin             *bool  `json:"is_admin"`
	TunnelLimit         *int   `json:"tunnel_limit"`
	TeamLimit           *int   `json:"team_limit"`
	SubdomainLimit      *int   `json:"subdomain_limit"`
	BandwidthGB         *int   `json:"bandwidth_gb"`
	CustomDomainAllowed *bool  `json:"custom_domain_allowed"`
}

type parsedImportFile struct {
	FileName       string
	Format         string
	Headers        []string
	MissingHeaders []string
	Rows           []importRow
}

type analyzedImportRow struct {
	Source         importRow
	Role           string
	Plan           string
	ExistingUser   *models.User
	ExistingMember *models.OrgMember
	Preview        *models.ImportPreviewRow
}

// ─── Caller helpers ───────────────────────────────────────────

func (h *OrgHandler) callerOrgRole(r *http.Request, orgID string, ownerID *string, claims *jwtauth.JWTClaims) (string, bool) {
	if claims == nil {
		return "", false
	}
	if ownerID != nil && *ownerID == claims.UserID {
		return "owner", true
	}
	m, err := h.DB.GetOrgMembership(r.Context(), orgID, claims.UserID)
	if err != nil {
		return "", false
	}
	return m.Role, true
}

func canManageOrg(role string) bool {
	return role == "owner" || role == "admin"
}

func dedupeUserIDs(ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func normalizeResourceRequestType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "tunnel":
		return "tunnel"
	case "subdomain":
		return "subdomain"
	case "domain":
		return "domain"
	case "custom-domain", "custom_domain":
		return "custom_domain"
	case "bandwidth":
		return "bandwidth"
	case "team":
		return "team"
	case "plan":
		return "plan"
	case "billing":
		return "billing"
	default:
		return ""
	}
}

func (h *OrgHandler) notifyUsers(ctx context.Context, userIDs []string, notifType, title, body, link string) {
	if h.Notify == nil {
		return
	}
	for _, userID := range dedupeUserIDs(userIDs) {
		go h.Notify.Send(ctx, userID, notifType, title, body, link)
	}
}

func (h *OrgHandler) emailUsers(ctx context.Context, userIDs []string, subject, title, body, link string) {
	if h.Mailer == nil || !h.Mailer.Enabled() {
		return
	}
	linkLabel := "Open Mekong Tunnel"
	htmlBody := `<div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;padding:24px;color:#111827">` +
		`<h2 style="margin:0 0 12px;">` + title + `</h2>` +
		`<p style="line-height:1.6;margin:0 0 16px;">` + body + `</p>`
	if link != "" {
		htmlBody += `<p style="margin:0 0 16px;"><a href="` + strings.TrimRight(h.FrontendURL, "/") + link + `" style="display:inline-block;padding:10px 16px;background:#ca8a04;color:#111827;text-decoration:none;border-radius:10px;font-weight:700">` + linkLabel + `</a></p>`
	}
	htmlBody += `</div>`

	for _, userID := range dedupeUserIDs(userIDs) {
		user, err := h.DB.GetUserByID(ctx, userID)
		if err != nil || user == nil || strings.TrimSpace(user.Email) == "" {
			continue
		}
		go func(email string) {
			if err := h.Mailer.Send(email, subject, htmlBody); err != nil {
				log.Printf("[org] email %s: %v", email, err)
			}
		}(user.Email)
	}
}

func (h *OrgHandler) orgManagerIDs(ctx context.Context, orgID string) []string {
	ids, err := h.DB.ListOrgManagerUserIDs(ctx, orgID)
	if err != nil {
		return nil
	}
	return dedupeUserIDs(ids)
}

func (h *OrgHandler) applyApprovedResourceRequest(ctx context.Context, rr *models.ResourceRequest) error {
	if rr == nil {
		return nil
	}
	alloc, err := h.DB.GetAllocation(ctx, rr.OrgID, rr.UserID)
	if err != nil {
		return err
	}
	approvedAmount := rr.AmountApproved
	if approvedAmount < 1 {
		approvedAmount = rr.AmountRequested
	}
	switch rr.Type {
	case "tunnel":
		alloc.TunnelLimit += approvedAmount
	case "subdomain":
		alloc.SubdomainLimit += approvedAmount
	case "bandwidth":
		alloc.BandwidthGB += approvedAmount
	case "team":
		alloc.TeamLimit += approvedAmount
	case "domain", "custom_domain":
		alloc.CustomDomainAllowed = true
	case "plan", "billing":
		return nil
	default:
		return nil
	}
	updatedBy := ""
	if rr.ReviewedBy != nil {
		updatedBy = *rr.ReviewedBy
	}
	return h.DB.UpsertAllocation(ctx, rr.OrgID, rr.UserID, alloc.TunnelLimit, alloc.TeamLimit, alloc.SubdomainLimit, alloc.BandwidthGB, alloc.CustomDomainAllowed, updatedBy)
}

func (h *OrgHandler) authorizedImportOrg(w http.ResponseWriter, r *http.Request) (*models.Organization, *jwtauth.JWTClaims, bool) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return nil, nil, false
	}
	id := r.PathValue("id")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return nil, nil, false
	}
	if !claims.IsAdmin {
		role, ok := h.callerOrgRole(r, id, org.OwnerID, claims)
		if !ok || !canManageOrg(role) {
			response.Forbidden(w, "owner or admin only")
			return nil, nil, false
		}
	}
	return org, claims, true
}

func parseOptionalCSVInt(value string) *int {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return nil
	}
	return &n
}

func parseOptionalCSVBool(value string) *bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}
	var out bool
	switch value {
	case "1", "true", "yes", "y":
		out = true
	case "0", "false", "no", "n":
		out = false
	default:
		return nil
	}
	return &out
}

func normalizeImportRole(role string, isAdmin *bool) string {
	if isAdmin != nil && *isAdmin {
		return "admin"
	}
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin":
		return "admin"
	case "org", "member", "user", "":
		return "member"
	default:
		return "member"
	}
}

func normalizeImportPlan(plan string) string {
	switch strings.ToLower(strings.TrimSpace(plan)) {
	case "":
		return ""
	case "free", "student", "pro", "org":
		return strings.ToLower(strings.TrimSpace(plan))
	default:
		return ""
	}
}

func normalizeImportInputRow(row importRow) importRow {
	row.Email = strings.ToLower(strings.TrimSpace(row.Email))
	row.Name = strings.TrimSpace(row.Name)
	row.Role = strings.TrimSpace(row.Role)
	row.Plan = strings.TrimSpace(row.Plan)
	if row.TunnelLimit != nil && *row.TunnelLimit < 0 {
		zero := 0
		row.TunnelLimit = &zero
	}
	if row.TeamLimit != nil && *row.TeamLimit < 0 {
		zero := 0
		row.TeamLimit = &zero
	}
	if row.SubdomainLimit != nil && *row.SubdomainLimit < 0 {
		zero := 0
		row.SubdomainLimit = &zero
	}
	if row.BandwidthGB != nil && *row.BandwidthGB < 1 {
		one := 1
		row.BandwidthGB = &one
	}
	return row
}

func buildImportCSV(rows []importRow) string {
	if len(rows) == 0 {
		return ""
	}
	boolString := func(value *bool) string {
		if value == nil {
			return ""
		}
		if *value {
			return "true"
		}
		return "false"
	}
	intString := func(value *int) string {
		if value == nil {
			return ""
		}
		return strconv.Itoa(*value)
	}
	escape := func(value string) string {
		if strings.ContainsAny(value, ",\"\n") {
			return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
		}
		return value
	}

	headers := []string{"email", "name", "role", "plan", "is_admin", "tunnel_limit", "team_limit", "subdomain_limit", "bandwidth_gb", "custom_domain_allowed"}
	lines := []string{strings.Join(headers, ",")}
	for _, row := range rows {
		role := normalizeImportRole(row.Role, row.IsAdmin)
		isAdmin := "false"
		if role == "admin" {
			isAdmin = "true"
		}
		cols := []string{
			escape(strings.ToLower(strings.TrimSpace(row.Email))),
			escape(strings.TrimSpace(row.Name)),
			escape(role),
			escape(normalizeImportPlan(row.Plan)),
			isAdmin,
			intString(row.TunnelLimit),
			intString(row.TeamLimit),
			intString(row.SubdomainLimit),
			intString(row.BandwidthGB),
			boolString(row.CustomDomainAllowed),
		}
		lines = append(lines, strings.Join(cols, ","))
	}
	return strings.Join(lines, "\n") + "\n"
}

func importRowMessage(action string, errors, warnings []string) string {
	if len(errors) > 0 {
		return errors[0]
	}
	if len(warnings) > 0 {
		return warnings[0]
	}
	return action
}

func parseImportUpload(r *http.Request) (*parsedImportFile, error) {
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return nil, fmt.Errorf("expected multipart form with 'file' field")
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		return nil, fmt.Errorf("missing file field")
	}
	defer file.Close()

	parsed := &parsedImportFile{
		FileName: header.Filename,
		Format:   "csv",
	}
	filename := strings.ToLower(header.Filename)

	if strings.HasSuffix(filename, ".json") {
		parsed.Format = "json"
		data, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("failed to read file")
		}
		if err := json.Unmarshal(data, &parsed.Rows); err != nil {
			return nil, fmt.Errorf("invalid JSON file")
		}
		for i := range parsed.Rows {
			parsed.Rows[i] = normalizeImportInputRow(parsed.Rows[i])
		}
		return parsed, nil
	}

	reader := csv.NewReader(file)
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("invalid CSV file")
	}
	if len(records) < 2 {
		return nil, fmt.Errorf("CSV must have a header row and at least one data row")
	}

	parsed.Headers = make([]string, 0, len(records[0]))
	colIdx := map[string]int{}
	for i, col := range records[0] {
		normalized := strings.ToLower(strings.TrimSpace(col))
		parsed.Headers = append(parsed.Headers, normalized)
		colIdx[normalized] = i
	}
	if _, ok := colIdx["email"]; !ok {
		parsed.MissingHeaders = append(parsed.MissingHeaders, "email")
	}

	for _, rec := range records[1:] {
		get := func(col string) string {
			i, ok := colIdx[col]
			if !ok || i >= len(rec) {
				return ""
			}
			return strings.TrimSpace(rec[i])
		}
		parsed.Rows = append(parsed.Rows, normalizeImportInputRow(importRow{
			Email:               get("email"),
			Name:                get("name"),
			Role:                get("role"),
			Plan:                get("plan"),
			IsAdmin:             parseOptionalCSVBool(get("is_admin")),
			TunnelLimit:         parseOptionalCSVInt(get("tunnel_limit")),
			TeamLimit:           parseOptionalCSVInt(get("team_limit")),
			SubdomainLimit:      parseOptionalCSVInt(get("subdomain_limit")),
			BandwidthGB:         parseOptionalCSVInt(get("bandwidth_gb")),
			CustomDomainAllowed: parseOptionalCSVBool(get("custom_domain_allowed")),
		}))
	}

	return parsed, nil
}

func (h *OrgHandler) buildImportPreview(ctx context.Context, org *models.Organization, parsed *parsedImportFile) (*models.ImportPreview, []*analyzedImportRow, error) {
	currentCount := org.MemberCount
	if currentCount == 0 {
		currentCount, _ = h.DB.CountOrgMembers(ctx, org.ID)
	}
	projectedCount := currentCount
	preview := &models.ImportPreview{
		FileName:       parsed.FileName,
		Format:         parsed.Format,
		Headers:        parsed.Headers,
		MissingHeaders: parsed.MissingHeaders,
		Rows:           []*models.ImportPreviewRow{},
		Summary: &models.ImportPreviewSummary{
			TotalRows:      len(parsed.Rows),
			CurrentSeats:   currentCount,
			ProjectedSeats: currentCount,
			SeatLimit:      org.SeatLimit,
		},
	}
	if len(parsed.MissingHeaders) > 0 {
		preview.FileErrors = append(preview.FileErrors, fmt.Sprintf("missing required column(s): %s", strings.Join(parsed.MissingHeaders, ", ")))
	}

	seenEmails := map[string]int{}
	analyzed := make([]*analyzedImportRow, 0, len(parsed.Rows))

	for i, row := range parsed.Rows {
		rowNumber := i + 1
		if parsed.Format == "csv" {
			rowNumber = i + 2
		}
		pr := &models.ImportPreviewRow{
			Row:    rowNumber,
			Email:  row.Email,
			Name:   row.Name,
			Role:   normalizeImportRole(row.Role, row.IsAdmin),
			Plan:   normalizeImportPlan(row.Plan),
			Status: "valid",
			Action: "update organization membership",
		}

		rowErrors := make([]string, 0, 2)
		warnings := make([]string, 0, 4)

		if row.Email == "" {
			rowErrors = append(rowErrors, "email is required")
		}
		if row.Email != "" {
			seenEmails[row.Email]++
			if seenEmails[row.Email] > 1 {
				rowErrors = append(rowErrors, "duplicate email in import file")
			}
		}

		role := normalizeImportRole(row.Role, row.IsAdmin)
		plan := normalizeImportPlan(row.Plan)
		if row.Plan != "" && plan == "" {
			rowErrors = append(rowErrors, fmt.Sprintf("invalid personal plan %q", row.Plan))
		}

		var existingUser *models.User
		var existingMember *models.OrgMember
		if row.Email != "" {
			user, err := h.DB.GetUserByEmail(ctx, row.Email)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return nil, nil, err
			}
			if errors.Is(err, pgx.ErrNoRows) {
				user = nil
			}
			existingUser = user
			if existingUser != nil {
				member, memberErr := h.DB.GetOrgMembership(ctx, org.ID, existingUser.ID)
				if memberErr != nil && !errors.Is(memberErr, pgx.ErrNoRows) {
					return nil, nil, memberErr
				}
				if errors.Is(memberErr, pgx.ErrNoRows) {
					member = nil
				}
				existingMember = member
			}
		}

		createUser := existingUser == nil
		addMember := existingMember == nil
		updateUser := false

		if existingUser != nil {
			pr.ExistingUser = true
			if row.Name != "" && row.Name != existingUser.Name {
				updateUser = true
				warnings = append(warnings, fmt.Sprintf("display name will update from %q to %q", existingUser.Name, row.Name))
			}
			if plan != "" && plan != existingUser.Plan {
				updateUser = true
				warnings = append(warnings, fmt.Sprintf("personal plan will update from %s to %s", strings.ToUpper(existingUser.Plan), strings.ToUpper(plan)))
			}
		} else if row.Name == "" && row.Email != "" {
			warnings = append(warnings, "display name is blank, so the email prefix will be used")
		}

		if existingMember != nil {
			pr.ExistingMember = true
			pr.Action = "update existing organization member"
			if existingMember.Role != role {
				warnings = append(warnings, fmt.Sprintf("organization role will update from %s to %s", existingMember.Role, role))
			}
		} else if existingUser != nil {
			pr.Action = "add existing user to organization"
			pr.ConsumesSeat = true
		} else {
			pr.Action = "create provisioned user and add to organization"
			pr.ConsumesSeat = true
		}

		if pr.ConsumesSeat && org.SeatLimit > 0 && projectedCount >= org.SeatLimit {
			rowErrors = append(rowErrors, fmt.Sprintf("organization seat limit reached (%d)", org.SeatLimit))
		}

		if len(rowErrors) == 0 && pr.ConsumesSeat {
			projectedCount++
		}

		if len(rowErrors) > 0 {
			pr.Status = "error"
			pr.Errors = rowErrors
			preview.Summary.ErrorRows++
		} else if len(warnings) > 0 {
			pr.Status = "warning"
			pr.Warnings = warnings
			preview.Summary.WarningRows++
		} else {
			preview.Summary.ValidRows++
		}
		pr.Message = importRowMessage(pr.Action, rowErrors, warnings)

		if len(rowErrors) == 0 {
			if createUser {
				preview.Summary.CreateUsers++
			}
			if addMember {
				preview.Summary.AddMembers++
			}
			if updateUser {
				preview.Summary.UpdateUsers++
			}
			if existingMember != nil {
				preview.Summary.ExistingMembers++
			}
		}

		preview.Rows = append(preview.Rows, pr)
		analyzed = append(analyzed, &analyzedImportRow{
			Source:         row,
			Role:           role,
			Plan:           plan,
			ExistingUser:   existingUser,
			ExistingMember: existingMember,
			Preview:        pr,
		})
	}

	preview.Summary.ProjectedSeats = projectedCount
	if preview.Summary.ErrorRows > 0 {
		failedRows := make([]importRow, 0, preview.Summary.ErrorRows)
		for _, row := range analyzed {
			if row.Preview.Status == "error" {
				failedRows = append(failedRows, row.Source)
			}
		}
		preview.FailedCSV = buildImportCSV(failedRows)
	}

	return preview, analyzed, nil
}

// ─── POST /api/org/create ────────────────────────────────────

func (h *OrgHandler) CreateMyOrg(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	if !claims.IsAdmin && claims.Plan != "org" {
		response.Forbidden(w, "organization plan required")
		return
	}
	if existingOrg, _, err := h.DB.GetMyOrg(r.Context(), claims.UserID); err == nil && existingOrg != nil {
		response.Error(w, http.StatusConflict, "you are already in an organization")
		return
	}

	var body struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Domain = strings.TrimSpace(body.Domain)
	if body.Name == "" {
		response.BadRequest(w, "name is required")
		return
	}

	createdBy := claims.UserID
	org, err := h.DB.CreateOrganization(r.Context(), body.Name, body.Domain, "org", claims.UserID, "organization", 100, &createdBy)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Created(w, org)
}

// ─── GET /api/org/mine ─────────────────────────────────────────
// Returns the org the current user owns or belongs to.

func (h *OrgHandler) GetMine(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	org, member, err := h.DB.GetMyOrg(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "you are not in any organization")
		return
	}
	alloc, _ := h.DB.GetAllocation(r.Context(), org.ID, claims.UserID)
	myReqs, _ := h.DB.GetMyResourceRequests(r.Context(), claims.UserID)
	if myReqs == nil {
		myReqs = []*models.ResourceRequest{}
	}
	response.Success(w, map[string]any{
		"org":        org,
		"my_role":    member.Role,
		"allocation": alloc,
		"requests":   myReqs,
	})
}

// ─── GET /api/org/{id} ────────────────────────────────────────

func (h *OrgHandler) GetOrg(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	role, ok := h.callerOrgRole(r, id, org.OwnerID, claims)
	if !ok {
		response.Forbidden(w, "you are not a member of this organization")
		return
	}
	response.Success(w, map[string]any{"org": org, "my_role": role})
}

// ─── GET /api/org/{id}/members ────────────────────────────────

func (h *OrgHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	role, ok := h.callerOrgRole(r, id, org.OwnerID, claims)
	if !ok || !canManageOrg(role) {
		response.Forbidden(w, "owner or admin only")
		return
	}

	q := r.URL.Query()
	if q.Has("limit") || q.Has("offset") {
		limit, _ := strconv.Atoi(q.Get("limit"))
		offset, _ := strconv.Atoi(q.Get("offset"))
		members, total, err := h.DB.ListOrgMembersPage(r.Context(), id, limit, offset)
		if err != nil {
			response.InternalError(w, err)
			return
		}
		if members == nil {
			members = []*models.OrgMember{}
		}
		w.Header().Set("X-Total-Count", strconv.Itoa(total))
		w.Header().Set("X-Limit", strconv.Itoa(limit))
		w.Header().Set("X-Offset", strconv.Itoa(offset))
		response.Success(w, map[string]any{
			"members":    members,
			"total":      total,
			"seat_limit": org.SeatLimit,
		})
		return
	}

	members, err := h.DB.ListOrgMembers(r.Context(), id)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if members == nil {
		members = []*models.OrgMember{}
	}
	count, _ := h.DB.CountOrgMembers(r.Context(), id)
	response.Success(w, map[string]any{
		"members":    members,
		"count":      count,
		"seat_limit": org.SeatLimit,
	})
}

// ─── DELETE /api/org/{id}/members/{userId} ─────────────────────

func (h *OrgHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	userID := r.PathValue("userId")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	role, ok := h.callerOrgRole(r, id, org.OwnerID, claims)
	if !ok || !canManageOrg(role) {
		response.Forbidden(w, "owner or admin only")
		return
	}
	if err := h.DB.RemoveOrgMember(r.Context(), id, userID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"ok": true})
}

// ─── PATCH /api/org/{id}/members/{userId}/allocation ──────────

func (h *OrgHandler) SetAllocation(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	userID := r.PathValue("userId")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	role, ok := h.callerOrgRole(r, id, org.OwnerID, claims)
	if !ok || !canManageOrg(role) {
		response.Forbidden(w, "owner or admin only")
		return
	}
	var body struct {
		TunnelLimit         int  `json:"tunnel_limit"`
		TeamLimit           int  `json:"team_limit"`
		SubdomainLimit      int  `json:"subdomain_limit"`
		CustomDomainAllowed bool `json:"custom_domain_allowed"`
		BandwidthGB         int  `json:"bandwidth_gb"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	if body.BandwidthGB < 1 {
		body.BandwidthGB = 1
	}
	if body.TunnelLimit < 0 {
		body.TunnelLimit = 0
	}
	if body.TeamLimit < 0 {
		body.TeamLimit = 0
	}
	if err := h.DB.UpsertAllocation(r.Context(), id, userID, body.TunnelLimit, body.TeamLimit, body.SubdomainLimit, body.BandwidthGB, body.CustomDomainAllowed, claims.UserID); err != nil {
		response.InternalError(w, err)
		return
	}
	message := fmt.Sprintf("Your organization allocation is now %d tunnels, %d teams, %d subdomains, %d GB bandwidth, custom domains: %t.", body.TunnelLimit, body.TeamLimit, body.SubdomainLimit, body.BandwidthGB, body.CustomDomainAllowed)
	h.notifyUsers(r.Context(), []string{userID}, "org_allocation_changed", "Organization allocation updated", message, "/dashboard/org")
	h.emailUsers(r.Context(), []string{userID}, "Your organization allocation changed", "Organization allocation updated", message, "/dashboard/org")
	response.Success(w, map[string]any{"ok": true})
}

// ─── GET /api/org/{id}/requests ───────────────────────────────

func (h *OrgHandler) ListRequests(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	role, ok := h.callerOrgRole(r, id, org.OwnerID, claims)
	if !ok || !canManageOrg(role) {
		response.Forbidden(w, "owner or admin only")
		return
	}
	status := r.URL.Query().Get("status")
	reqs, err := h.DB.ListResourceRequests(r.Context(), id, status)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if reqs == nil {
		reqs = []*models.ResourceRequest{}
	}
	response.Success(w, reqs)
}

// ─── PATCH /api/org/{id}/requests/{reqId} ─────────────────────

func (h *OrgHandler) ReviewRequest(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	reqID := r.PathValue("reqId")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	role, ok := h.callerOrgRole(r, id, org.OwnerID, claims)
	if !ok || !canManageOrg(role) {
		response.Forbidden(w, "owner or admin only")
		return
	}
	var body struct {
		Status         string `json:"status"` // approved | denied | needs_discussion
		ReviewerNote   string `json:"reviewer_note"`
		ApprovedAmount int    `json:"approved_amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	body.Status = strings.TrimSpace(body.Status)
	body.ReviewerNote = strings.TrimSpace(body.ReviewerNote)
	if body.Status != "approved" && body.Status != "denied" && body.Status != "needs_discussion" {
		response.BadRequest(w, "status must be 'approved', 'denied', or 'needs_discussion'")
		return
	}
	rr, err := h.DB.GetResourceRequestByID(r.Context(), reqID)
	if err != nil || rr.OrgID != id {
		response.NotFound(w, "request not found")
		return
	}
	approvedAmount := body.ApprovedAmount
	if rr.Type == "billing" {
		if approvedAmount < 0 || approvedAmount > 100 {
			response.BadRequest(w, "approved_amount must be between 0 and 100 for billing requests")
			return
		}
		if body.Status == "approved" && approvedAmount == 0 {
			approvedAmount = rr.AmountRequested
		}
	} else {
		if approvedAmount < 0 {
			response.BadRequest(w, "approved_amount must be zero or positive")
			return
		}
		if body.Status == "approved" && approvedAmount == 0 {
			approvedAmount = rr.AmountRequested
		}
	}
	if err := h.DB.ReviewResourceRequest(r.Context(), reqID, body.Status, claims.UserID, body.ReviewerNote, approvedAmount); err != nil {
		response.InternalError(w, err)
		return
	}
	if body.Status == "approved" {
		rr.ReviewedBy = &claims.UserID
		rr.AmountApproved = approvedAmount
		if err := h.applyApprovedResourceRequest(r.Context(), rr); err != nil {
			response.InternalError(w, err)
			return
		}
	}
	if body.ReviewerNote != "" {
		_, _ = h.DB.AddResourceRequestComment(r.Context(), reqID, claims.UserID, role, "review", body.ReviewerNote)
	}
	updated, err := h.DB.GetResourceRequestByID(r.Context(), reqID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	var notifType string
	var title string
	switch body.Status {
	case "approved":
		notifType = "org_request_approved"
		title = "Organization request approved"
	case "denied":
		notifType = "org_request_denied"
		title = "Organization request denied"
	default:
		notifType = "org_request_discussion"
		title = "Organization request needs discussion"
	}
	message := fmt.Sprintf("Your %s request was marked %s.", updated.Type, strings.ReplaceAll(body.Status, "_", " "))
	if updated.Type == "billing" && updated.Status == "approved" && updated.AmountApproved > 0 {
		message += fmt.Sprintf(" Approved discount: %d%%.", updated.AmountApproved)
	}
	if body.ReviewerNote != "" {
		message += " Note: " + body.ReviewerNote
	}
	h.notifyUsers(r.Context(), []string{updated.UserID}, notifType, title, message, "/dashboard/org")
	h.emailUsers(r.Context(), []string{updated.UserID}, title, title, message, "/dashboard/org")
	response.Success(w, updated)
}

// ─── POST /api/org/request ────────────────────────────────────
// Member submits a resource request.

func (h *OrgHandler) SubmitRequest(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	var body struct {
		Type   string `json:"type"`
		Amount int    `json:"amount"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	// Find which org this user belongs to
	org, member, err := h.DB.GetMyOrg(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "you are not in any organization")
		return
	}
	body.Type = normalizeResourceRequestType(body.Type)
	body.Reason = strings.TrimSpace(body.Reason)
	if body.Type == "" {
		response.BadRequest(w, "invalid request type")
		return
	}
	if body.Type == "billing" {
		if body.Amount < 1 || body.Amount > 100 {
			response.BadRequest(w, "billing discount request must be between 1 and 100 percent")
			return
		}
	} else if body.Amount < 1 {
		body.Amount = 1
	}
	rr, err := h.DB.CreateResourceRequest(r.Context(), org.ID, claims.UserID, body.Type, body.Reason, body.Amount)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	managerIDs := h.orgManagerIDs(r.Context(), org.ID)
	message := fmt.Sprintf("%s requested %d %s resource(s). %s", claims.Email, body.Amount, body.Type, body.Reason)
	if body.Type == "billing" {
		message = fmt.Sprintf("%s requested a %d%% billing discount. %s", claims.Email, body.Amount, body.Reason)
	}
	h.notifyUsers(r.Context(), managerIDs, "org_request_submitted", "New organization request", message, "/dashboard/org")
	h.emailUsers(r.Context(), managerIDs, "New organization request", "New organization request", message, "/dashboard/org")
	_ = member
	response.Success(w, rr)
}

// ─── POST /api/org/{id}/requests/{reqId}/comments ────────────────────────────

func (h *OrgHandler) AddRequestComment(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	reqID := r.PathValue("reqId")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	role, ok := h.callerOrgRole(r, id, org.OwnerID, claims)
	if !ok {
		response.Forbidden(w, "you are not a member of this organization")
		return
	}
	reqRow, err := h.DB.GetResourceRequestByID(r.Context(), reqID)
	if err != nil || reqRow.OrgID != id {
		response.NotFound(w, "request not found")
		return
	}
	if reqRow.UserID != claims.UserID && !canManageOrg(role) {
		response.Forbidden(w, "only the requester or an org manager can comment")
		return
	}
	var body struct {
		Body string `json:"body"`
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	body.Body = strings.TrimSpace(body.Body)
	body.Kind = strings.TrimSpace(body.Kind)
	if body.Body == "" {
		response.BadRequest(w, "body is required")
		return
	}
	if body.Kind == "" {
		body.Kind = "comment"
	}
	comment, err := h.DB.AddResourceRequestComment(r.Context(), reqID, claims.UserID, role, body.Kind, body.Body)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if user, err := h.DB.GetUserByID(r.Context(), claims.UserID); err == nil && user != nil {
		comment.AuthorName = user.Name
		comment.AuthorEmail = user.Email
	}
	recipients := []string{}
	if reqRow.UserID == claims.UserID {
		recipients = append(recipients, h.orgManagerIDs(r.Context(), id)...)
	} else {
		recipients = append(recipients, reqRow.UserID)
	}
	message := fmt.Sprintf("%s commented on the %s request: %s", claims.Email, reqRow.Type, body.Body)
	h.notifyUsers(r.Context(), recipients, "org_request_comment", "New organization request comment", message, "/dashboard/org")
	h.emailUsers(r.Context(), recipients, "Organization request comment", "New organization request comment", message, "/dashboard/org")
	response.Created(w, comment)
}

// ─── POST /api/org/{id}/import/preview ───────────────────────

func (h *OrgHandler) PreviewImport(w http.ResponseWriter, r *http.Request) {
	org, _, ok := h.authorizedImportOrg(w, r)
	if !ok {
		return
	}
	parsed, err := parseImportUpload(r)
	if err != nil {
		response.BadRequest(w, err.Error())
		return
	}
	preview, _, err := h.buildImportPreview(r.Context(), org, parsed)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, preview)
}

// ─── POST /api/org/{id}/import ────────────────────────────────
// Bulk import members from a CSV or JSON file.

func (h *OrgHandler) BulkImport(w http.ResponseWriter, r *http.Request) {
	org, claims, ok := h.authorizedImportOrg(w, r)
	if !ok {
		return
	}
	parsed, err := parseImportUpload(r)
	if err != nil {
		response.BadRequest(w, err.Error())
		return
	}
	preview, analyzed, err := h.buildImportPreview(r.Context(), org, parsed)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	result := &models.ImportResult{
		Total:   len(analyzed),
		Summary: preview.Summary,
	}
	failedRows := make([]importRow, 0)

	for _, row := range analyzed {
		if row.Preview.Status == "error" {
			result.Errors = append(result.Errors, fmt.Sprintf("row %d (%s): %s", row.Preview.Row, row.Preview.Email, row.Preview.Message))
			result.Skipped++
			failedRows = append(failedRows, row.Source)
			continue
		}

		var userID string
		if row.ExistingUser != nil {
			userID = row.ExistingUser.ID
			update := map[string]any{}
			if row.Source.Name != "" && row.Source.Name != row.ExistingUser.Name {
				update["name"] = row.Source.Name
			}
			if row.Plan != "" && row.Plan != row.ExistingUser.Plan {
				update["plan"] = row.Plan
			}
			if len(update) > 0 {
				if _, err := h.DB.UpdateUser(r.Context(), row.ExistingUser.ID, update); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("%s: update existing user: %v", row.Source.Email, err))
					result.Skipped++
					failedRows = append(failedRows, row.Source)
					continue
				}
			}
		} else {
			tempPass := generateTempPassword(10)
			hash, err := jwtauth.HashPassword(tempPass)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: failed to hash password: %v", row.Source.Email, err))
				result.Skipped++
				failedRows = append(failedRows, row.Source)
				continue
			}
			name := row.Source.Name
			if name == "" {
				name = strings.Split(row.Source.Email, "@")[0]
			}
			newUser, err := h.DB.CreateProvisionedUser(r.Context(), row.Source.Email, name, hash, org.ID)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", row.Source.Email, err))
				result.Skipped++
				failedRows = append(failedRows, row.Source)
				continue
			}
			userID = newUser.ID
			if row.Plan != "" && row.Plan != newUser.Plan {
				if _, err := h.DB.UpdateUser(r.Context(), newUser.ID, map[string]any{"plan": row.Plan}); err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("%s: set plan: %v", row.Source.Email, err))
					result.Skipped++
					failedRows = append(failedRows, row.Source)
					continue
				}
			}
			if h.Mailer != nil {
				go h.Mailer.SendProvisionedWelcome(row.Source.Email, name, org.Name, tempPass, h.FrontendURL)
			} else {
				log.Printf("[import] provisioned %s temp password: %s", row.Source.Email, tempPass)
			}
			result.Created++
		}

		if err := h.DB.AddOrgMember(r.Context(), org.ID, userID, row.Role); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: add member: %v", row.Source.Email, err))
			result.Skipped++
			failedRows = append(failedRows, row.Source)
			continue
		}

		if row.Source.TunnelLimit != nil || row.Source.TeamLimit != nil || row.Source.SubdomainLimit != nil || row.Source.BandwidthGB != nil || row.Source.CustomDomainAllowed != nil {
			tunnelLimit := 1
			if row.Source.TunnelLimit != nil {
				tunnelLimit = *row.Source.TunnelLimit
			}
			teamLimit := 1
			if row.Source.TeamLimit != nil {
				teamLimit = *row.Source.TeamLimit
			}
			subdomainLimit := 0
			if row.Source.SubdomainLimit != nil {
				subdomainLimit = *row.Source.SubdomainLimit
			}
			bandwidthGB := 1
			if row.Source.BandwidthGB != nil {
				bandwidthGB = *row.Source.BandwidthGB
			}
			customDomainAllowed := false
			if row.Source.CustomDomainAllowed != nil {
				customDomainAllowed = *row.Source.CustomDomainAllowed
			}
			if err := h.DB.UpsertAllocation(r.Context(), org.ID, userID, tunnelLimit, teamLimit, subdomainLimit, bandwidthGB, customDomainAllowed, claims.UserID); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: update allocation: %v", row.Source.Email, err))
				result.Skipped++
				failedRows = append(failedRows, row.Source)
				continue
			}
		}

		if row.ExistingUser != nil {
			result.Added++
		}
	}

	if len(failedRows) > 0 {
		result.FailedCSV = buildImportCSV(failedRows)
	}

	response.Success(w, result)
}

// ─── GET /api/org/{id}/teams ─────────────────────────────────

func (h *OrgHandler) ListTeams(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	if _, ok := h.callerOrgRole(r, id, org.OwnerID, claims); !ok {
		response.Forbidden(w, "you are not a member of this organization")
		return
	}
	teams, err := h.DB.ListTeamsByOrg(r.Context(), id)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if teams == nil {
		teams = []*models.Team{}
	}
	response.Success(w, map[string]any{"teams": teams})
}

// ─── POST /api/org/{id}/teams ────────────────────────────────

func (h *OrgHandler) CreateTeam(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	role, ok := h.callerOrgRole(r, id, org.OwnerID, claims)
	if !ok || !canManageOrg(role) {
		response.Forbidden(w, "owner or admin only")
		return
	}

	var body struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		OwnerUserID string `json:"owner_user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	body.Type = strings.TrimSpace(body.Type)
	body.OwnerUserID = strings.TrimSpace(body.OwnerUserID)
	if body.Name == "" || body.OwnerUserID == "" {
		response.BadRequest(w, "team name and owner_user_id are required")
		return
	}
	if body.Type == "" {
		body.Type = "project"
	}

	if _, err := h.DB.GetOrgMembership(r.Context(), id, body.OwnerUserID); err != nil {
		if org.OwnerID == nil || *org.OwnerID != body.OwnerUserID {
			response.NotFound(w, "organization member not found")
			return
		}
	}

	alloc, err := h.DB.GetAllocation(r.Context(), id, body.OwnerUserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	currentCount, err := h.DB.CountOrgTeamsByOwner(r.Context(), id, body.OwnerUserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if alloc.TeamLimit >= 0 && currentCount >= alloc.TeamLimit {
		response.Error(w, http.StatusConflict, fmt.Sprintf("org team limit reached (%d/%d)", currentCount, alloc.TeamLimit))
		return
	}

	team, err := h.DB.CreateOrgTeam(r.Context(), body.Name, body.Type, org.Plan, body.OwnerUserID, id, claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if err := h.DB.AddTeamMember(r.Context(), team.ID, body.OwnerUserID, "owner"); err != nil {
		_ = h.DB.DeleteTeam(r.Context(), team.ID)
		response.InternalError(w, err)
		return
	}
	if createdOwner, err := h.DB.GetUserByID(r.Context(), body.OwnerUserID); err == nil {
		team.Owner = createdOwner
	}
	if h.Notify != nil && body.OwnerUserID != claims.UserID {
		go h.Notify.Send(r.Context(), body.OwnerUserID, "org_team_created",
			"Organization team created",
			fmt.Sprintf("A new team \"%s\" was created for you in %s.", body.Name, org.Name),
			"/dashboard/team")
	}
	response.Created(w, team)
}

// ─── DELETE /api/org/{id}/teams/{teamId} ─────────────────────

func (h *OrgHandler) DeleteTeam(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	teamID := r.PathValue("teamId")
	org, err := h.DB.GetOrganizationByID(r.Context(), id)
	if err != nil {
		response.NotFound(w, "organization not found")
		return
	}
	role, ok := h.callerOrgRole(r, id, org.OwnerID, claims)
	if !ok || !canManageOrg(role) {
		response.Forbidden(w, "owner or admin only")
		return
	}
	team, err := h.DB.GetTeamByID(r.Context(), teamID)
	if err != nil || team.OrgID == nil || *team.OrgID != id {
		response.NotFound(w, "organization team not found")
		return
	}
	if err := h.DB.DeleteTeam(r.Context(), teamID); err != nil {
		response.InternalError(w, err)
		return
	}
	if h.Notify != nil {
		go h.Notify.Send(r.Context(), team.OwnerID, "org_team_deleted",
			"Organization team removed",
			fmt.Sprintf("The organization team \"%s\" was removed.", team.Name),
			"/dashboard/org")
	}
	response.Success(w, map[string]any{"ok": true})
}

// ─── PATCH /api/admin/org/{id}/seat-limit ─────────────────────

func (h *OrgHandler) SetSeatLimit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		SeatLimit int `json:"seat_limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	if err := h.DB.UpdateOrgSeatLimit(r.Context(), id, body.SeatLimit); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"ok": true})
}

// ─── PATCH /api/admin/org/{id}/plan ───────────────────────────

func (h *OrgHandler) SetPlan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Plan string `json:"plan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	if err := h.DB.UpdateOrgPlan(r.Context(), id, body.Plan); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"ok": true})
}

// generateTempPassword returns a random alphanumeric string of n characters.
func generateTempPassword(n int) string {
	const charset = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, n)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	return string(b)
}
