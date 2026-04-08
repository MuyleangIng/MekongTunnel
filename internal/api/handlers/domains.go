package handlers

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/customdomain"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

const mekongCNAMETarget = "proxy.angkorsearch.dev"

// DomainsHandler manages custom domains.
type DomainsHandler struct {
	DB       *db.DB
	Telegram TelegramAlerter
}

type enrichedCustomDomain struct {
	ID                string                   `json:"id"`
	UserID            string                   `json:"user_id,omitempty"`
	TeamID            *string                  `json:"team_id,omitempty"`
	Domain            string                   `json:"domain"`
	Status            string                   `json:"status"`
	VerificationToken string                   `json:"verification_token"`
	TargetSubdomain   *string                  `json:"target_subdomain,omitempty"`
	CreatedAt         string                   `json:"created_at"`
	VerifiedAt        *string                  `json:"verified_at,omitempty"`
	CNAMETarget       string                   `json:"cname_target"`
	TXTName           string                   `json:"txt_name"`
	TXTValue          string                   `json:"txt_value"`
	DNSMode           string                   `json:"dns_mode"`
	PrimaryRecords    []customdomain.DNSRecord `json:"primary_records,omitempty"`
	FallbackRecords   []customdomain.DNSRecord `json:"fallback_records,omitempty"`
	DNSNote           string                   `json:"dns_note,omitempty"`
}

type customDomainVerificationResult struct {
	Verified        bool                     `json:"verified"`
	Status          string                   `json:"status"`
	CNAMEOK         bool                     `json:"cname_ok"`
	TXTOK           bool                     `json:"txt_ok"`
	AddressOK       bool                     `json:"address_ok"`
	CNAMETarget     string                   `json:"cname_target"`
	TXTName         string                   `json:"txt_name"`
	TXTValue        string                   `json:"txt_value"`
	HTTPSOK         bool                     `json:"https_ok"`
	HTTPSError      string                   `json:"https_error,omitempty"`
	Ready           bool                     `json:"ready"`
	ReadinessStatus string                   `json:"readiness_status"`
	Message         string                   `json:"message"`
	DNSMode         string                   `json:"dns_mode"`
	PrimaryRecords  []customdomain.DNSRecord `json:"primary_records,omitempty"`
	FallbackRecords []customdomain.DNSRecord `json:"fallback_records,omitempty"`
	DNSNote         string                   `json:"dns_note,omitempty"`
}

type customDomainDeleteResult struct {
	Domain          string  `json:"domain"`
	TargetSubdomain *string `json:"target_subdomain,omitempty"`
	RouteRemoved    bool    `json:"route_removed"`
	DNSChanged      bool    `json:"dns_changed"`
	HTTPSNote       string  `json:"https_note"`
	CleanupAction   string  `json:"cleanup_action"`
}

func (h *DomainsHandler) userFromAPIToken(r *http.Request) (*models.User, error) {
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

func enrichCustomDomain(d *models.CustomDomain) enrichedCustomDomain {
	dns := customdomain.BuildDNSInstructions(d.Domain, mekongCNAMETarget, d.VerificationToken, net.LookupIP)
	var verifiedAt *string
	if d.VerifiedAt != nil {
		s := d.VerifiedAt.Format("2006-01-02T15:04:05Z")
		verifiedAt = &s
	}
	var target *string
	if d.TargetSubdomain != nil {
		target = d.TargetSubdomain
	}
	return enrichedCustomDomain{
		ID:                d.ID,
		UserID:            d.UserID,
		TeamID:            d.TeamID,
		Domain:            d.Domain,
		Status:            d.Status,
		VerificationToken: d.VerificationToken,
		TargetSubdomain:   target,
		CreatedAt:         d.CreatedAt.Format("2006-01-02T15:04:05Z"),
		VerifiedAt:        verifiedAt,
		CNAMETarget:       mekongCNAMETarget,
		TXTName:           "_mekongtunnel-verify." + d.Domain,
		TXTValue:          "mekong-verify=" + d.VerificationToken,
		DNSMode:           dns.Mode,
		PrimaryRecords:    dns.PrimaryRecords,
		FallbackRecords:   dns.FallbackRecords,
		DNSNote:           dns.Note,
	}
}

func normalizeCustomDomainInput(raw string) string {
	domain := strings.ToLower(strings.TrimSpace(raw))
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimRight(domain, "/")
	return domain
}

func validateCustomDomain(domain string) error {
	if err := customdomain.ValidateDomain(domain); err != nil {
		return err
	}
	if strings.HasSuffix(domain, "proxy.angkorsearch.dev") {
		return fmt.Errorf("cannot add proxy.angkorsearch.dev subdomains here — use Reserved Subdomains instead")
	}
	return nil
}

func (h *DomainsHandler) decodeCreateBody(r *http.Request) (string, bool) {
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return "", false
	}
	return normalizeCustomDomainInput(body.Domain), true
}

func (h *DomainsHandler) respondWithCustomDomains(w http.ResponseWriter, list []*models.CustomDomain) {
	out := make([]enrichedCustomDomain, 0, len(list))
	for _, d := range list {
		out = append(out, enrichCustomDomain(d))
	}
	response.Success(w, out)
}

func deleteResultForDomain(d *models.CustomDomain) customDomainDeleteResult {
	return customDomainDeleteResult{
		Domain:          d.Domain,
		TargetSubdomain: d.TargetSubdomain,
		RouteRemoved:    true,
		DNSChanged:      false,
		HTTPSNote:       "The MekongTunnel app route is removed. If DNS still points here, a shared or existing certificate may still validate, but the hostname will no longer route to the deleted app.",
		CleanupAction:   "Remove or change the DNS record at your provider if you want the hostname fully disconnected.",
	}
}

// List handles GET /api/domains
func (h *DomainsHandler) List(w http.ResponseWriter, r *http.Request) {
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
	list, err := h.DB.ListCustomDomainsByScope(r.Context(), claims.UserID, scope.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	h.respondWithCustomDomains(w, list)
}

// ListCLI handles GET /api/cli/domains using an API token.
func (h *DomainsHandler) ListCLI(w http.ResponseWriter, r *http.Request) {
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
	list, err := h.DB.ListCustomDomainsByScope(r.Context(), user.ID, scope.TeamID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	h.respondWithCustomDomains(w, list)
}

// Create handles POST /api/domains
func (h *DomainsHandler) Create(w http.ResponseWriter, r *http.Request) {
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
		response.Forbidden(w, "only owner, admin, or teacher can manage team custom domains")
		return
	}
	domain, ok := h.decodeCreateBody(r)
	if !ok {
		response.BadRequest(w, "invalid request body")
		return
	}
	if err := validateCustomDomain(domain); err != nil {
		response.BadRequest(w, err.Error())
		return
	}

	ownerUserID := claims.UserID
	if scope.IsTeam() {
		ownerUserID = ""
	}
	d, err := h.DB.CreateCustomDomainByScope(r.Context(), ownerUserID, scope.TeamID, domain)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			response.Conflict(w, "domain already added")
			return
		}
		response.InternalError(w, err)
		return
	}
	notifyDomainCreated(r.Context(), h.Telegram, domainAlertRecipients(r.Context(), h.DB, d), d)
	response.Created(w, enrichCustomDomain(d))
}

// CreateCLI handles POST /api/cli/domains using an API token.
func (h *DomainsHandler) CreateCLI(w http.ResponseWriter, r *http.Request) {
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
		response.Forbidden(w, "only owner, admin, or teacher can manage team custom domains")
		return
	}
	domain, ok := h.decodeCreateBody(r)
	if !ok {
		response.BadRequest(w, "invalid request body")
		return
	}
	if err := validateCustomDomain(domain); err != nil {
		response.BadRequest(w, err.Error())
		return
	}
	ownerUserID := user.ID
	if scope.IsTeam() {
		ownerUserID = ""
	}
	d, err := h.DB.CreateCustomDomainByScope(r.Context(), ownerUserID, scope.TeamID, domain)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			response.Conflict(w, "domain already added")
			return
		}
		response.InternalError(w, err)
		return
	}
	notifyDomainCreated(r.Context(), h.Telegram, domainAlertRecipients(r.Context(), h.DB, d), d)
	response.Created(w, enrichCustomDomain(d))
}

// Delete handles DELETE /api/domains/{id}
func (h *DomainsHandler) Delete(w http.ResponseWriter, r *http.Request) {
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
		response.Forbidden(w, "only owner, admin, or teacher can manage team custom domains")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}
	d, err := h.DB.GetCustomDomainByScope(r.Context(), id, claims.UserID, scope.TeamID)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}
	if err := h.DB.DeleteCustomDomainByScope(r.Context(), id, claims.UserID, scope.TeamID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, deleteResultForDomain(d))
}

// DeleteCLI handles DELETE /api/cli/domains/{id} using an API token.
func (h *DomainsHandler) DeleteCLI(w http.ResponseWriter, r *http.Request) {
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
		response.Forbidden(w, "only owner, admin, or teacher can manage team custom domains")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}
	d, err := h.DB.GetCustomDomainByScope(r.Context(), id, user.ID, scope.TeamID)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}
	if err := h.DB.DeleteCustomDomainByScope(r.Context(), id, user.ID, scope.TeamID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, deleteResultForDomain(d))
}

func (h *DomainsHandler) respondVerification(w http.ResponseWriter, r *http.Request, d *models.CustomDomain) {
	recipients := domainAlertRecipients(r.Context(), h.DB, d)
	dns := customdomain.BuildDNSInstructions(d.Domain, mekongCNAMETarget, d.VerificationToken, net.LookupIP)

	// Localhost / dev bypass: auto-verify any *.localhost or 127.x.x.x domain
	if isLocalhostDomain(d.Domain) {
		_ = h.DB.SetCustomDomainVerified(r.Context(), d.ID)
		if updated, err := h.DB.GetCustomDomainByID(r.Context(), d.ID); err == nil && updated != nil {
			d = updated
		}
		notifyDomainVerificationResult(r.Context(), h.Telegram, recipients, d, true, true, "")
		response.Success(w, customDomainVerificationResult{
			Verified:        true,
			Status:          "verified",
			CNAMEOK:         false,
			TXTOK:           false,
			AddressOK:       false,
			CNAMETarget:     mekongCNAMETarget,
			TXTName:         "_mekongtunnel-verify." + d.Domain,
			TXTValue:        "mekong-verify=" + d.VerificationToken,
			HTTPSOK:         true,
			Ready:           true,
			ReadinessStatus: "ready",
			Message:         "Localhost domain auto-verified for local development.",
			DNSMode:         dns.Mode,
			PrimaryRecords:  dns.PrimaryRecords,
			FallbackRecords: dns.FallbackRecords,
			DNSNote:         dns.Note,
		})
		return
	}

	cnameOK := checkCNAME(d.Domain, mekongCNAMETarget)
	txtName := "_mekongtunnel-verify." + d.Domain
	expectedTXT := "mekong-verify=" + d.VerificationToken
	txtOK := checkTXT(txtName, expectedTXT)
	addressOK := checkAddressMatch(d.Domain, mekongCNAMETarget)
	verified := cnameOK || txtOK || addressOK
	httpsOK := false
	httpsErr := ""
	readinessStatus := "pending_dns"

	if verified {
		_ = h.DB.SetCustomDomainVerified(r.Context(), d.ID)
		httpsOK, httpsErr = checkHTTPSReady(d.Domain)
		if httpsOK {
			readinessStatus = "ready"
		} else {
			readinessStatus = "pending_https"
		}
	} else {
		_ = h.DB.SetCustomDomainFailed(r.Context(), d.ID)
	}

	if updated, err := h.DB.GetCustomDomainByID(r.Context(), d.ID); err == nil && updated != nil {
		d = updated
	}

	status := "failed"
	if verified {
		status = "verified"
	}

	notifyDomainVerificationResult(r.Context(), h.Telegram, recipients, d, verified, httpsOK, verifyMessage(cnameOK, txtOK, addressOK, httpsOK, httpsErr))

	response.Success(w, customDomainVerificationResult{
		Verified:        verified,
		Status:          status,
		CNAMEOK:         cnameOK,
		TXTOK:           txtOK,
		AddressOK:       addressOK,
		CNAMETarget:     mekongCNAMETarget,
		TXTName:         txtName,
		TXTValue:        expectedTXT,
		HTTPSOK:         httpsOK,
		HTTPSError:      httpsErr,
		Ready:           verified && httpsOK,
		ReadinessStatus: readinessStatus,
		Message:         verifyMessage(cnameOK, txtOK, addressOK, httpsOK, httpsErr),
		DNSMode:         dns.Mode,
		PrimaryRecords:  dns.PrimaryRecords,
		FallbackRecords: dns.FallbackRecords,
		DNSNote:         dns.Note,
	})
}

// Verify handles POST /api/domains/{id}/verify — checks DNS and marks verified
func (h *DomainsHandler) Verify(w http.ResponseWriter, r *http.Request) {
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
		response.Forbidden(w, "only owner, admin, or teacher can manage team custom domains")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}

	d, err := h.DB.GetCustomDomainByScope(r.Context(), id, claims.UserID, scope.TeamID)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}
	h.respondVerification(w, r, d)
}

// VerifyCLI handles POST /api/cli/domains/{id}/verify using an API token.
func (h *DomainsHandler) VerifyCLI(w http.ResponseWriter, r *http.Request) {
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
		response.Forbidden(w, "only owner, admin, or teacher can manage team custom domains")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}
	d, err := h.DB.GetCustomDomainByScope(r.Context(), id, user.ID, scope.TeamID)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}
	h.respondVerification(w, r, d)
}

// SetTarget handles PATCH /api/domains/{id}/target — set which tunnel subdomain to route to
func (h *DomainsHandler) SetTarget(w http.ResponseWriter, r *http.Request) {
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
		response.Forbidden(w, "only owner, admin, or teacher can manage team custom domains")
		return
	}
	id := r.PathValue("id")
	var body struct {
		TargetSubdomain string `json:"target_subdomain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid body")
		return
	}
	targetSubdomain := strings.ToLower(strings.TrimSpace(body.TargetSubdomain))
	if targetSubdomain == "" {
		response.BadRequest(w, "target_subdomain is required")
		return
	}

	reserved, err := h.DB.GetReservedSubdomainForScope(r.Context(), claims.UserID, scope.TeamID, targetSubdomain)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if reserved == "" {
		if scope.IsTeam() {
			response.BadRequest(w, "target_subdomain must be one of this team's reserved subdomains")
		} else {
			response.BadRequest(w, "target_subdomain must be one of your reserved subdomains")
		}
		return
	}

	d, err := h.DB.GetCustomDomainByScope(r.Context(), id, claims.UserID, scope.TeamID)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}
	if err := h.DB.SetCustomDomainTargetByScope(r.Context(), id, claims.UserID, scope.TeamID, targetSubdomain); err != nil {
		response.InternalError(w, err)
		return
	}
	prevTarget := ""
	if d.TargetSubdomain != nil {
		prevTarget = strings.TrimSpace(*d.TargetSubdomain)
	}
	if prevTarget != targetSubdomain {
		targetCopy := targetSubdomain
		d.TargetSubdomain = &targetCopy
		notifyDomainTargetUpdated(r.Context(), h.Telegram, domainAlertRecipients(r.Context(), h.DB, d), d)
	}
	response.Success(w, map[string]any{"ok": true})
}

// SetTargetCLI handles PATCH /api/cli/domains/{id}/target using an API token.
func (h *DomainsHandler) SetTargetCLI(w http.ResponseWriter, r *http.Request) {
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
		response.Forbidden(w, "only owner, admin, or teacher can manage team custom domains")
		return
	}
	id := r.PathValue("id")
	var body struct {
		TargetSubdomain string `json:"target_subdomain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid body")
		return
	}
	targetSubdomain := strings.ToLower(strings.TrimSpace(body.TargetSubdomain))
	if targetSubdomain == "" {
		response.BadRequest(w, "target_subdomain is required")
		return
	}
	reserved, err := h.DB.GetReservedSubdomainForScope(r.Context(), user.ID, scope.TeamID, targetSubdomain)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if reserved == "" {
		if scope.IsTeam() {
			response.BadRequest(w, "target_subdomain must be one of this team's reserved subdomains")
		} else {
			response.BadRequest(w, "target_subdomain must be one of your reserved subdomains")
		}
		return
	}
	d, err := h.DB.GetCustomDomainByScope(r.Context(), id, user.ID, scope.TeamID)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}
	if err := h.DB.SetCustomDomainTargetByScope(r.Context(), id, user.ID, scope.TeamID, targetSubdomain); err != nil {
		response.InternalError(w, err)
		return
	}
	prevTarget := ""
	if d.TargetSubdomain != nil {
		prevTarget = strings.TrimSpace(*d.TargetSubdomain)
	}
	if prevTarget != targetSubdomain {
		targetCopy := targetSubdomain
		d.TargetSubdomain = &targetCopy
		notifyDomainTargetUpdated(r.Context(), h.Telegram, domainAlertRecipients(r.Context(), h.DB, d), d)
	}
	response.Success(w, map[string]any{"ok": true})
}

// ── DNS helpers ───────────────────────────────────────────────

func isLocalhostDomain(domain string) bool {
	return strings.HasSuffix(domain, ".localhost") ||
		domain == "localhost" ||
		strings.HasPrefix(domain, "127.") ||
		strings.HasPrefix(domain, "192.168.")
}

func checkCNAME(domain, target string) bool {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return false
	}
	// LookupCNAME returns FQDN with trailing dot
	cname = strings.TrimSuffix(strings.ToLower(cname), ".")
	target = strings.TrimSuffix(strings.ToLower(target), ".")
	return cname == target
}

func checkTXT(txtName, expectedValue string) bool {
	records, err := net.LookupTXT(txtName)
	if err != nil {
		return false
	}
	for _, rec := range records {
		if strings.Contains(rec, expectedValue) {
			return true
		}
	}
	return false
}

func checkAddressMatch(domain, target string) bool {
	domainIPs, err := net.LookupIP(domain)
	if err != nil || len(domainIPs) == 0 {
		return false
	}
	targetIPs, err := net.LookupIP(target)
	if err != nil || len(targetIPs) == 0 {
		return false
	}

	targetSet := make(map[string]struct{}, len(targetIPs))
	for _, ip := range targetIPs {
		targetSet[ip.String()] = struct{}{}
	}
	for _, ip := range domainIPs {
		if _, ok := targetSet[ip.String()]; ok {
			return true
		}
	}
	return false
}

func checkHTTPSReady(domain string) (bool, string) {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(domain, "443"), &tls.Config{
		ServerName: domain,
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return false, err.Error()
	}
	_ = conn.Close()
	return true, ""
}

func verifyMessage(cnameOK, txtOK, addressOK, httpsOK bool, httpsErr string) string {
	dnsVerified := cnameOK || txtOK || addressOK
	source := verificationSource(cnameOK, txtOK, addressOK)
	if dnsVerified && httpsOK {
		return "Domain verified via " + source + " and HTTPS is ready."
	}
	if dnsVerified {
		if httpsErr == "" {
			return "Domain verified via " + source + ". HTTPS is not ready yet."
		}
		return "Domain verified via " + source + ", but HTTPS is not ready yet: " + httpsErr
	}
	return fmt.Sprintf(
		"DNS verification failed. Ensure your domain has either a CNAME record pointing to %s, "+
			"an A/AAAA record pointing to the same proxy IPs as %s, "+
			"or a TXT record at _mekongtunnel-verify.<your-domain> with the verification token.",
		mekongCNAMETarget,
		mekongCNAMETarget,
	)
}

func verificationSource(cnameOK, txtOK, addressOK bool) string {
	parts := make([]string, 0, 3)
	if cnameOK {
		parts = append(parts, "CNAME record")
	}
	if addressOK && !cnameOK {
		parts = append(parts, "A/AAAA record")
	}
	if txtOK {
		parts = append(parts, "TXT record")
	}
	switch len(parts) {
	case 0:
		return "DNS records"
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	default:
		return parts[0] + ", " + parts[1] + ", and " + parts[2]
	}
}
