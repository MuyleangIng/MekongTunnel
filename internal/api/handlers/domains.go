package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
)

const mekongCNAMETarget = "mekongtunnel.dev"

// DomainsHandler manages custom domains.
type DomainsHandler struct {
	DB *db.DB
}

// List handles GET /api/domains
func (h *DomainsHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	list, err := h.DB.ListCustomDomains(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	// Enrich with derived fields
	type enriched struct {
		ID                string  `json:"id"`
		UserID            string  `json:"user_id"`
		Domain            string  `json:"domain"`
		Status            string  `json:"status"`
		VerificationToken string  `json:"verification_token"`
		TargetSubdomain   *string `json:"target_subdomain,omitempty"`
		CreatedAt         string  `json:"created_at"`
		VerifiedAt        *string `json:"verified_at,omitempty"`
		CNAMETarget       string  `json:"cname_target"`
		TXTName           string  `json:"txt_name"`
		TXTValue          string  `json:"txt_value"`
	}
	out := make([]enriched, 0, len(list))
	for _, d := range list {
		var verifiedAt *string
		if d.VerifiedAt != nil {
			s := d.VerifiedAt.Format("2006-01-02T15:04:05Z")
			verifiedAt = &s
		}
		var target *string
		if d.TargetSubdomain != nil {
			target = d.TargetSubdomain
		}
		out = append(out, enriched{
			ID:                d.ID,
			UserID:            d.UserID,
			Domain:            d.Domain,
			Status:            d.Status,
			VerificationToken: d.VerificationToken,
			TargetSubdomain:   target,
			CreatedAt:         d.CreatedAt.Format("2006-01-02T15:04:05Z"),
			VerifiedAt:        verifiedAt,
			CNAMETarget:       mekongCNAMETarget,
			TXTName:           "_mekongtunnel-verify." + d.Domain,
			TXTValue:          "mekong-verify=" + d.VerificationToken,
		})
	}
	response.Success(w, out)
}

// Create handles POST /api/domains
func (h *DomainsHandler) Create(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid request body")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(body.Domain))
	// strip scheme if user pastes a URL
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimRight(domain, "/")

	if domain == "" || !strings.Contains(domain, ".") {
		response.BadRequest(w, "invalid domain name")
		return
	}
	// reject mekongtunnel.dev itself
	if strings.HasSuffix(domain, "mekongtunnel.dev") {
		response.BadRequest(w, "cannot add mekongtunnel.dev subdomains here — use Reserved Subdomains instead")
		return
	}

	d, err := h.DB.CreateCustomDomain(r.Context(), claims.UserID, domain)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			response.Conflict(w, "domain already added")
			return
		}
		response.InternalError(w, err)
		return
	}
	response.Created(w, map[string]any{
		"id":                 d.ID,
		"user_id":            d.UserID,
		"domain":             d.Domain,
		"status":             d.Status,
		"verification_token": d.VerificationToken,
		"created_at":         d.CreatedAt,
		"cname_target":       mekongCNAMETarget,
		"txt_name":           "_mekongtunnel-verify." + d.Domain,
		"txt_value":          "mekong-verify=" + d.VerificationToken,
	})
}

// Delete handles DELETE /api/domains/{id}
func (h *DomainsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}
	if err := h.DB.DeleteCustomDomain(r.Context(), id, claims.UserID); err != nil {
		response.InternalError(w, err)
		return
	}
	response.NoContent(w)
}

// Verify handles POST /api/domains/{id}/verify — checks DNS and marks verified
func (h *DomainsHandler) Verify(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "missing id")
		return
	}

	d, err := h.DB.GetCustomDomain(r.Context(), id, claims.UserID)
	if err != nil {
		response.NotFound(w, "domain not found")
		return
	}

	// Localhost / dev bypass: auto-verify any *.localhost or 127.x.x.x domain
	if isLocalhostDomain(d.Domain) {
		_ = h.DB.SetCustomDomainVerified(r.Context(), d.ID)
		response.Success(w, map[string]any{
			"verified": true, "status": "verified",
			"cname_ok": false, "txt_ok": false,
			"cname_target": mekongCNAMETarget,
			"txt_name": "_mekongtunnel-verify." + d.Domain,
			"txt_value": "mekong-verify=" + d.VerificationToken,
			"message": "Localhost domain auto-verified for local development.",
		})
		return
	}

	// Try CNAME first: domain should point to mekongtunnel.dev
	cnameOK := checkCNAME(d.Domain, mekongCNAMETarget)

	// Try TXT: _mekongtunnel-verify.<domain> should contain the token
	txtName := "_mekongtunnel-verify." + d.Domain
	expectedTXT := "mekong-verify=" + d.VerificationToken
	txtOK := checkTXT(txtName, expectedTXT)

	verified := cnameOK || txtOK

	if verified {
		_ = h.DB.SetCustomDomainVerified(r.Context(), d.ID)
	} else {
		_ = h.DB.SetCustomDomainFailed(r.Context(), d.ID)
	}

	status := "failed"
	if verified {
		status = "verified"
	}

	response.Success(w, map[string]any{
		"verified":   verified,
		"status":     status,
		"cname_ok":   cnameOK,
		"txt_ok":     txtOK,
		"cname_target": mekongCNAMETarget,
		"txt_name":   txtName,
		"txt_value":  expectedTXT,
		"message":    verifyMessage(cnameOK, txtOK),
	})
}

// SetTarget handles PATCH /api/domains/{id}/target — set which tunnel subdomain to route to
func (h *DomainsHandler) SetTarget(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
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
	if err := h.DB.SetCustomDomainTarget(r.Context(), id, claims.UserID, body.TargetSubdomain); err != nil {
		response.InternalError(w, err)
		return
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

func verifyMessage(cnameOK, txtOK bool) string {
	if cnameOK && txtOK {
		return "Domain verified via CNAME and TXT records."
	}
	if cnameOK {
		return "Domain verified via CNAME record."
	}
	if txtOK {
		return "Domain verified via TXT record."
	}
	return fmt.Sprintf(
		"DNS verification failed. Ensure your domain has either a CNAME record pointing to %s, "+
			"or a TXT record at _mekongtunnel-verify.<your-domain> with the verification token.",
		mekongCNAMETarget,
	)
}
