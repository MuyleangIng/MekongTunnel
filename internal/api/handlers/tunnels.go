package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// TunnelsHandler handles /api/tunnels/* endpoints.
type TunnelsHandler struct {
	DB              *db.DB
	TunnelServerURL string
	StatsClient     *http.Client
}

// ListTunnels handles GET /api/tunnels.
func (h *TunnelsHandler) ListTunnels(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	status := r.URL.Query().Get("status")
	query := r.URL.Query()
	if query.Has("limit") || query.Has("offset") {
		limit := queryInt(r, "limit", 50)
		if limit < 1 {
			limit = 50
		}
		if limit > 200 {
			limit = 200
		}
		offset := queryInt(r, "offset", 0)
		tunnels, total, err := h.DB.ListTunnelsByUserPage(r.Context(), claims.UserID, status, limit, offset)
		if err != nil {
			response.InternalError(w, err)
			return
		}
		if tunnels == nil {
			tunnels = []*models.Tunnel{}
		}
		w.Header().Set("X-Total-Count", strconv.Itoa(total))
		w.Header().Set("X-Limit", strconv.Itoa(limit))
		w.Header().Set("X-Offset", strconv.Itoa(offset))
		response.Success(w, tunnels)
		return
	}

	tunnels, err := h.DB.ListTunnelsByUser(r.Context(), claims.UserID, status)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	if tunnels == nil {
		tunnels = []*models.Tunnel{}
	}
	response.Success(w, tunnels)
}

// GetStats handles GET /api/tunnels/stats — proxies to Go tunnel server.
func (h *TunnelsHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	statsURL := h.TunnelServerURL + "/api/stats"
	client := h.StatsClient
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, statsURL, nil)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		response.InternalError(w, fmt.Errorf("tunnel server unreachable: %w", err))
		return
	}
	defer resp.Body.Close()

	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// ReportTunnel handles POST /api/tunnels — upsert from the Go tunnel server.
func (h *TunnelsHandler) ReportTunnel(w http.ResponseWriter, r *http.Request) {
	var t models.Tunnel
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if t.ID == "" || t.Subdomain == "" {
		response.BadRequest(w, "id and subdomain are required")
		return
	}

	if t.StartedAt.IsZero() {
		t.StartedAt = time.Now()
	}
	if t.Status == "" {
		t.Status = "active"
	}

	if err := h.DB.UpsertTunnel(r.Context(), &t); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"message": "tunnel synced"})
}

// UpdateTunnelStatus handles PATCH /api/tunnels/{id}.
func (h *TunnelsHandler) UpdateTunnelStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "tunnel id required")
		return
	}

	var body struct {
		Status        string `json:"status"`
		TotalRequests int64  `json:"total_requests"`
		TotalBytes    int64  `json:"total_bytes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	if body.Status != "" {
		var endedAt *time.Time
		if body.Status == "stopped" {
			now := time.Now()
			endedAt = &now
		}
		if err := h.DB.UpdateTunnelStatus(r.Context(), id, body.Status, endedAt); err != nil {
			response.InternalError(w, err)
			return
		}
	}

	if body.TotalRequests > 0 || body.TotalBytes > 0 {
		if err := h.DB.UpdateTunnelStats(r.Context(), id, body.TotalRequests, body.TotalBytes); err != nil {
			response.InternalError(w, err)
			return
		}
	}

	response.Success(w, map[string]any{"message": "tunnel updated"})
}
