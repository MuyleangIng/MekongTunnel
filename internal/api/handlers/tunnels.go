package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/auth"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

type liveTunnelSnapshot struct {
	Subdomain     string    `json:"subdomain"`
	UserID        string    `json:"user_id,omitempty"`
	ClientIP      string    `json:"client_ip"`
	UptimeSecs    int64     `json:"uptime_secs"`
	RequestCount  uint64    `json:"request_count"`
	TodayRequests uint64    `json:"today_requests"`
	TotalBytes    uint64    `json:"total_bytes"`
	TodayBytes    uint64    `json:"today_bytes"`
	LocalPort     uint32    `json:"local_port"`
	LastActiveAt  time.Time `json:"last_active_at"`
	StartedAt     time.Time `json:"started_at"`
}

type tunnelLogClaims struct {
	TunnelID string `json:"tunnel_id"`
	ViewerID string `json:"viewer_id,omitempty"`
	TeamID   string `json:"team_id,omitempty"`
	jwt.RegisteredClaims
}

// TunnelsHandler handles /api/tunnels/* endpoints.
type TunnelsHandler struct {
	DB              *db.DB
	TunnelServerURL string
	StatsClient     *http.Client
	StreamClient    *http.Client
	JWTSecret       string
	Telegram        TelegramAlerter
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
		h.mergeLiveTunnels(r.Context(), claims.UserID, tunnels)
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
	h.mergeLiveTunnels(r.Context(), claims.UserID, tunnels)
	response.Success(w, tunnels)
}

// ClearHistory handles DELETE /api/tunnels/history.
// It removes stopped tunnel rows only, never active ones.
func (h *TunnelsHandler) ClearHistory(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	teamID := requestedTeamID(r)
	var (
		deleted int64
		err     error
	)

	if teamID != "" {
		scope, scopeErr := resolveResourceScope(r.Context(), h.DB, claims.UserID, teamID)
		if scopeErr != nil {
			if scopeErr == errResourceTeamNotFound {
				response.NotFound(w, "team not found")
				return
			}
			response.Forbidden(w, "you are not a member of this team")
			return
		}
		deleted, err = h.DB.DeleteStoppedTunnelsByUserAndTeam(r.Context(), claims.UserID, scope.TeamID)
	} else {
		deleted, err = h.DB.DeleteStoppedTunnelsByUser(r.Context(), claims.UserID)
	}

	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"deleted": deleted,
	})
}

// ListLiveTunnels handles GET /api/tunnels/live — active tunnels from the tunnel edge.
func (h *TunnelsHandler) ListLiveTunnels(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	live, err := h.fetchLiveTunnels(r.Context(), claims.UserID, "")
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if live == nil {
		live = []liveTunnelSnapshot{}
	}
	response.Success(w, live)
}

// GetOverview handles GET /api/tunnels/overview.
func (h *TunnelsHandler) GetOverview(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	live, err := h.fetchLiveTunnels(r.Context(), claims.UserID, "")
	if err != nil {
		response.InternalError(w, err)
		return
	}

	stopped, err := h.DB.ListTunnelsByUser(r.Context(), claims.UserID, "stopped")
	if err != nil {
		response.InternalError(w, err)
		return
	}

	var requestsToday uint64
	var bandwidthToday uint64
	var bandwidthUsed uint64
	for _, t := range live {
		requestsToday += t.TodayRequests
		bandwidthToday += t.TodayBytes
		bandwidthUsed += t.TotalBytes
	}
	for _, t := range stopped {
		if t.TotalBytes > 0 {
			bandwidthUsed += uint64(t.TotalBytes)
		}
	}

	response.Success(w, map[string]any{
		"active_tunnels":  len(live),
		"requests_today":  requestsToday,
		"bandwidth_today": bandwidthToday,
		"bandwidth_used":  bandwidthUsed,
		"live_tunnels":    live,
	})
}

// GetStats handles GET /api/tunnels/stats — proxies to Go tunnel server.
func (h *TunnelsHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	statsURL := h.TunnelServerURL + "/api/stats"
	client := h.statsClient()

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

	copyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// CreateLogToken handles POST /api/tunnels/{id}/log-token.
func (h *TunnelsHandler) CreateLogToken(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	tunnelRecord, err := h.loadTunnel(r.Context(), r.PathValue("id"))
	if err != nil {
		response.NotFound(w, "tunnel not found")
		return
	}

	teamID := strings.TrimSpace(r.URL.Query().Get("team_id"))
	if err := h.authorizeViewer(r.Context(), claims, tunnelRecord, teamID); err != nil {
		response.Forbidden(w, err.Error())
		return
	}

	expiresAt := time.Now().Add(15 * time.Minute)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tunnelLogClaims{
		TunnelID: tunnelRecord.ID,
		ViewerID: claims.UserID,
		TeamID:   teamID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   tunnelRecord.ID,
			Issuer:    "mekongtunnel-logs",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	})

	signed, err := token.SignedString([]byte(h.JWTSecret))
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"token":      signed,
		"expires_at": expiresAt,
		"tunnel_id":  tunnelRecord.ID,
	})
}

// GetLogs handles GET /api/tunnels/{id}/logs.
// Auth can be provided either as a signed ?token= query param or as a normal Bearer JWT.
func (h *TunnelsHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	tunnelRecord, err := h.loadTunnel(r.Context(), r.PathValue("id"))
	if err != nil {
		response.NotFound(w, "tunnel not found")
		return
	}

	tokenStr := strings.TrimSpace(r.URL.Query().Get("token"))
	if tokenStr != "" {
		if _, err := h.validateLogToken(tokenStr, tunnelRecord.ID); err != nil {
			response.Unauthorized(w, "invalid log token")
			return
		}
	} else {
		claims := h.requestClaims(r)
		if claims == nil {
			response.Unauthorized(w, "authentication required")
			return
		}
		teamID := strings.TrimSpace(r.URL.Query().Get("team_id"))
		if err := h.authorizeViewer(r.Context(), claims, tunnelRecord, teamID); err != nil {
			response.Forbidden(w, err.Error())
			return
		}
	}

	stream := strings.EqualFold(r.URL.Query().Get("stream"), "sse") || r.URL.Query().Get("follow") == "true"
	resp, err := h.proxyTunnelLogs(r.Context(), tunnelRecord.Subdomain, stream)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	defer resp.Body.Close()

	copyResponseHeaders(w, resp)
	w.WriteHeader(resp.StatusCode)

	if stream {
		if err := relayStreamingBody(w, resp.Body); err != nil && !strings.Contains(err.Error(), "context canceled") {
			return
		}
		return
	}

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

	var before *models.Tunnel
	if existing, err := h.DB.GetTunnelByID(r.Context(), t.ID); err == nil {
		before = existing
	}

	if err := h.DB.UpsertTunnel(r.Context(), &t); err != nil {
		response.InternalError(w, err)
		return
	}

	notifyTunnelTransition(r.Context(), h.Telegram, before, t.Status)

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

	var before *models.Tunnel
	if body.Status != "" {
		if existing, err := h.DB.GetTunnelByID(r.Context(), id); err == nil {
			before = existing
		}
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

		notifyTunnelTransition(r.Context(), h.Telegram, before, body.Status)
	}

	if body.TotalRequests > 0 || body.TotalBytes > 0 {
		if err := h.DB.UpdateTunnelStats(r.Context(), id, body.TotalRequests, body.TotalBytes); err != nil {
			response.InternalError(w, err)
			return
		}
	}

	response.Success(w, map[string]any{"message": "tunnel updated"})
}

func (h *TunnelsHandler) mergeLiveTunnels(ctx context.Context, userID string, tunnels []*models.Tunnel) {
	if len(tunnels) == 0 {
		return
	}

	live, err := h.fetchLiveTunnels(ctx, userID, "")
	if err != nil || len(live) == 0 {
		return
	}

	mergeLiveTunnelRows(tunnels, live)
}

func mergeLiveTunnelRows(tunnels []*models.Tunnel, live []liveTunnelSnapshot) {
	if len(tunnels) == 0 || len(live) == 0 {
		return
	}

	liveBySubdomain := make(map[string]liveTunnelSnapshot, len(live))
	for _, item := range live {
		liveBySubdomain[item.Subdomain] = item
	}

	for _, tunnelRecord := range tunnels {
		if tunnelRecord == nil || tunnelRecord.Status != string(models.TunnelActive) {
			continue
		}
		item, ok := liveBySubdomain[tunnelRecord.Subdomain]
		if !ok {
			continue
		}
		tunnelRecord.Status = string(models.TunnelActive)
		if item.LocalPort > 0 {
			tunnelRecord.LocalPort = int(item.LocalPort)
		}
		if !item.StartedAt.IsZero() {
			tunnelRecord.StartedAt = item.StartedAt
		}
		tunnelRecord.TotalRequests = int64(item.TodayRequests)
		tunnelRecord.TotalBytes = int64(item.TodayBytes)
	}
}

func (h *TunnelsHandler) fetchLiveTunnels(ctx context.Context, userID, subdomain string) ([]liveTunnelSnapshot, error) {
	values := url.Values{}
	if userID != "" {
		values.Set("user_id", userID)
	}
	if subdomain != "" {
		values.Set("subdomain", subdomain)
	}

	liveURL := h.TunnelServerURL + "/api/tunnels/live"
	if encoded := values.Encode(); encoded != "" {
		liveURL += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, liveURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := h.statsClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("tunnel server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("tunnel server live lookup failed: %s", strings.TrimSpace(string(body)))
	}

	var live []liveTunnelSnapshot
	if err := json.NewDecoder(resp.Body).Decode(&live); err != nil {
		return nil, err
	}
	return live, nil
}

func (h *TunnelsHandler) proxyTunnelLogs(ctx context.Context, subdomain string, stream bool) (*http.Response, error) {
	logsURL := h.TunnelServerURL + "/api/tunnels/logs/" + url.PathEscape(subdomain)
	if stream {
		logsURL += "?stream=sse"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, logsURL, nil)
	if err != nil {
		return nil, err
	}

	client := h.statsClient()
	if stream {
		client = h.streamClient()
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tunnel log proxy failed: %w", err)
	}
	return resp, nil
}

func (h *TunnelsHandler) loadTunnel(ctx context.Context, id string) (*models.Tunnel, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("tunnel id required")
	}
	return h.DB.GetTunnelByID(ctx, id)
}

func (h *TunnelsHandler) authorizeViewer(ctx context.Context, claims *auth.JWTClaims, tunnelRecord *models.Tunnel, teamID string) error {
	if claims == nil {
		return fmt.Errorf("authentication required")
	}
	if claims.IsAdmin {
		return nil
	}

	ownerID := ""
	if tunnelRecord.UserID != nil {
		ownerID = *tunnelRecord.UserID
	}
	if ownerID == "" {
		return fmt.Errorf("tunnel owner is unavailable")
	}
	if ownerID == claims.UserID {
		return nil
	}
	if teamID == "" {
		return fmt.Errorf("team access required")
	}

	team, err := h.DB.GetTeamByID(ctx, teamID)
	if err != nil {
		return fmt.Errorf("team not found")
	}
	if !h.userBelongsToTeam(ctx, team, ownerID) {
		return fmt.Errorf("target user is not in this team")
	}
	if team.OwnerID == claims.UserID {
		return nil
	}

	membership, err := h.DB.GetTeamMembership(ctx, teamID, claims.UserID)
	if err != nil {
		return fmt.Errorf("you are not a member of this team")
	}
	if !canInvite(membership.Role) {
		return fmt.Errorf("only owner, admin, or teacher can view member tunnels")
	}
	return nil
}

func (h *TunnelsHandler) userBelongsToTeam(ctx context.Context, team *models.Team, userID string) bool {
	if team == nil || userID == "" {
		return false
	}
	if team.OwnerID == userID {
		return true
	}
	_, err := h.DB.GetTeamMembership(ctx, team.ID, userID)
	return err == nil
}

func (h *TunnelsHandler) requestClaims(r *http.Request) *auth.JWTClaims {
	if claims := middleware.GetClaims(r); claims != nil {
		return claims
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return nil
	}
	return middleware.ParseTokenString(strings.TrimSpace(authz[7:]), h.JWTSecret)
}

func (h *TunnelsHandler) validateLogToken(tokenStr, tunnelID string) (*tunnelLogClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &tunnelLogClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(h.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*tunnelLogClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if claims.TunnelID != tunnelID {
		return nil, fmt.Errorf("wrong tunnel")
	}
	return claims, nil
}

func (h *TunnelsHandler) statsClient() *http.Client {
	if h.StatsClient != nil {
		return h.StatsClient
	}
	return http.DefaultClient
}

func (h *TunnelsHandler) streamClient() *http.Client {
	if h.StreamClient != nil {
		return h.StreamClient
	}
	return &http.Client{}
}

func copyResponseHeaders(w http.ResponseWriter, resp *http.Response) {
	if contentType := resp.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	for _, header := range []string{"Cache-Control", "Connection", "X-Accel-Buffering"} {
		if value := resp.Header.Get(header); value != "" {
			w.Header().Set(header, value)
		}
	}
}

func relayStreamingBody(w http.ResponseWriter, body io.Reader) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, err := io.Copy(w, body)
		return err
	}

	buf := make([]byte, 4096)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			flusher.Flush()
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}
