package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/system"
)

// MonitorHandler serves system resource metrics to admin clients.
type MonitorHandler struct{}

// GetSnapshot handles GET /api/admin/system — single snapshot.
func (h *MonitorHandler) GetSnapshot(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil || !claims.IsAdmin {
		response.Forbidden(w, "admin only")
		return
	}

	snap, err := system.Collect(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, snap)
}

// Stream handles GET /api/admin/system/stream — SSE live feed.
// Auth via ?token= query param (SSE cannot set headers).
func (h *MonitorHandler) Stream(w http.ResponseWriter, r *http.Request, jwtSecret string) {
	claims := middleware.ParseTokenString(r.URL.Query().Get("token"), jwtSecret)
	if claims == nil || !claims.IsAdmin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	// Send first snapshot immediately
	sendSnapshot := func() bool {
		snap, err := system.Collect(ctx)
		if err != nil { return true }
		data, err := json.Marshal(snap)
		if err != nil { return true }
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
		return false
	}
	if sendSnapshot() { return }

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if sendSnapshot() { return }
		}
	}
}
