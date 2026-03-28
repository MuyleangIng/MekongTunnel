package handlers

import (
	"testing"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

func TestMergeLiveTunnelsOnlyUpdatesActiveRows(t *testing.T) {
	userID := "user-123"
	active := &models.Tunnel{
		ID:        "active-row",
		Subdomain: "myapp",
		Status:    "active",
	}
	stopped := &models.Tunnel{
		ID:        "stopped-row",
		Subdomain: "myapp",
		Status:    "stopped",
	}

	tunnels := []*models.Tunnel{active, stopped}
	mergeLiveTunnelRows(tunnels, []liveTunnelSnapshot{{
		Subdomain:     "myapp",
		UserID:        userID,
		LocalPort:     3000,
		TodayRequests: 125,
		TodayBytes:    3145728,
		StartedAt:     time.Unix(1711548000, 0).UTC(),
	}})

	if active.Status != "active" || active.LocalPort != 3000 || active.TotalRequests != 125 || active.TotalBytes != 3145728 {
		t.Fatalf("active tunnel row did not receive live merge: %+v", active)
	}
	if stopped.Status != "stopped" {
		t.Fatalf("stopped tunnel status = %q, want stopped", stopped.Status)
	}
	if stopped.LocalPort != 0 || stopped.TotalRequests != 0 || stopped.TotalBytes != 0 {
		t.Fatalf("stopped tunnel row was incorrectly updated: %+v", stopped)
	}
}
