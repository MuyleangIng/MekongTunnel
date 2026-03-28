package db

import (
	"testing"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

func TestDedupeActiveTunnelsKeepsNewestActivePerSubdomain(t *testing.T) {
	now := time.Now()
	tunnels := []*models.Tunnel{
		{ID: "new-active", Subdomain: "myapp", Status: "active", StartedAt: now},
		{ID: "old-active", Subdomain: "myapp", Status: "active", StartedAt: now.Add(-time.Minute)},
		{ID: "stopped-history", Subdomain: "myapp", Status: "stopped", StartedAt: now.Add(-2 * time.Minute)},
		{ID: "other-active", Subdomain: "other", Status: "active", StartedAt: now.Add(-3 * time.Minute)},
	}

	got := dedupeActiveTunnels(tunnels)
	if len(got) != 3 {
		t.Fatalf("dedupeActiveTunnels() len = %d, want 3", len(got))
	}
	if got[0].ID != "new-active" {
		t.Fatalf("first tunnel id = %q, want newest active row kept", got[0].ID)
	}
	if got[1].ID != "stopped-history" {
		t.Fatalf("second tunnel id = %q, want stopped history preserved", got[1].ID)
	}
	if got[2].ID != "other-active" {
		t.Fatalf("third tunnel id = %q, want other active tunnel preserved", got[2].ID)
	}
}
