package proxy

import (
	"context"
	"strings"
	"testing"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/tunnel"
)

type limitValidator struct {
	stubTokenValidator
	limit int
}

func (v limitValidator) MaxActiveTunnelsForUser(context.Context, string) (int, string, error) {
	return v.limit, "Free", nil
}

func addTestTunnel(s *Server, sub, ip, userID string) *tunnel.Tunnel {
	tun := tunnel.New(sub, fakeListener{}, "127.0.0.1", 80, ip, config.DefaultTunnelLifetime)
	if userID != "" {
		tun.SetUserID(userID)
	}
	s.mu.Lock()
	s.tunnels[sub] = tun
	s.mu.Unlock()
	return tun
}

func TestEnforceTunnelLimitsPerPlan(t *testing.T) {
	s := newTestServer(t)
	s.SetTokenValidator(limitValidator{limit: 2})
	addTestTunnel(s, "a-a-00000001", "1.1.1.1", "user-1")
	second := addTestTunnel(s, "a-a-00000002", "1.1.1.1", "user-1")
	if err := s.enforceTunnelLimits(context.Background(), second); err != nil {
		t.Fatalf("2nd tunnel within limit 2 rejected: %v", err)
	}
	third := addTestTunnel(s, "a-a-00000003", "2.2.2.2", "user-1")
	err := s.enforceTunnelLimits(context.Background(), third)
	if err == nil || !strings.Contains(err.Error(), "allows 2 active tunnels") {
		t.Fatalf("3rd tunnel over limit 2: got %v", err)
	}
	other := addTestTunnel(s, "a-a-00000004", "1.1.1.1", "user-2")
	if err := s.enforceTunnelLimits(context.Background(), other); err != nil {
		t.Fatalf("another user's tunnel should not count: %v", err)
	}
}

func TestEnforceTunnelLimitsAnonymousPerIP(t *testing.T) {
	s := newTestServer(t)
	s.SetAnonMaxTunnelsPerIP(1)
	addTestTunnel(s, "b-b-00000001", "3.3.3.3", "")
	signedIn := addTestTunnel(s, "b-b-00000002", "3.3.3.3", "")
	if err := s.enforceTunnelLimits(context.Background(), signedIn); err == nil {
		t.Fatal("2nd anonymous tunnel from same IP should be rejected")
	}
	otherIP := addTestTunnel(s, "b-b-00000003", "4.4.4.4", "")
	if err := s.enforceTunnelLimits(context.Background(), otherIP); err != nil {
		t.Fatalf("different IP should be allowed: %v", err)
	}
}
