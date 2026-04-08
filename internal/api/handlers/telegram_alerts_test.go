package handlers

import (
	"context"
	"testing"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

type fakeTelegramAlerter struct {
	calls []string
}

func (f *fakeTelegramAlerter) NotifyTunnelDown(_ context.Context, userID, service string, port int) {
	f.calls = append(f.calls, "tunnel_down:"+userID+":"+service)
}

func (f *fakeTelegramAlerter) NotifyTunnelIssue(_ context.Context, userID, service, symptom string) {
	f.calls = append(f.calls, "tunnel_issue:"+userID+":"+service+":"+symptom)
}

func (f *fakeTelegramAlerter) NotifyTunnelRecovered(_ context.Context, userID, service string) {
	f.calls = append(f.calls, "tunnel_recovered:"+userID+":"+service)
}

func (f *fakeTelegramAlerter) NotifyDomainPending(_ context.Context, userIDs []string, host string) {
	f.calls = append(f.calls, "domain_pending:"+host)
}

func (f *fakeTelegramAlerter) NotifyDomainFailed(_ context.Context, userIDs []string, host, reason string) {
	f.calls = append(f.calls, "domain_failed:"+host)
}

func (f *fakeTelegramAlerter) NotifyDomainReady(_ context.Context, userIDs []string, host, target string) {
	f.calls = append(f.calls, "domain_ready:"+host+":"+target)
}

func (f *fakeTelegramAlerter) NotifyDomainUpdated(_ context.Context, userIDs []string, host, target string) {
	f.calls = append(f.calls, "domain_updated:"+host+":"+target)
}

func TestNotifyTunnelTransitionRoutesDownIssueAndRecovered(t *testing.T) {
	userID := "user-1"
	before := &models.Tunnel{
		ID:        "tun_123",
		Subdomain: "myapp",
		UserID:    &userID,
		LocalPort: 3000,
		Status:    "active",
	}

	t.Run("down", func(t *testing.T) {
		fake := &fakeTelegramAlerter{}
		notifyTunnelTransition(context.Background(), fake, before, "stopped")
		if len(fake.calls) != 1 || fake.calls[0] != "tunnel_down:user-1:myapp" {
			t.Fatalf("unexpected calls: %#v", fake.calls)
		}
	})

	t.Run("issue", func(t *testing.T) {
		fake := &fakeTelegramAlerter{}
		notifyTunnelTransition(context.Background(), fake, before, "failed")
		if len(fake.calls) != 1 || fake.calls[0] != "tunnel_issue:user-1:myapp:status changed to failed" {
			t.Fatalf("unexpected calls: %#v", fake.calls)
		}
	})

	t.Run("recovered", func(t *testing.T) {
		fake := &fakeTelegramAlerter{}
		stopped := *before
		stopped.Status = "stopped"
		notifyTunnelTransition(context.Background(), fake, &stopped, "active")
		if len(fake.calls) != 1 || fake.calls[0] != "tunnel_recovered:user-1:myapp" {
			t.Fatalf("unexpected calls: %#v", fake.calls)
		}
	})
}

func TestNotifyDomainVerificationResultRoutesExpectedAlert(t *testing.T) {
	target := "myapp"
	domain := &models.CustomDomain{
		Domain:          "app.example.com",
		TargetSubdomain: &target,
	}

	t.Run("pending", func(t *testing.T) {
		fake := &fakeTelegramAlerter{}
		notifyDomainVerificationResult(context.Background(), fake, []string{"user-1"}, domain, true, false, "")
		if len(fake.calls) != 1 || fake.calls[0] != "domain_pending:app.example.com" {
			t.Fatalf("unexpected calls: %#v", fake.calls)
		}
	})

	t.Run("failed", func(t *testing.T) {
		fake := &fakeTelegramAlerter{}
		notifyDomainVerificationResult(context.Background(), fake, []string{"user-1"}, domain, false, false, "dns failed")
		if len(fake.calls) != 1 || fake.calls[0] != "domain_failed:app.example.com" {
			t.Fatalf("unexpected calls: %#v", fake.calls)
		}
	})

	t.Run("ready", func(t *testing.T) {
		fake := &fakeTelegramAlerter{}
		notifyDomainVerificationResult(context.Background(), fake, []string{"user-1"}, domain, true, true, "")
		if len(fake.calls) != 1 || fake.calls[0] != "domain_ready:app.example.com:myapp" {
			t.Fatalf("unexpected calls: %#v", fake.calls)
		}
	})
}
