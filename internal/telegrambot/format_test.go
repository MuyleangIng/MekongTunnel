package telegrambot

import (
	"strings"
	"testing"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

func TestFormatHelpIncludesCoreCommands(t *testing.T) {
	got := FormatHelp()

	for _, want := range []string{
		"`/link`",
		"`/services`",
		"`/logs <id>`",
		"`/domain <host>`",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FormatHelp missing %q in %q", want, got)
		}
	}
}

func TestFormatUserIncludesStatusAndNextStep(t *testing.T) {
	got := FormatUser(&models.User{
		Name:          "Jane",
		Email:         "jane_test@example.com",
		EmailVerified: false,
		Plan:          "pro",
		AccountType:   "personal",
	})

	for _, want := range []string{
		"*Your Mekong Account*",
		"Name: Jane",
		"Email: jane\\_test@example.com",
		"Status: ⚠ not verified",
		"Plan: PRO",
		"Account: PERSONAL",
		"Next: `/services`",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FormatUser missing %q in %q", want, got)
		}
	}
}

func TestFormatTunnelsShowsReadableMonitoringView(t *testing.T) {
	got := FormatTunnels([]*models.Tunnel{
		{ID: "tun_1", Subdomain: "myapp", LocalPort: 3000, Status: "active", TotalRequests: 1284},
		{ID: "tun_2", Subdomain: "admin", LocalPort: 8080, Status: "active", TotalRequests: 214},
	})

	for _, want := range []string{
		"*Active Tunnels* (2)",
		"🟢 `myapp`",
		"Port: `3000` | Requests: `1,284`",
		"🟢 `admin`",
		"Tip: Use `/logs <subdomain>` to inspect one tunnel.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FormatTunnels missing %q in %q", want, got)
		}
	}
}

func TestFormatDomainShowsStatusTargetAndTimes(t *testing.T) {
	createdAt := time.Date(2026, time.April, 1, 14, 10, 0, 0, time.FixedZone("KST", 9*60*60))
	lastChecked := time.Date(2026, time.April, 8, 9, 15, 0, 0, time.FixedZone("KST", 9*60*60))
	verifiedAt := time.Date(2026, time.April, 8, 9, 20, 0, 0, time.FixedZone("KST", 9*60*60))
	target := "myapp"

	got := FormatDomain(&models.CustomDomain{
		Domain:          "app.example.com",
		Status:          "active",
		TargetSubdomain: &target,
		CreatedAt:       createdAt,
		LastCheckedAt:   &lastChecked,
		VerifiedAt:      &verifiedAt,
	})

	for _, want := range []string{
		"✅ *Domain Check*",
		"Host: `app.example.com`",
		"Status: active",
		"Target: `myapp`",
		"Last checked: 08 Apr 2026 09:15 KST",
		"Verified: 08 Apr 2026 09:20 KST",
		"Added: 01 Apr 2026 14:10 KST",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FormatDomain missing %q in %q", want, got)
		}
	}
}

func TestFormatLogsPlainRedactsSecrets(t *testing.T) {
	got := FormatLogsPlain([]string{
		"Authorization: Bearer abc123",
		"Cookie: sid=secret",
		"GET /health 200",
	}, "myapp")

	for _, want := range []string{
		"Recent logs: myapp",
		"Last 20 lines. Secrets are redacted.",
		"Authorization: Bearer [REDACTED]",
		"[REDACTED]",
		"GET /health 200",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FormatLogsPlain missing %q in %q", want, got)
		}
	}

	for _, secret := range []string{"abc123", "sid=secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("FormatLogsPlain leaked %q in %q", secret, got)
		}
	}
}

func TestFutureAlertTemplates(t *testing.T) {
	down := FormatTunnelDownAlert("myapp", 3000)
	if !strings.Contains(down, "🔴 Tunnel Down") || !strings.Contains(down, "Then: /logs myapp") {
		t.Fatalf("FormatTunnelDownAlert returned unexpected output: %q", down)
	}

	failed := FormatDomainFailedAlert("app.example.com", "")
	if !strings.Contains(failed, "🔴 Domain Failed") || !strings.Contains(failed, "Check: /domain app.example.com") {
		t.Fatalf("FormatDomainFailedAlert returned unexpected output: %q", failed)
	}

	ready := FormatDomainReadyAlert("app.example.com", "myapp")
	if !strings.Contains(ready, "✅ Domain Ready") || !strings.Contains(ready, "Target: myapp") {
		t.Fatalf("FormatDomainReadyAlert returned unexpected output: %q", ready)
	}

	updated := FormatDomainUpdatedAlert("app.example.com", "myapp")
	if !strings.Contains(updated, "🟡 Domain Updated") || !strings.Contains(updated, "Status: route updated") {
		t.Fatalf("FormatDomainUpdatedAlert returned unexpected output: %q", updated)
	}

	recovered := FormatTunnelRecoveredAlert("myapp")
	if !strings.Contains(recovered, "🟢 Tunnel Recovered") || !strings.Contains(recovered, "Check: /services") {
		t.Fatalf("FormatTunnelRecoveredAlert returned unexpected output: %q", recovered)
	}
}
