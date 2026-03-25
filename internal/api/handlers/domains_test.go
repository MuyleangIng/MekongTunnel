package handlers

import (
	"strings"
	"testing"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

func TestVerifyMessagePendingHTTPS(t *testing.T) {
	got := verifyMessage(true, false, false, false, "x509: certificate mismatch")
	if !strings.Contains(got, "HTTPS is not ready yet") {
		t.Fatalf("verifyMessage() = %q, want HTTPS pending guidance", got)
	}
	if !strings.Contains(got, "certificate mismatch") {
		t.Fatalf("verifyMessage() = %q, want TLS error detail", got)
	}
}

func TestVerifyMessageReady(t *testing.T) {
	got := verifyMessage(true, false, false, true, "")
	if got != "Domain verified via CNAME record and HTTPS is ready." {
		t.Fatalf("verifyMessage() = %q, want ready message", got)
	}
}

func TestVerifyMessagePendingDNS(t *testing.T) {
	got := verifyMessage(false, false, false, false, "")
	if !strings.Contains(got, "DNS verification failed") {
		t.Fatalf("verifyMessage() = %q, want DNS failure guidance", got)
	}
}

func TestVerifyMessageAddressReady(t *testing.T) {
	got := verifyMessage(false, false, true, true, "")
	if got != "Domain verified via A/AAAA record and HTTPS is ready." {
		t.Fatalf("verifyMessage() = %q, want address-based ready message", got)
	}
}

func TestVerifyMessageSuppressesRedundantAddressWhenCNAMEExists(t *testing.T) {
	got := verifyMessage(true, false, true, true, "")
	if got != "Domain verified via CNAME record and HTTPS is ready." {
		t.Fatalf("verifyMessage() = %q, want CNAME-only ready message", got)
	}
}

func TestValidateCustomDomainRejectsEmptyLabel(t *testing.T) {
	if err := validateCustomDomain("ttt..mekongtunnel.dev"); err == nil {
		t.Fatal("validateCustomDomain() error = nil, want invalid domain")
	}
}

func TestDeleteResultForDomainExplainsCleanup(t *testing.T) {
	target := "myapp"
	got := deleteResultForDomain(&models.CustomDomain{
		Domain:          "app.example.com",
		TargetSubdomain: &target,
	})
	if !got.RouteRemoved || got.DNSChanged {
		t.Fatalf("deleteResultForDomain() = %#v, want route_removed=true and dns_changed=false", got)
	}
	if !strings.Contains(got.HTTPSNote, "certificate") {
		t.Fatalf("deleteResultForDomain() https_note = %q, want certificate guidance", got.HTTPSNote)
	}
	if !strings.Contains(got.CleanupAction, "DNS record") {
		t.Fatalf("deleteResultForDomain() cleanup_action = %q, want DNS cleanup guidance", got.CleanupAction)
	}
}
