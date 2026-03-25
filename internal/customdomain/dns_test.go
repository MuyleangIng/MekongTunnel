package customdomain

import (
	"net"
	"testing"
)

func TestBuildDNSInstructionsApex(t *testing.T) {
	got := BuildDNSInstructions("muyleanging.com", "proxy.angkorsearch.dev", "abc123", func(string) ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("216.198.79.1"),
			net.ParseIP("2001:db8::1"),
		}, nil
	})

	if got.Mode != ModeApex {
		t.Fatalf("BuildDNSInstructions() mode = %q, want %q", got.Mode, ModeApex)
	}
	if len(got.PrimaryRecords) != 2 {
		t.Fatalf("BuildDNSInstructions() primary record count = %d, want 2", len(got.PrimaryRecords))
	}
	if got.PrimaryRecords[0].Type != "A" || got.PrimaryRecords[0].Name != "@" || got.PrimaryRecords[0].Value != "216.198.79.1" {
		t.Fatalf("BuildDNSInstructions() first primary record = %#v", got.PrimaryRecords[0])
	}
	if got.PrimaryRecords[1].Type != "AAAA" || got.PrimaryRecords[1].Name != "@" || got.PrimaryRecords[1].Value != "2001:db8::1" {
		t.Fatalf("BuildDNSInstructions() second primary record = %#v", got.PrimaryRecords[1])
	}
	if len(got.FallbackRecords) != 1 {
		t.Fatalf("BuildDNSInstructions() fallback record count = %d, want 1", len(got.FallbackRecords))
	}
	if got.FallbackRecords[0].Type != "TXT" || got.FallbackRecords[0].Name != "_mekongtunnel-verify" {
		t.Fatalf("BuildDNSInstructions() fallback record = %#v", got.FallbackRecords[0])
	}
}

func TestBuildDNSInstructionsSubdomain(t *testing.T) {
	got := BuildDNSInstructions("test.muyleanging.com", "proxy.angkorsearch.dev", "abc123", nil)

	if got.Mode != ModeSubdomain {
		t.Fatalf("BuildDNSInstructions() mode = %q, want %q", got.Mode, ModeSubdomain)
	}
	if len(got.PrimaryRecords) != 1 {
		t.Fatalf("BuildDNSInstructions() primary record count = %d, want 1", len(got.PrimaryRecords))
	}
	if got.PrimaryRecords[0].Type != "CNAME" || got.PrimaryRecords[0].Name != "test" || got.PrimaryRecords[0].Value != "proxy.angkorsearch.dev" {
		t.Fatalf("BuildDNSInstructions() primary record = %#v", got.PrimaryRecords[0])
	}
	if len(got.FallbackRecords) != 1 {
		t.Fatalf("BuildDNSInstructions() fallback record count = %d, want 1", len(got.FallbackRecords))
	}
	if got.FallbackRecords[0].Type != "TXT" || got.FallbackRecords[0].Name != "_mekongtunnel-verify.test" {
		t.Fatalf("BuildDNSInstructions() fallback record = %#v", got.FallbackRecords[0])
	}
}

func TestIsApexDomainWithMultiLabelSuffix(t *testing.T) {
	if !IsApexDomain("example.com.kh") {
		t.Fatal("IsApexDomain(example.com.kh) = false, want true")
	}
	if IsApexDomain("app.example.com.kh") {
		t.Fatal("IsApexDomain(app.example.com.kh) = true, want false")
	}
}

func TestValidateDomainRejectsEmptyLabel(t *testing.T) {
	if err := ValidateDomain("ttt..mekongtunnel.dev"); err == nil {
		t.Fatal("ValidateDomain() error = nil, want invalid domain")
	}
}
