package proxy

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/tunnel"
)

func newExpiryTestTunnel(t *testing.T) *tunnel.Tunnel {
	t.Helper()
	return tunnel.New("test-sub-00000000", fakeListener{}, "127.0.0.1", 80, "127.0.0.1", config.DefaultTunnelLifetime)
}

type fakeListener struct{}

func (fakeListener) Accept() (net.Conn, error) { return nil, errors.New("not implemented") }
func (fakeListener) Close() error              { return nil }
func (fakeListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234} }

func TestParseExecExpiryCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
		ok      bool
	}{
		{name: "one word duration", command: "1w", want: "1w", ok: true},
		{name: "long flag equals", command: "--expire=48h", want: "48h", ok: true},
		{name: "short flag equals", command: "-e=2d", want: "2d", ok: true},
		{name: "space separated", command: "--expire 1week", want: "1week", ok: true},
		{name: "unsupported", command: "uname -a", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseExecExpiryCommand(tt.command)
			if ok != tt.ok {
				t.Fatalf("parseExecExpiryCommand(%q) ok = %v, want %v", tt.command, ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("parseExecExpiryCommand(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}

func TestApplyRequestedExpiry(t *testing.T) {
	tun := newExpiryTestTunnel(t)

	if err := applyRequestedExpiry("48h", tun); err != nil {
		t.Fatalf("applyRequestedExpiry() error: %v", err)
	}
	if got := tun.MaxLifetime(); got != 48*time.Hour {
		t.Fatalf("MaxLifetime() = %v, want 48h", got)
	}
}

func TestApplyRequestedExpiry_MaxExceeded(t *testing.T) {
	tun := newExpiryTestTunnel(t)
	if err := applyRequestedExpiry("2w", tun); err == nil {
		t.Fatal("applyRequestedExpiry() should fail when over max lifetime")
	}
}

func TestClaimTrustedDeploySubdomain(t *testing.T) {
	const (
		currentSub = "happy-tiger-12345678"
		targetSub  = "student-demo"
		edgeSecret = "shared-secret"
	)

	srv := &Server{
		tunnels:   make(map[string]*tunnel.Tunnel),
		apiSecret: edgeSecret,
	}
	tun := tunnel.New(currentSub, fakeListener{}, "127.0.0.1", 80, "127.0.0.1", config.DefaultTunnelLifetime)
	tun.SetDeploySubdomain(targetSub)
	tun.SetEdgeSecret(edgeSecret)
	srv.tunnels[currentSub] = tun

	got, err := srv.claimTrustedDeploySubdomain(tun, currentSub)
	if err != nil {
		t.Fatalf("claimTrustedDeploySubdomain() error: %v", err)
	}
	if got != targetSub {
		t.Fatalf("claimTrustedDeploySubdomain() = %q, want %q", got, targetSub)
	}
	if tun.Subdomain != targetSub {
		t.Fatalf("tun.Subdomain = %q, want %q", tun.Subdomain, targetSub)
	}
	if !tun.DisableSync() {
		t.Fatal("trusted deployment tunnel should disable tunnel-session sync")
	}
	if _, ok := srv.tunnels[targetSub]; !ok {
		t.Fatal("renamed deployment tunnel not found in registry")
	}
	if _, ok := srv.tunnels[currentSub]; ok {
		t.Fatal("old deployment tunnel registry key still present after rename")
	}
}

func TestClaimTrustedDeploySubdomain_BadSecret(t *testing.T) {
	const currentSub = "happy-tiger-12345678"

	srv := &Server{
		tunnels:   make(map[string]*tunnel.Tunnel),
		apiSecret: "shared-secret",
	}
	tun := tunnel.New(currentSub, fakeListener{}, "127.0.0.1", 80, "127.0.0.1", config.DefaultTunnelLifetime)
	tun.SetDeploySubdomain("student-demo")
	tun.SetEdgeSecret("wrong-secret")
	srv.tunnels[currentSub] = tun

	got, err := srv.claimTrustedDeploySubdomain(tun, currentSub)
	if err == nil {
		t.Fatal("claimTrustedDeploySubdomain() should fail for a bad edge secret")
	}
	if got != currentSub {
		t.Fatalf("claimTrustedDeploySubdomain() = %q, want %q on failure", got, currentSub)
	}
	if tun.Subdomain != currentSub {
		t.Fatalf("tun.Subdomain = %q, want %q after failure", tun.Subdomain, currentSub)
	}
	if tun.DisableSync() {
		t.Fatal("failed trusted deployment claim must not disable sync")
	}
}
