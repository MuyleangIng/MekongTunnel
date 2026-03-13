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
