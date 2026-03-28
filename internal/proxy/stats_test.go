package proxy

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/tunnel"
)

func TestStreamTunnelLogsEmitsReadyAndKeepalive(t *testing.T) {
	origRetry := tunnelLogSSERetryInterval
	origHeartbeat := tunnelLogSSEHeartbeatInterval
	tunnelLogSSERetryInterval = 25 * time.Millisecond
	tunnelLogSSEHeartbeatInterval = 10 * time.Millisecond
	defer func() {
		tunnelLogSSERetryInterval = origRetry
		tunnelLogSSEHeartbeatInterval = origHeartbeat
	}()

	logger := tunnel.NewRequestLogger(io.Discard, 4)
	defer logger.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/api/tunnels/logs/demo?stream=sse", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		streamTunnelLogs(rec, req, "demo", logger)
		close(done)
	}()

	time.Sleep(35 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("streamTunnelLogs did not exit after request context cancellation")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "retry: 25") {
		t.Fatalf("missing SSE retry hint in body: %q", body)
	}
	if !strings.Contains(body, "event: ready") {
		t.Fatalf("missing ready event in body: %q", body)
	}
	if !strings.Contains(body, ": keepalive") {
		t.Fatalf("missing keepalive heartbeat in body: %q", body)
	}
}
