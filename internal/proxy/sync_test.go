package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/tunnel"
)

func TestTunnelSyncOpenAndClose(t *testing.T) {
	var openPayload map[string]any
	var closePayload map[string]any

	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/tunnels":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read open body: %v", err)
			}
			if err := json.Unmarshal(body, &openPayload); err != nil {
				t.Fatalf("decode open body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case r.Method == http.MethodPatch && r.URL.Path != "":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read close body: %v", err)
			}
			if err := json.Unmarshal(body, &closePayload); err != nil {
				t.Fatalf("decode close body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer api.Close()

	srv := &Server{}
	srv.SetAPIBaseURL(api.URL)

	tun := tunnel.New("myapp", fakeListener{}, "127.0.0.1", 80, "127.0.0.1", config.DefaultTunnelLifetime)
	tun.SetLocalPort(3000)
	tun.SetUserID("user-123")
	tun.RecordTraffic(512)

	if err := srv.syncTunnelUpsert(context.Background(), tun); err != nil {
		t.Fatalf("syncTunnelUpsert() error: %v", err)
	}
	if err := srv.syncTunnelStopped(context.Background(), tun); err != nil {
		t.Fatalf("syncTunnelStopped() error: %v", err)
	}

	if got := openPayload["id"]; got == "" || got == nil {
		t.Fatal("open payload missing tunnel id")
	}
	if got := openPayload["subdomain"]; got != "myapp" {
		t.Fatalf("open payload subdomain = %v, want myapp", got)
	}
	if got := openPayload["user_id"]; got != "user-123" {
		t.Fatalf("open payload user_id = %v, want user-123", got)
	}

	if got := closePayload["status"]; got != "stopped" {
		t.Fatalf("close payload status = %v, want stopped", got)
	}
	if got := closePayload["total_requests"]; got != float64(1) {
		t.Fatalf("close payload total_requests = %v, want 1", got)
	}
	if got := closePayload["total_bytes"]; got != float64(512) {
		t.Fatalf("close payload total_bytes = %v, want 512", got)
	}
}
