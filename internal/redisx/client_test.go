package redisx

import (
	"context"
	"fmt"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)

	client, err := Connect(context.Background(), Config{
		URL:             fmt.Sprintf("redis://%s/0", mr.Addr()),
		Prefix:          "test",
		DefaultCacheTTL: 15 * time.Second,
		DomainCacheTTL:  20 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}

func TestServerConfigCache(t *testing.T) {
	client := newTestClient(t)

	cfg := &models.ServerConfig{
		MaxTunnelsPerIP:       42,
		AnnouncementEnabled:   true,
		AnnouncementText:      "hello",
		AnnouncementColor:     "green",
		AnnouncementLink:      "https://angkorsearch.dev",
		AnnouncementLinkLabel: "Open",
	}

	if err := client.SetServerConfig(context.Background(), cfg); err != nil {
		t.Fatalf("SetServerConfig: %v", err)
	}

	got, ok, err := client.GetServerConfig(context.Background())
	if err != nil {
		t.Fatalf("GetServerConfig: %v", err)
	}
	if !ok {
		t.Fatal("GetServerConfig cache miss")
	}
	if got.MaxTunnelsPerIP != cfg.MaxTunnelsPerIP || got.AnnouncementText != cfg.AnnouncementText {
		t.Fatalf("unexpected config: %+v", got)
	}
}

func TestCustomDomainCache(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.SetCustomDomainTarget(ctx, "App.Example.com", "myapp", true); err != nil {
		t.Fatalf("SetCustomDomainTarget: %v", err)
	}

	target, found, cached, err := client.GetCustomDomainTarget(ctx, "app.example.com")
	if err != nil {
		t.Fatalf("GetCustomDomainTarget: %v", err)
	}
	if !cached || !found || target != "myapp" {
		t.Fatalf("unexpected cached domain result: target=%q found=%v cached=%v", target, found, cached)
	}

	if err := client.SetCustomDomainTarget(ctx, "missing.example.com", "", false); err != nil {
		t.Fatalf("SetCustomDomainTarget miss: %v", err)
	}

	target, found, cached, err = client.GetCustomDomainTarget(ctx, "missing.example.com")
	if err != nil {
		t.Fatalf("GetCustomDomainTarget miss: %v", err)
	}
	if !cached || found || target != "" {
		t.Fatalf("unexpected cached miss result: target=%q found=%v cached=%v", target, found, cached)
	}
}

func TestEmailOTPStore(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	if err := client.StoreEmailOTP(ctx, "user-1", "hash-a", time.Minute); err != nil {
		t.Fatalf("StoreEmailOTP: %v", err)
	}

	ok, err := client.VerifyEmailOTP(ctx, "user-1", "wrong")
	if err != nil {
		t.Fatalf("VerifyEmailOTP wrong: %v", err)
	}
	if ok {
		t.Fatal("VerifyEmailOTP accepted wrong hash")
	}

	ok, err = client.VerifyEmailOTP(ctx, "user-1", "hash-a")
	if err != nil {
		t.Fatalf("VerifyEmailOTP correct: %v", err)
	}
	if !ok {
		t.Fatal("VerifyEmailOTP rejected correct hash")
	}

	ok, err = client.VerifyEmailOTP(ctx, "user-1", "hash-a")
	if err != nil {
		t.Fatalf("VerifyEmailOTP reuse: %v", err)
	}
	if ok {
		t.Fatal("VerifyEmailOTP allowed OTP reuse")
	}
}

func TestAllowRateLimit(t *testing.T) {
	client := newTestClient(t)
	ctx := context.Background()

	allowed, remaining, retryAfter, err := client.AllowRateLimit(ctx, "auth-login", "127.0.0.1", 2, time.Minute)
	if err != nil {
		t.Fatalf("AllowRateLimit #1: %v", err)
	}
	if !allowed || remaining != 1 || retryAfter <= 0 {
		t.Fatalf("unexpected first result: allowed=%v remaining=%d retryAfter=%v", allowed, remaining, retryAfter)
	}

	allowed, remaining, _, err = client.AllowRateLimit(ctx, "auth-login", "127.0.0.1", 2, time.Minute)
	if err != nil {
		t.Fatalf("AllowRateLimit #2: %v", err)
	}
	if !allowed || remaining != 0 {
		t.Fatalf("unexpected second result: allowed=%v remaining=%d", allowed, remaining)
	}

	allowed, remaining, retryAfter, err = client.AllowRateLimit(ctx, "auth-login", "127.0.0.1", 2, time.Minute)
	if err != nil {
		t.Fatalf("AllowRateLimit #3: %v", err)
	}
	if allowed || remaining != 0 || retryAfter <= 0 {
		t.Fatalf("unexpected third result: allowed=%v remaining=%d retryAfter=%v", allowed, remaining, retryAfter)
	}
}
