package redisx

import (
	"context"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

const missingDomainSentinel = "__missing__"

// GetServerConfig returns the cached server config when present.
func (c *Client) GetServerConfig(ctx context.Context) (*models.ServerConfig, bool, error) {
	var cfg models.ServerConfig
	ok, err := c.getJSON(ctx, c.key("cache", "server_config"), &cfg)
	if !ok || err != nil {
		return nil, ok, err
	}
	return &cfg, true, nil
}

// SetServerConfig caches the latest server config snapshot.
func (c *Client) SetServerConfig(ctx context.Context, cfg *models.ServerConfig) error {
	if cfg == nil {
		return nil
	}
	return c.setJSON(ctx, c.key("cache", "server_config"), cfg, c.DefaultCacheTTL())
}

// GetCustomDomainTarget returns a cached custom-domain lookup result.
func (c *Client) GetCustomDomainTarget(ctx context.Context, host string) (target string, found bool, cached bool, err error) {
	key := c.key("cache", "custom_domain_target", normalizeHost(host))
	value, ok, err := c.getString(ctx, key)
	if !ok || err != nil {
		return "", false, ok, err
	}
	if value == missingDomainSentinel {
		return "", false, true, nil
	}
	return value, true, true, nil
}

// SetCustomDomainTarget caches a custom-domain lookup result, including misses.
func (c *Client) SetCustomDomainTarget(ctx context.Context, host, target string, found bool) error {
	value := missingDomainSentinel
	if found {
		value = target
	}
	return c.setString(ctx, c.key("cache", "custom_domain_target", normalizeHost(host)), value, c.DomainCacheTTL())
}

// DeleteCustomDomainTarget invalidates the cached lookup result for a host.
func (c *Client) DeleteCustomDomainTarget(ctx context.Context, host string) error {
	host = normalizeHost(host)
	if host == "" {
		return nil
	}
	return c.delete(ctx, c.key("cache", "custom_domain_target", host))
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}
