package redisx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	defaultPrefix              = "mekong"
	defaultCacheTTL            = 30 * time.Second
	defaultDomainCacheTTL      = 1 * time.Minute
	defaultNotificationChannel = "notifications"
)

// Config controls the optional Redis integration.
type Config struct {
	URL                 string
	Prefix              string
	DefaultCacheTTL     time.Duration
	DomainCacheTTL      time.Duration
	NotificationChannel string
}

// Client wraps a Redis client plus Mekong-specific key conventions.
type Client struct {
	raw                 *redis.Client
	prefix              string
	defaultCacheTTL     time.Duration
	domainCacheTTL      time.Duration
	notificationChannel string
}

// ConfigFromEnv reads Redis configuration from environment variables.
func ConfigFromEnv() Config {
	cfg := Config{
		URL:                 strings.TrimSpace(os.Getenv("REDIS_URL")),
		Prefix:              strings.TrimSpace(os.Getenv("REDIS_PREFIX")),
		DefaultCacheTTL:     defaultCacheTTL,
		DomainCacheTTL:      defaultDomainCacheTTL,
		NotificationChannel: strings.TrimSpace(os.Getenv("REDIS_NOTIFICATION_CHANNEL")),
	}
	if d, ok := getenvDuration("REDIS_CACHE_TTL"); ok && d > 0 {
		cfg.DefaultCacheTTL = d
	}
	if d, ok := getenvDuration("REDIS_DOMAIN_CACHE_TTL"); ok && d > 0 {
		cfg.DomainCacheTTL = d
	}
	return cfg
}

// Connect establishes an optional Redis connection. When cfg.URL is empty, Redis is disabled.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, nil
	}

	opt, err := redis.ParseURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}

	raw := redis.NewClient(opt)
	if err := raw.Ping(ctx).Err(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	if cfg.Prefix == "" {
		cfg.Prefix = defaultPrefix
	}
	if cfg.DefaultCacheTTL <= 0 {
		cfg.DefaultCacheTTL = defaultCacheTTL
	}
	if cfg.DomainCacheTTL <= 0 {
		cfg.DomainCacheTTL = defaultDomainCacheTTL
	}
	if cfg.NotificationChannel == "" {
		cfg.NotificationChannel = defaultNotificationChannel
	}

	return &Client{
		raw:                 raw,
		prefix:              cfg.Prefix,
		defaultCacheTTL:     cfg.DefaultCacheTTL,
		domainCacheTTL:      cfg.DomainCacheTTL,
		notificationChannel: cfg.NotificationChannel,
	}, nil
}

// Enabled reports whether Redis integration is active.
func (c *Client) Enabled() bool {
	return c != nil && c.raw != nil
}

// Close closes the underlying Redis connection.
func (c *Client) Close() error {
	if !c.Enabled() {
		return nil
	}
	return c.raw.Close()
}

// DefaultCacheTTL returns the configured generic cache TTL.
func (c *Client) DefaultCacheTTL() time.Duration {
	if !c.Enabled() || c.defaultCacheTTL <= 0 {
		return defaultCacheTTL
	}
	return c.defaultCacheTTL
}

// DomainCacheTTL returns the configured custom-domain lookup cache TTL.
func (c *Client) DomainCacheTTL() time.Duration {
	if !c.Enabled() || c.domainCacheTTL <= 0 {
		return defaultDomainCacheTTL
	}
	return c.domainCacheTTL
}

func (c *Client) key(parts ...string) string {
	if !c.Enabled() {
		return ""
	}
	return c.prefix + ":" + strings.Join(parts, ":")
}

func (c *Client) notificationChannelKey() string {
	return c.key("pubsub", c.notificationChannel)
}

func (c *Client) getJSON(ctx context.Context, key string, dst any) (bool, error) {
	if !c.Enabled() {
		return false, nil
	}
	raw, err := c.raw.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return false, nil
		}
		return false, err
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Client) setJSON(ctx context.Context, key string, value any, ttl time.Duration) error {
	if !c.Enabled() {
		return nil
	}
	if ttl <= 0 {
		ttl = c.DefaultCacheTTL()
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.raw.Set(ctx, key, payload, ttl).Err()
}

func (c *Client) getString(ctx context.Context, key string) (string, bool, error) {
	if !c.Enabled() {
		return "", false, nil
	}
	value, err := c.raw.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", false, nil
		}
		return "", false, err
	}
	return value, true, nil
}

func (c *Client) setString(ctx context.Context, key, value string, ttl time.Duration) error {
	if !c.Enabled() {
		return nil
	}
	if ttl <= 0 {
		ttl = c.DefaultCacheTTL()
	}
	return c.raw.Set(ctx, key, value, ttl).Err()
}

func (c *Client) delete(ctx context.Context, keys ...string) error {
	if !c.Enabled() || len(keys) == 0 {
		return nil
	}
	return c.raw.Del(ctx, keys...).Err()
}

func getenvDuration(key string) (time.Duration, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, false
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, false
	}
	return d, true
}
