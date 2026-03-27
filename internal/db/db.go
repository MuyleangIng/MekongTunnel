// Package db provides PostgreSQL access for MekongTunnel API.
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package db

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/redisx"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgxpool.Pool and exposes all query methods.
type DB struct {
	Pool  *pgxpool.Pool
	redis *redisx.Client
}

// Connect creates a new connection pool using the provided PostgreSQL URL.
func Connect(databaseURL string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse db config: %w", err)
	}
	applyPoolTuningFromEnv(cfg)

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, fmt.Errorf("create db pool: %w", err)
	}

	// Verify connectivity.
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return &DB{Pool: pool}, nil
}

// Close releases all connections in the pool.
func (db *DB) Close() {
	db.Pool.Close()
}

// SetRedis attaches the optional Redis services used for cache and ephemeral state.
func (db *DB) SetRedis(client *redisx.Client) {
	db.redis = client
}

func applyPoolTuningFromEnv(cfg *pgxpool.Config) {
	if n, ok := getenvInt32("DB_MAX_CONNS"); ok && n > 0 {
		cfg.MaxConns = n
	}
	if n, ok := getenvInt32("DB_MIN_CONNS"); ok && n >= 0 {
		cfg.MinConns = n
	}
	if d, ok := getenvDuration("DB_MAX_CONN_LIFETIME"); ok && d > 0 {
		cfg.MaxConnLifetime = d
	}
	if d, ok := getenvDuration("DB_MAX_CONN_IDLE_TIME"); ok && d > 0 {
		cfg.MaxConnIdleTime = d
	}
	if d, ok := getenvDuration("DB_HEALTH_CHECK_PERIOD"); ok && d > 0 {
		cfg.HealthCheckPeriod = d
	}
}

func getenvInt32(key string) (int32, bool) {
	raw := os.Getenv(key)
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return int32(n), true
}

func getenvDuration(key string) (time.Duration, bool) {
	raw := os.Getenv(key)
	if raw == "" {
		return 0, false
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, false
	}
	return d, true
}
