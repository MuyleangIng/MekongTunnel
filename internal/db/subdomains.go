package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// ── Reserved subdomains ───────────────────────────────────────

func (db *DB) ListReservedSubdomains(ctx context.Context, userID string) ([]*models.ReservedSubdomain, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT rs.id, rs.user_id, rs.subdomain, rs.created_at,
		       sr.id, sr.allowed_ips, sr.allowed_agents, sr.rate_limit_rpm,
		       sr.max_connections, sr.block_tor, sr.force_https, sr.custom_headers, sr.enabled, sr.updated_at
		FROM reserved_subdomains rs
		LEFT JOIN subdomain_rules sr ON sr.subdomain_id = rs.id
		WHERE rs.user_id = $1
		ORDER BY rs.created_at DESC`, userID)
	if err != nil { return nil, err }
	defer rows.Close()

	var out []*models.ReservedSubdomain
	for rows.Next() {
		s := &models.ReservedSubdomain{}
		// All rule fields are nullable (LEFT JOIN may return NULL)
		var (
			ruleID         *string
			allowedIPs     []string
			allowedAgents  []string
			rateLimitRPM   *int
			maxConnections *int
			blockTor       *bool
			forceHTTPS     *bool
			hdrs           []byte
			enabled        *bool
			updatedAt      *time.Time
		)
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.Subdomain, &s.CreatedAt,
			&ruleID, &allowedIPs, &allowedAgents, &rateLimitRPM,
			&maxConnections, &blockTor, &forceHTTPS, &hdrs, &enabled, &updatedAt,
		); err != nil {
			return nil, err
		}
		if ruleID != nil {
			r := &models.SubdomainRule{
				ID:             *ruleID,
				SubdomainID:    s.ID,
				AllowedIPs:     allowedIPs,
				AllowedAgents:  allowedAgents,
				RateLimitRPM:   derefInt(rateLimitRPM),
				MaxConnections: derefInt(maxConnections),
				BlockTor:       derefBool(blockTor),
				ForceHTTPS:     derefBool(forceHTTPS),
				Enabled:        derefBool(enabled),
			}
			if updatedAt != nil { r.UpdatedAt = *updatedAt }
			if len(hdrs) > 0 { json.Unmarshal(hdrs, &r.CustomHeaders) }
			s.Rule = r
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (db *DB) CreateReservedSubdomain(ctx context.Context, userID, subdomain string) (*models.ReservedSubdomain, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO reserved_subdomains (user_id, subdomain)
		VALUES ($1, $2)
		RETURNING id, user_id, subdomain, created_at`, userID, subdomain)
	s := &models.ReservedSubdomain{}
	err := row.Scan(&s.ID, &s.UserID, &s.Subdomain, &s.CreatedAt)
	return s, err
}

func (db *DB) DeleteReservedSubdomain(ctx context.Context, id, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM reserved_subdomains WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}

func (db *DB) GetReservedSubdomain(ctx context.Context, id string) (*models.ReservedSubdomain, error) {
	row := db.Pool.QueryRow(ctx, `SELECT id, user_id, subdomain, created_at FROM reserved_subdomains WHERE id = $1`, id)
	s := &models.ReservedSubdomain{}
	return s, row.Scan(&s.ID, &s.UserID, &s.Subdomain, &s.CreatedAt)
}

// ── Subdomain rules ──────────────────────────────────────────

func (db *DB) UpsertSubdomainRule(ctx context.Context, rule *models.SubdomainRule) (*models.SubdomainRule, error) {
	hdrs, _ := json.Marshal(rule.CustomHeaders)
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO subdomain_rules
		  (subdomain_id, allowed_ips, allowed_agents, rate_limit_rpm,
		   max_connections, block_tor, force_https, custom_headers, enabled, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (subdomain_id) DO UPDATE SET
		  allowed_ips    = EXCLUDED.allowed_ips,
		  allowed_agents = EXCLUDED.allowed_agents,
		  rate_limit_rpm = EXCLUDED.rate_limit_rpm,
		  max_connections= EXCLUDED.max_connections,
		  block_tor      = EXCLUDED.block_tor,
		  force_https    = EXCLUDED.force_https,
		  custom_headers = EXCLUDED.custom_headers,
		  enabled        = EXCLUDED.enabled,
		  updated_at     = EXCLUDED.updated_at
		RETURNING id, subdomain_id, allowed_ips, allowed_agents, rate_limit_rpm,
		          max_connections, block_tor, force_https, custom_headers, enabled, updated_at`,
		rule.SubdomainID, rule.AllowedIPs, rule.AllowedAgents,
		rule.RateLimitRPM, rule.MaxConnections, rule.BlockTor, rule.ForceHTTPS,
		hdrs, rule.Enabled, time.Now())

	r := &models.SubdomainRule{}
	var rawHdrs []byte
	err := row.Scan(&r.ID, &r.SubdomainID, &r.AllowedIPs, &r.AllowedAgents,
		&r.RateLimitRPM, &r.MaxConnections, &r.BlockTor, &r.ForceHTTPS,
		&rawHdrs, &r.Enabled, &r.UpdatedAt)
	if err != nil { return nil, err }
	if len(rawHdrs) > 0 { json.Unmarshal(rawHdrs, &r.CustomHeaders) }
	return r, nil
}

func (db *DB) GetSubdomainRuleBySubdomain(ctx context.Context, subdomain string) (*models.SubdomainRule, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT sr.id, sr.subdomain_id, sr.allowed_ips, sr.allowed_agents,
		       sr.rate_limit_rpm, sr.max_connections, sr.block_tor, sr.force_https,
		       sr.custom_headers, sr.enabled, sr.updated_at
		FROM subdomain_rules sr
		JOIN reserved_subdomains rs ON rs.id = sr.subdomain_id
		WHERE rs.subdomain = $1 AND sr.enabled = true`, subdomain)
	r := &models.SubdomainRule{}
	var rawHdrs []byte
	err := row.Scan(&r.ID, &r.SubdomainID, &r.AllowedIPs, &r.AllowedAgents,
		&r.RateLimitRPM, &r.MaxConnections, &r.BlockTor, &r.ForceHTTPS,
		&rawHdrs, &r.Enabled, &r.UpdatedAt)
	if err != nil { return nil, err }
	if len(rawHdrs) > 0 { json.Unmarshal(rawHdrs, &r.CustomHeaders) }
	return r, nil
}

// GetSubdomainCount returns how many reserved subdomains a user has.
func (db *DB) GetSubdomainCount(ctx context.Context, userID string) (int, error) {
	var count int
	err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM reserved_subdomains WHERE user_id = $1`, userID).Scan(&count)
	return count, err
}

// GetSubdomainLimit returns the maxReservedSubdomains for a user's plan (-1 = unlimited).
func (db *DB) GetSubdomainLimit(ctx context.Context, userPlan string) (int, error) {
	var raw []byte
	err := db.Pool.QueryRow(ctx,
		`SELECT config FROM plan_configs WHERE plan_id = $1`, userPlan).Scan(&raw)
	if err != nil {
		return 0, err
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return 0, err
	}
	if v, ok := cfg["maxReservedSubdomains"]; ok {
		switch n := v.(type) {
		case float64:
			return int(n), nil
		}
	}
	return 0, nil
}

// SubdomainAnalytics holds aggregated stats for a reserved subdomain.
type SubdomainAnalytics struct {
	SubdomainID    string  `json:"subdomain_id"`
	Subdomain      string  `json:"subdomain"`
	TotalRequests  int64   `json:"total_requests"`
	TotalBytes     int64   `json:"total_bytes"`
	TunnelCount    int     `json:"tunnel_count"`
	ActiveTunnels  int     `json:"active_tunnels"`
	LastSeenAt     *string `json:"last_seen_at,omitempty"`
}

// GetSubdomainAnalytics returns aggregated tunnel stats for all of a user's reserved subdomains.
func (db *DB) GetSubdomainAnalytics(ctx context.Context, userID string) ([]*SubdomainAnalytics, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT
			rs.id,
			rs.subdomain,
			COALESCE(SUM(t.total_requests), 0)::bigint  AS total_requests,
			COALESCE(SUM(t.total_bytes), 0)::bigint     AS total_bytes,
			COUNT(t.id)::int                             AS tunnel_count,
			COUNT(t.id) FILTER (WHERE t.status='active')::int AS active_tunnels,
			MAX(t.ended_at)::text                        AS last_seen_at
		FROM reserved_subdomains rs
		LEFT JOIN tunnels t ON t.subdomain = rs.subdomain AND t.user_id = rs.user_id
		WHERE rs.user_id = $1
		GROUP BY rs.id, rs.subdomain
		ORDER BY rs.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*SubdomainAnalytics
	for rows.Next() {
		a := &SubdomainAnalytics{}
		if err := rows.Scan(&a.SubdomainID, &a.Subdomain,
			&a.TotalRequests, &a.TotalBytes, &a.TunnelCount, &a.ActiveTunnels, &a.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ── Null-safe helpers ──────────────────────────────────────────

func derefInt(p *int) int {
	if p == nil { return 0 }
	return *p
}

func derefBool(p *bool) bool {
	if p == nil { return false }
	return *p
}
