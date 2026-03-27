package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// ── Custom Domains ─────────────────────────────────────────────

type customDomainScanner interface {
	Scan(dest ...any) error
}

func scanCustomDomain(row customDomainScanner) (*models.CustomDomain, error) {
	d := &models.CustomDomain{}
	err := row.Scan(
		&d.ID, &d.UserID, &d.Domain, &d.Status, &d.VerificationToken,
		&d.TargetSubdomain, &d.CreatedAt, &d.VerifiedAt, &d.LastCheckedAt,
	)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func (db *DB) ListCustomDomains(ctx context.Context, userID string) ([]*models.CustomDomain, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, domain, status, verification_token,
		       target_subdomain, created_at, verified_at, last_checked_at
		FROM custom_domains
		WHERE user_id = $1
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.CustomDomain
	for rows.Next() {
		d, err := scanCustomDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (db *DB) CreateCustomDomain(ctx context.Context, userID, domain string) (*models.CustomDomain, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO custom_domains (user_id, domain)
		VALUES ($1, $2)
		RETURNING id, user_id, domain, status, verification_token,
		          target_subdomain, created_at, verified_at, last_checked_at`,
		userID, domain)
	d, err := scanCustomDomain(row)
	if err != nil {
		return nil, err
	}
	db.invalidateCustomDomainLookup(ctx, d.Domain)
	return d, nil
}

func (db *DB) GetCustomDomain(ctx context.Context, id, userID string) (*models.CustomDomain, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, domain, status, verification_token,
		       target_subdomain, created_at, verified_at, last_checked_at
		FROM custom_domains WHERE id = $1 AND user_id = $2`, id, userID)
	return scanCustomDomain(row)
}

func (db *DB) GetCustomDomainByID(ctx context.Context, id string) (*models.CustomDomain, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, domain, status, verification_token,
		       target_subdomain, created_at, verified_at, last_checked_at
		FROM custom_domains WHERE id = $1`, id)
	return scanCustomDomain(row)
}

func (db *DB) ListAllCustomDomains(ctx context.Context, userID, status, search string, limit, offset int) ([]*models.CustomDomain, error) {
	query := `
		SELECT id, user_id, domain, status, verification_token,
		       target_subdomain, created_at, verified_at, last_checked_at
		FROM custom_domains`
	args := make([]any, 0, 4)
	conditions := make([]string, 0, 3)
	i := 1

	if userID != "" {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", i))
		args = append(args, userID)
		i++
	}
	if status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", i))
		args = append(args, status)
		i++
	}
	if search != "" {
		conditions = append(conditions, fmt.Sprintf("domain ILIKE $%d", i))
		args = append(args, "%"+search+"%")
		i++
	}
	if len(conditions) > 0 {
		query += " WHERE " + conditions[0]
		for _, cond := range conditions[1:] {
			query += " AND " + cond
		}
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", i, i+1)
	args = append(args, limit, offset)

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.CustomDomain
	for rows.Next() {
		d, err := scanCustomDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (db *DB) DeleteCustomDomain(ctx context.Context, id, userID string) error {
	if db.redis == nil {
		_, err := db.Pool.Exec(ctx,
			`DELETE FROM custom_domains WHERE id = $1 AND user_id = $2`, id, userID)
		return err
	}

	var domain string
	err := db.Pool.QueryRow(ctx,
		`DELETE FROM custom_domains WHERE id = $1 AND user_id = $2 RETURNING lower(domain)`,
		id, userID).Scan(&domain)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}
	db.invalidateCustomDomainLookup(ctx, domain)
	return nil
}

func (db *DB) DeleteCustomDomainByID(ctx context.Context, id string) error {
	if db.redis == nil {
		_, err := db.Pool.Exec(ctx,
			`DELETE FROM custom_domains WHERE id = $1`, id)
		return err
	}

	var domain string
	err := db.Pool.QueryRow(ctx,
		`DELETE FROM custom_domains WHERE id = $1 RETURNING lower(domain)`, id).Scan(&domain)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}
	db.invalidateCustomDomainLookup(ctx, domain)
	return nil
}

func (db *DB) SetCustomDomainVerified(ctx context.Context, id string) error {
	now := time.Now()
	if db.redis == nil {
		_, err := db.Pool.Exec(ctx,
			`UPDATE custom_domains SET status='verified', verified_at=$1, last_checked_at=$1 WHERE id=$2`,
			now, id)
		return err
	}

	var domain string
	err := db.Pool.QueryRow(ctx,
		`UPDATE custom_domains
		 SET status='verified', verified_at=$1, last_checked_at=$1
		 WHERE id=$2
		 RETURNING lower(domain)`,
		now, id).Scan(&domain)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}
	db.invalidateCustomDomainLookup(ctx, domain)
	return nil
}

func (db *DB) SetCustomDomainFailed(ctx context.Context, id string) error {
	now := time.Now()
	if db.redis == nil {
		_, err := db.Pool.Exec(ctx,
			`UPDATE custom_domains SET status='failed', last_checked_at=$1 WHERE id=$2`, now, id)
		return err
	}

	var domain string
	err := db.Pool.QueryRow(ctx,
		`UPDATE custom_domains
		 SET status='failed', last_checked_at=$1
		 WHERE id=$2
		 RETURNING lower(domain)`,
		now, id).Scan(&domain)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}
	db.invalidateCustomDomainLookup(ctx, domain)
	return nil
}

func (db *DB) SetCustomDomainTarget(ctx context.Context, id, userID, targetSubdomain string) error {
	if db.redis == nil {
		_, err := db.Pool.Exec(ctx,
			`UPDATE custom_domains SET target_subdomain=$1 WHERE id=$2 AND user_id=$3`,
			targetSubdomain, id, userID)
		return err
	}

	var domain string
	err := db.Pool.QueryRow(ctx,
		`UPDATE custom_domains
		 SET target_subdomain=$1
		 WHERE id=$2 AND user_id=$3
		 RETURNING lower(domain)`,
		targetSubdomain, id, userID).Scan(&domain)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}
	db.invalidateCustomDomainLookup(ctx, domain)
	return nil
}

func (db *DB) SetCustomDomainTargetByID(ctx context.Context, id, targetSubdomain string) error {
	if db.redis == nil {
		_, err := db.Pool.Exec(ctx,
			`UPDATE custom_domains SET target_subdomain=$1 WHERE id=$2`,
			targetSubdomain, id)
		return err
	}

	var domain string
	err := db.Pool.QueryRow(ctx,
		`UPDATE custom_domains
		 SET target_subdomain=$1
		 WHERE id=$2
		 RETURNING lower(domain)`,
		targetSubdomain, id).Scan(&domain)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil
		}
		return err
	}
	db.invalidateCustomDomainLookup(ctx, domain)
	return nil
}

// LookupVerifiedCustomDomainTarget returns the routed reserved subdomain for a
// verified custom domain, or found=false when the host is unknown.
func (db *DB) LookupVerifiedCustomDomainTarget(ctx context.Context, host string) (targetSubdomain string, found bool, err error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if db.redis != nil {
		target, cachedFound, cached, cacheErr := db.redis.GetCustomDomainTarget(ctx, host)
		if cacheErr == nil && cached {
			return target, cachedFound, nil
		}
	}

	err = db.Pool.QueryRow(ctx, `
		SELECT COALESCE(target_subdomain, '')
		FROM custom_domains
		WHERE status = 'verified' AND lower(domain) = lower($1)
		LIMIT 1`, host).Scan(&targetSubdomain)
	if err != nil {
		if err == pgx.ErrNoRows {
			if db.redis != nil {
				_ = db.redis.SetCustomDomainTarget(ctx, host, "", false)
			}
			return "", false, nil
		}
		return "", false, err
	}
	if db.redis != nil {
		_ = db.redis.SetCustomDomainTarget(ctx, host, targetSubdomain, true)
	}
	return targetSubdomain, true, nil
}

// ListVerifiedCustomDomains returns all verified domains — used by the proxy to route traffic.
func (db *DB) ListVerifiedCustomDomains(ctx context.Context) ([]*models.CustomDomain, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, domain, status, verification_token,
		       target_subdomain, created_at, verified_at, last_checked_at
		FROM custom_domains WHERE status = 'verified'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*models.CustomDomain
	for rows.Next() {
		d, err := scanCustomDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (db *DB) invalidateCustomDomainLookup(ctx context.Context, domain string) {
	if db.redis == nil {
		return
	}
	_ = db.redis.DeleteCustomDomainTarget(ctx, domain)
}
