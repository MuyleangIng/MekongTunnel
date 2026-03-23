package db

import (
	"context"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// ── Custom Domains ─────────────────────────────────────────────

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
		d := &models.CustomDomain{}
		if err := rows.Scan(
			&d.ID, &d.UserID, &d.Domain, &d.Status, &d.VerificationToken,
			&d.TargetSubdomain, &d.CreatedAt, &d.VerifiedAt, &d.LastCheckedAt,
		); err != nil {
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
	d := &models.CustomDomain{}
	err := row.Scan(
		&d.ID, &d.UserID, &d.Domain, &d.Status, &d.VerificationToken,
		&d.TargetSubdomain, &d.CreatedAt, &d.VerifiedAt, &d.LastCheckedAt,
	)
	return d, err
}

func (db *DB) GetCustomDomain(ctx context.Context, id, userID string) (*models.CustomDomain, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, domain, status, verification_token,
		       target_subdomain, created_at, verified_at, last_checked_at
		FROM custom_domains WHERE id = $1 AND user_id = $2`, id, userID)
	d := &models.CustomDomain{}
	err := row.Scan(
		&d.ID, &d.UserID, &d.Domain, &d.Status, &d.VerificationToken,
		&d.TargetSubdomain, &d.CreatedAt, &d.VerifiedAt, &d.LastCheckedAt,
	)
	return d, err
}

func (db *DB) DeleteCustomDomain(ctx context.Context, id, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM custom_domains WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}

func (db *DB) SetCustomDomainVerified(ctx context.Context, id string) error {
	now := time.Now()
	_, err := db.Pool.Exec(ctx,
		`UPDATE custom_domains SET status='verified', verified_at=$1, last_checked_at=$1 WHERE id=$2`,
		now, id)
	return err
}

func (db *DB) SetCustomDomainFailed(ctx context.Context, id string) error {
	now := time.Now()
	_, err := db.Pool.Exec(ctx,
		`UPDATE custom_domains SET status='failed', last_checked_at=$1 WHERE id=$2`, now, id)
	return err
}

func (db *DB) SetCustomDomainTarget(ctx context.Context, id, userID, targetSubdomain string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE custom_domains SET target_subdomain=$1 WHERE id=$2 AND user_id=$3`,
		targetSubdomain, id, userID)
	return err
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
		d := &models.CustomDomain{}
		if err := rows.Scan(
			&d.ID, &d.UserID, &d.Domain, &d.Status, &d.VerificationToken,
			&d.TargetSubdomain, &d.CreatedAt, &d.VerifiedAt, &d.LastCheckedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
