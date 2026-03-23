package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

const partnerCols = `id, name, slogan, description, logo_url, website_url, badge,
	facebook_url, twitter_url, instagram_url, linkedin_url, github_url, youtube_url,
	is_active, is_public, sort_order, created_at, updated_at`

func scanPartner(row interface{ Scan(...any) error }) (*models.Partner, error) {
	p := &models.Partner{}
	return p, row.Scan(
		&p.ID, &p.Name, &p.Slogan, &p.Description, &p.LogoURL, &p.WebsiteURL, &p.Badge,
		&p.FacebookURL, &p.TwitterURL, &p.InstagramURL, &p.LinkedinURL, &p.GithubURL, &p.YoutubeURL,
		&p.IsActive, &p.IsPublic, &p.SortOrder, &p.CreatedAt, &p.UpdatedAt,
	)
}

// ListPublicPartners returns all active+public partners ordered by sort_order.
func (db *DB) ListPublicPartners(ctx context.Context) ([]*models.Partner, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT `+partnerCols+` FROM partners WHERE is_active AND is_public ORDER BY sort_order, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Partner
	for rows.Next() {
		p, err := scanPartner(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// ListAllPartners returns all partners (admin view).
func (db *DB) ListAllPartners(ctx context.Context) ([]*models.Partner, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT `+partnerCols+` FROM partners ORDER BY sort_order, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Partner
	for rows.Next() {
		p, err := scanPartner(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// CreatePartner inserts a new partner row.
func (db *DB) CreatePartner(ctx context.Context, p *models.Partner) (*models.Partner, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO partners (name, slogan, description, logo_url, website_url, badge,
			facebook_url, twitter_url, instagram_url, linkedin_url, github_url, youtube_url,
			is_active, is_public, sort_order)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		RETURNING `+partnerCols,
		p.Name, p.Slogan, p.Description, p.LogoURL, p.WebsiteURL, p.Badge,
		p.FacebookURL, p.TwitterURL, p.InstagramURL, p.LinkedinURL, p.GithubURL, p.YoutubeURL,
		p.IsActive, p.IsPublic, p.SortOrder,
	)
	return scanPartner(row)
}

// UpdatePartner applies a map of fields to a partner row.
func (db *DB) UpdatePartner(ctx context.Context, id string, fields map[string]any) (*models.Partner, error) {
	allowed := map[string]bool{
		"name": true, "slogan": true, "description": true, "logo_url": true, "website_url": true,
		"badge": true, "facebook_url": true, "twitter_url": true, "instagram_url": true,
		"linkedin_url": true, "github_url": true, "youtube_url": true,
		"is_active": true, "is_public": true, "sort_order": true,
	}
	fields["updated_at"] = time.Now()

	var setClauses []string
	var args []any
	i := 1
	for k, v := range fields {
		if !allowed[k] && k != "updated_at" {
			continue
		}
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", k, i))
		args = append(args, v)
		i++
	}
	if len(setClauses) == 0 {
		return nil, fmt.Errorf("no valid fields to update")
	}
	args = append(args, id)
	row := db.Pool.QueryRow(ctx,
		`UPDATE partners SET `+strings.Join(setClauses, ", ")+
			` WHERE id = $`+fmt.Sprintf("%d", i)+
			` RETURNING `+partnerCols,
		args...,
	)
	return scanPartner(row)
}

// DeletePartner hard-deletes a partner by ID.
func (db *DB) DeletePartner(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM partners WHERE id = $1`, id)
	return err
}
