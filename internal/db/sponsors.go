package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

const sponsorCols = `id, type, title, description, url, button_text, icon, badge,
	bank_name, account_name, account_number, currency, note,
	is_active, sort_order, created_at, updated_at`

func scanSponsor(row interface{ Scan(...any) error }) (*models.Sponsor, error) {
	s := &models.Sponsor{}
	return s, row.Scan(
		&s.ID, &s.Type, &s.Title, &s.Description, &s.URL, &s.ButtonText, &s.Icon, &s.Badge,
		&s.BankName, &s.AccountName, &s.AccountNumber, &s.Currency, &s.Note,
		&s.IsActive, &s.SortOrder, &s.CreatedAt, &s.UpdatedAt,
	)
}

// ListPublicSponsors returns all active sponsors ordered by sort_order.
func (db *DB) ListPublicSponsors(ctx context.Context) ([]*models.Sponsor, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT `+sponsorCols+` FROM sponsors WHERE is_active ORDER BY sort_order, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Sponsor
	for rows.Next() {
		s, err := scanSponsor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// ListAllSponsors returns all sponsors (admin view).
func (db *DB) ListAllSponsors(ctx context.Context) ([]*models.Sponsor, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT `+sponsorCols+` FROM sponsors ORDER BY sort_order, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Sponsor
	for rows.Next() {
		s, err := scanSponsor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// CreateSponsor inserts a new sponsor row.
func (db *DB) CreateSponsor(ctx context.Context, s *models.Sponsor) (*models.Sponsor, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO sponsors (type, title, description, url, button_text, icon, badge,
			bank_name, account_name, account_number, currency, note, is_active, sort_order)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		RETURNING `+sponsorCols,
		s.Type, s.Title, s.Description, s.URL, s.ButtonText, s.Icon, s.Badge,
		s.BankName, s.AccountName, s.AccountNumber, s.Currency, s.Note, s.IsActive, s.SortOrder,
	)
	return scanSponsor(row)
}

// UpdateSponsor applies a map of fields to a sponsor row.
func (db *DB) UpdateSponsor(ctx context.Context, id string, fields map[string]any) (*models.Sponsor, error) {
	allowed := map[string]bool{
		"type": true, "title": true, "description": true, "url": true, "button_text": true,
		"icon": true, "badge": true, "bank_name": true, "account_name": true,
		"account_number": true, "currency": true, "note": true,
		"is_active": true, "sort_order": true,
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
		`UPDATE sponsors SET `+strings.Join(setClauses, ", ")+
			` WHERE id = $`+fmt.Sprintf("%d", i)+
			` RETURNING `+sponsorCols,
		args...,
	)
	return scanSponsor(row)
}

// DeleteSponsor hard-deletes a sponsor by ID.
func (db *DB) DeleteSponsor(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM sponsors WHERE id = $1`, id)
	return err
}
