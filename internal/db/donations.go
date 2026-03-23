package db

import (
	"context"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

func (d *DB) CreateDonation(ctx context.Context, sub *models.DonationSubmission) (*models.DonationSubmission, error) {
	row := d.Pool.QueryRow(ctx, `
		INSERT INTO donation_submissions (name, email, amount, currency, payment_method, receipt_url, social_url, message)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id, name, email, amount, currency, payment_method, receipt_url, social_url, message, status, show_on_home, created_at, updated_at`,
		sub.Name, sub.Email, sub.Amount, sub.Currency, sub.PaymentMethod, sub.ReceiptURL, sub.SocialURL, sub.Message,
	)
	return scanDonation(row)
}

func (d *DB) ListDonationsAdmin(ctx context.Context, status string) ([]*models.DonationSubmission, error) {
	q := `SELECT id, name, email, amount, currency, payment_method, receipt_url, social_url, message, status, show_on_home, created_at, updated_at FROM donation_submissions`
	args := []any{}
	if status != "" {
		q += " WHERE status = $1"
		args = append(args, status)
	}
	q += " ORDER BY created_at DESC"
	rows, err := d.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.DonationSubmission
	for rows.Next() {
		s, err := scanDonationRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (d *DB) UpdateDonation(ctx context.Context, id string, status string, showOnHome bool) (*models.DonationSubmission, error) {
	row := d.Pool.QueryRow(ctx, `
		UPDATE donation_submissions SET status=$1, show_on_home=$2, updated_at=NOW()
		WHERE id=$3
		RETURNING id, name, email, amount, currency, payment_method, receipt_url, social_url, message, status, show_on_home, created_at, updated_at`,
		status, showOnHome, id,
	)
	return scanDonation(row)
}

func (d *DB) ListPublicDonations(ctx context.Context, limit, offset int) ([]*models.DonationSubmission, error) {
	if limit <= 0 {
		limit = 12
	}
	rows, err := d.Pool.Query(ctx, `
		SELECT id, name, email, amount, currency, payment_method, receipt_url, social_url, message, status, show_on_home, created_at, updated_at
		FROM donation_submissions WHERE status='approved' AND show_on_home=true ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.DonationSubmission
	for rows.Next() {
		s, err := scanDonationRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func (d *DB) CountPublicDonations(ctx context.Context) (int, error) {
	var n int
	err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM donation_submissions WHERE status='approved' AND show_on_home=true`).Scan(&n)
	return n, err
}

func (d *DB) DeleteDonation(ctx context.Context, id string) error {
	_, err := d.Pool.Exec(ctx, `DELETE FROM donation_submissions WHERE id=$1`, id)
	return err
}

type donationScanner interface {
	Scan(dest ...any) error
}

func scanDonation(row donationScanner) (*models.DonationSubmission, error) {
	s := &models.DonationSubmission{}
	err := row.Scan(&s.ID, &s.Name, &s.Email, &s.Amount, &s.Currency, &s.PaymentMethod,
		&s.ReceiptURL, &s.SocialURL, &s.Message, &s.Status, &s.ShowOnHome, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func scanDonationRow(rows interface{ Scan(...any) error }) (*models.DonationSubmission, error) {
	return scanDonation(rows)
}
