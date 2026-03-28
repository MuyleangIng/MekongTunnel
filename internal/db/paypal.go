package db

import (
	"context"
	"time"
)

// ─── Payment receipts (PayPal manual / ABA / Bakong) ─────────

type PaymentReceipt struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	Plan           string     `json:"plan"`
	AmountUSD      float64    `json:"amount_usd"`
	DiscountPct    int        `json:"discount_pct"`
	Method         string     `json:"method"`
	ReceiptURL     string     `json:"receipt_url"`
	Note           *string    `json:"note,omitempty"`
	Status         string     `json:"status"`
	AdminNote      *string    `json:"admin_note,omitempty"`
	ReviewedBy     *string    `json:"reviewed_by,omitempty"`
	ReviewedAt     *time.Time `json:"reviewed_at,omitempty"`
	AllowResubmit  bool       `json:"allow_resubmit"`
	RefundBank     *string    `json:"refund_bank,omitempty"`
	RefundAmount   *float64   `json:"refund_amount,omitempty"`
	RefundNote     *string    `json:"refund_note,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

func (db *DB) CreatePaymentReceipt(ctx context.Context, userID, plan, method, receiptURL string, amountUSD float64, discountPct int, note string) (*PaymentReceipt, error) {
	r := &PaymentReceipt{}
	var notePtr *string
	if note != "" {
		notePtr = &note
	}
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO payment_receipts (user_id, plan, amount_usd, discount_pct, method, receipt_url, note)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, user_id, plan, amount_usd, discount_pct, method, receipt_url, note,
		          status, admin_note, reviewed_by, reviewed_at,
		          allow_resubmit, refund_bank, refund_amount, refund_note,
		          created_at, updated_at`,
		userID, plan, amountUSD, discountPct, method, receiptURL, notePtr).Scan(
		&r.ID, &r.UserID, &r.Plan, &r.AmountUSD, &r.DiscountPct, &r.Method, &r.ReceiptURL, &r.Note,
		&r.Status, &r.AdminNote, &r.ReviewedBy, &r.ReviewedAt,
		&r.AllowResubmit, &r.RefundBank, &r.RefundAmount, &r.RefundNote,
		&r.CreatedAt, &r.UpdatedAt)
	return r, err
}

func (db *DB) ListPendingReceipts(ctx context.Context) ([]*PaymentReceipt, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, plan, amount_usd, discount_pct, method, receipt_url, note,
		       status, admin_note, reviewed_by, reviewed_at,
		       allow_resubmit, refund_bank, refund_amount, refund_note,
		       created_at, updated_at
		FROM payment_receipts
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PaymentReceipt
	for rows.Next() {
		r := &PaymentReceipt{}
		if err := rows.Scan(
			&r.ID, &r.UserID, &r.Plan, &r.AmountUSD, &r.DiscountPct, &r.Method, &r.ReceiptURL, &r.Note,
			&r.Status, &r.AdminNote, &r.ReviewedBy, &r.ReviewedAt,
			&r.AllowResubmit, &r.RefundBank, &r.RefundAmount, &r.RefundNote,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) ReviewPaymentReceipt(ctx context.Context, receiptID, adminID, status, adminNote, refundBank, refundNote string, refundAmount float64, allowResubmit bool) error {
	var refundBankPtr, refundNotePtr *string
	var refundAmountPtr *float64
	if refundBank != "" {
		refundBankPtr = &refundBank
	}
	if refundNote != "" {
		refundNotePtr = &refundNote
	}
	if refundAmount > 0 {
		refundAmountPtr = &refundAmount
	}
	_, err := db.Pool.Exec(ctx, `
		UPDATE payment_receipts
		SET status = $2, admin_note = $3, reviewed_by = $4, reviewed_at = NOW(), updated_at = NOW(),
		    allow_resubmit = $5, refund_bank = $6, refund_amount = $7, refund_note = $8
		WHERE id = $1`,
		receiptID, status, adminNote, adminID, allowResubmit, refundBankPtr, refundAmountPtr, refundNotePtr)
	return err
}

func (db *DB) GetPaymentReceipt(ctx context.Context, receiptID string) (*PaymentReceipt, error) {
	r := &PaymentReceipt{}
	err := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, plan, amount_usd, discount_pct, method, receipt_url, note,
		       status, admin_note, reviewed_by, reviewed_at,
		       allow_resubmit, refund_bank, refund_amount, refund_note,
		       created_at, updated_at
		FROM payment_receipts WHERE id = $1`, receiptID).Scan(
		&r.ID, &r.UserID, &r.Plan, &r.AmountUSD, &r.DiscountPct, &r.Method, &r.ReceiptURL, &r.Note,
		&r.Status, &r.AdminNote, &r.ReviewedBy, &r.ReviewedAt,
		&r.AllowResubmit, &r.RefundBank, &r.RefundAmount, &r.RefundNote,
		&r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (db *DB) ListUserReceipts(ctx context.Context, userID string) ([]*PaymentReceipt, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, plan, amount_usd, discount_pct, method, receipt_url, note,
		       status, admin_note, reviewed_by, reviewed_at,
		       allow_resubmit, refund_bank, refund_amount, refund_note,
		       created_at, updated_at
		FROM payment_receipts
		WHERE user_id = $1
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PaymentReceipt
	for rows.Next() {
		r := &PaymentReceipt{}
		if err := rows.Scan(
			&r.ID, &r.UserID, &r.Plan, &r.AmountUSD, &r.DiscountPct, &r.Method, &r.ReceiptURL, &r.Note,
			&r.Status, &r.AdminNote, &r.ReviewedBy, &r.ReviewedAt,
			&r.AllowResubmit, &r.RefundBank, &r.RefundAmount, &r.RefundNote,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeletePaymentReceipt deletes a receipt by ID.
func (db *DB) DeletePaymentReceipt(ctx context.Context, receiptID string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM payment_receipts WHERE id = $1`, receiptID)
	return err
}

// GetPendingReceiptCount returns the number of receipts with status 'pending'.
func (db *DB) GetPendingReceiptCount(ctx context.Context) (int, error) {
	var n int
	err := db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM payment_receipts WHERE status = 'pending'`).Scan(&n)
	return n, err
}

// GetUserPendingReceiptCount returns pending+needs_resubmit count for a user.
func (db *DB) GetUserPendingReceiptCount(ctx context.Context, userID string) (int, error) {
	var n int
	err := db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM payment_receipts
		WHERE user_id = $1 AND status IN ('pending','needs_resubmit')`, userID).Scan(&n)
	return n, err
}

// HasActivePendingReceipt returns true if the user already has a pending or
// needs_resubmit receipt for the given plan, preventing duplicate submissions.
func (db *DB) HasActivePendingReceipt(ctx context.Context, userID, plan string) (bool, error) {
	var n int
	err := db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM payment_receipts
		WHERE user_id = $1 AND plan = $2 AND status IN ('pending','needs_resubmit')`,
		userID, plan).Scan(&n)
	return n > 0, err
}
