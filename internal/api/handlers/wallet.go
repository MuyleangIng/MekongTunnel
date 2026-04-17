// wallet.go — credit wallet: balance, top-up via Bakong QR checkout, history.
// $1 USD = 1 credit. Credits are used to pay for deploy storage subscriptions.
//
// Payment flow (Bakong via Koma):
//  1. POST /api/wallet/topup/bakong → create KHQR session + local order
//  2. Frontend shows the returned QR and polls GET /api/wallet/order/{ref}
//  3. When Koma confirms payment, credits are applied automatically
//
// Legacy screenshot/admin review endpoints remain for old manual orders only.
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
	"github.com/jackc/pgx/v5"
)

const (
	creditPriceUSD = 1.0
	orderTTL       = 10 * time.Minute
)

// StoragePackage defines a purchasable storage add-on.
type StoragePackage struct {
	ID              string  `json:"id"`
	ExtraMB         int     `json:"extra_mb"`
	Credits         int     `json:"credits"`
	CreditsPerMonth int     `json:"credits_per_month"`
	Label           string  `json:"label"`
	PriceUSD        float64 `json:"price_usd"`
}

var storagePackages = []StoragePackage{
	{ID: "200mb", ExtraMB: 200, Credits: 2, CreditsPerMonth: 2, Label: "200MB", PriceUSD: 2.0},
	{ID: "500mb", ExtraMB: 500, Credits: 5, CreditsPerMonth: 5, Label: "500MB", PriceUSD: 5.0},
	{ID: "1gb", ExtraMB: 1024, Credits: 10, CreditsPerMonth: 10, Label: "1GB", PriceUSD: 10.0},
}

// WalletHandler handles /api/wallet/* endpoints.
type WalletHandler struct {
	DB                *db.DB
	BakongAccountName string
	BakongAccountID   string
	KomaAPIURL        string
	KomaMerchantID    string
	KomaSecretKey     string
	HTTPClient        *http.Client
	UploadDir         string
	FrontendURL       string
	Mailer            *mailer.Mailer
}

// GetBalance handles GET /api/wallet — returns balance + history + packages.
func (h *WalletHandler) GetBalance(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	balance, err := h.getBalance(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	txs, err := h.getTransactions(r.Context(), claims.UserID, 20)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"balance":      balance,
		"transactions": txs,
		"packages":     storagePackages,
	})
}

// TopupBakong handles POST /api/wallet/topup/bakong.
// It creates a Koma checkout session and returns the QR needed for Bakong payment.
func (h *WalletHandler) TopupBakong(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Credits int    `json:"credits"`
		Ref     string `json:"ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Credits < 1 {
		response.BadRequest(w, "credits must be >= 1")
		return
	}

	ref := strings.TrimSpace(body.Ref)
	if ref == "" {
		ref = fmt.Sprintf("MT-WALLET-%d-%s", time.Now().UnixMilli(), claims.UserID[:8])
	}
	amount := float64(body.Credits) * creditPriceUSD
	expiresAt := time.Now().Add(orderTTL)

	checkout, err := h.createKomaCheckout(r.Context(), ref, amount)
	if err != nil {
		log.Printf("[wallet] failed to create Koma checkout: %v", err)
		response.Error(w, http.StatusBadGateway, "unable to create Bakong checkout")
		return
	}

	if err := h.createOrder(
		r.Context(),
		claims.UserID,
		amount,
		body.Credits,
		checkout.TransactionID,
		expiresAt,
		"koma_qr",
		"wallet_topup",
		"",
		0,
		checkout.QRDataURL,
		checkout.MD5,
		checkout.PollToken,
	); err != nil {
		log.Printf("[wallet] failed to record Bakong order: %v", err)
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"ref":              checkout.TransactionID,
		"transaction_id":   checkout.TransactionID,
		"amount_usd":       amount,
		"credits":          body.Credits,
		"status":           "pending",
		"phase":            "ready",
		"qr_data_url":      checkout.QRDataURL,
		"md5":              checkout.MD5,
		"poll_token":       checkout.PollToken,
		"expires_at":       expiresAt,
		"poll_interval_ms": walletPollIntervalMS,
		"next_step":        "Scan the Bakong QR and keep this page open while payment confirmation is polled automatically",
	})
}

// ConfirmTopup handles POST /api/wallet/topup/confirm.
// The frontend calls this only after the Bakong SDK reports a successful payment.
func (h *WalletHandler) ConfirmTopup(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Credits int    `json:"credits"`
		Ref     string `json:"ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	if body.Credits < 1 {
		response.BadRequest(w, "credits must be >= 1")
		return
	}

	ref := strings.TrimSpace(body.Ref)
	if ref == "" {
		response.BadRequest(w, "ref is required")
		return
	}

	balance, alreadyRecorded, err := h.recordSDKTopup(r.Context(), claims.UserID, body.Credits, ref)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"ref":               ref,
		"credits":           body.Credits,
		"balance":           balance,
		"status":            "paid",
		"payment_confirmed": true,
		"already_recorded":  alreadyRecorded,
	})
}

// UploadScreenshot handles POST /api/wallet/topup/screenshot
// User uploads payment proof image for admin review.
func (h *WalletHandler) UploadScreenshot(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	if err := r.ParseMultipartForm(5 << 20); err != nil {
		response.BadRequest(w, "screenshot too large — max 5MB")
		return
	}

	ref := r.FormValue("ref")
	if ref == "" {
		response.BadRequest(w, "ref is required")
		return
	}

	var orderID string
	err := h.DB.Pool.QueryRow(r.Context(),
		`SELECT id FROM payment_orders WHERE gateway_ref=$1 AND user_id=$2 AND order_purpose='wallet_topup' AND status='pending' AND payment_mode='manual'`,
		ref, claims.UserID,
	).Scan(&orderID)
	if err != nil {
		response.NotFound(w, "order not found or already processed")
		return
	}

	file, header, err := r.FormFile("screenshot")
	if err != nil {
		response.BadRequest(w, "screenshot file required")
		return
	}
	defer file.Close()

	ext := ".jpg"
	if e := filepath.Ext(header.Filename); e != "" {
		ext = e
	}
	savePath := filepath.Join(h.UploadDir, "payment_screenshots", orderID+ext)
	if err := os.MkdirAll(filepath.Dir(savePath), 0755); err != nil {
		response.InternalError(w, err)
		return
	}
	out, err := os.Create(savePath)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		response.InternalError(w, err)
		return
	}

	if _, err := h.DB.Pool.Exec(r.Context(),
		`UPDATE payment_orders SET qr_code=$1 WHERE id=$2`,
		savePath, orderID,
	); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"message": "Screenshot submitted — admin will review and approve within 24 hours",
		"ref":     ref,
	})
}

// PollOrder handles GET /api/wallet/order/{ref} — poll payment status.
func (h *WalletHandler) PollOrder(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	ref := r.PathValue("ref")
	if ref == "" {
		response.BadRequest(w, "ref required")
		return
	}

	type orderState struct {
		Status            string
		Mode              string
		Credits           int
		AmountUSD         float64
		ProviderQRCode    *string
		ProviderMD5       *string
		ProviderPollToken *string
		ExpiresAt         time.Time
		PaidAt            *time.Time
	}

	var order orderState
	err := h.DB.Pool.QueryRow(r.Context(),
		`SELECT status, payment_mode, credits, amount_usd, provider_qr_code, provider_md5, provider_poll_token, expires_at, paid_at
		 FROM payment_orders
		 WHERE gateway_ref=$1 AND user_id=$2 AND order_purpose='wallet_topup'`,
		ref, claims.UserID,
	).Scan(
		&order.Status,
		&order.Mode,
		&order.Credits,
		&order.AmountUSD,
		&order.ProviderQRCode,
		&order.ProviderMD5,
		&order.ProviderPollToken,
		&order.ExpiresAt,
		&order.PaidAt,
	)
	if err != nil {
		response.NotFound(w, "order not found")
		return
	}

	phase := order.Status
	var bakong *komaStatusEnvelope

	if order.Mode == "koma_qr" && order.Status == "pending" {
		if order.ProviderMD5 == nil || order.ProviderPollToken == nil {
			log.Printf("[wallet] order %s missing Koma poll fields", ref)
			response.Error(w, http.StatusBadGateway, "payment order is missing Bakong polling data")
			return
		}

		bakong, err = h.checkKomaStatus(r.Context(), *order.ProviderMD5, *order.ProviderPollToken)
		if err != nil {
			log.Printf("[wallet] failed to poll Koma status for %s: %v", ref, err)
			response.Error(w, http.StatusBadGateway, "unable to check Bakong payment status")
			return
		}

		phase = deriveKomaPhase(order.Status, bakong)

		switch phase {
		case "paid":
			if err := h.applyTopup(r.Context(), claims.UserID, order.Credits, ref); err != nil {
				response.InternalError(w, err)
				return
			}
			order.Status = "paid"
			phase = "paid"
		case "failed":
			if err := h.updateOrderStatus(r.Context(), ref, "wallet_topup", "failed"); err != nil {
				response.InternalError(w, err)
				return
			}
			order.Status = "failed"
		case "expired":
			if err := h.updateOrderStatus(r.Context(), ref, "wallet_topup", "expired"); err != nil {
				response.InternalError(w, err)
				return
			}
			order.Status = "expired"
		default:
			if time.Now().After(order.ExpiresAt) {
				if err := h.updateOrderStatus(r.Context(), ref, "wallet_topup", "expired"); err != nil {
					response.InternalError(w, err)
					return
				}
				order.Status = "expired"
				phase = "expired"
			}
		}
	}

	response.Success(w, map[string]any{
		"ref":               ref,
		"status":            order.Status,
		"phase":             phase,
		"credits":           order.Credits,
		"amount_usd":        order.AmountUSD,
		"qr_data_url":       order.ProviderQRCode,
		"expires_at":        order.ExpiresAt,
		"paid_at":           order.PaidAt,
		"poll_interval_ms":  walletPollIntervalMS,
		"payment_confirmed": order.Status == "paid",
		"bakong":            bakong,
	})
}

// ListPendingScreenshots handles GET /api/wallet/admin/pending
// Admin sees all Bakong orders awaiting screenshot review.
func (h *WalletHandler) ListPendingScreenshots(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil || !claims.IsAdmin {
		response.Forbidden(w, "admin only")
		return
	}

	rows, err := h.DB.Pool.Query(r.Context(), `
		SELECT o.id, o.user_id, u.email, o.amount_usd, o.credits,
		       o.gateway_ref, o.qr_code, o.created_at
		FROM payment_orders o
		JOIN users u ON u.id = o.user_id
		WHERE o.status = 'pending' AND o.payment_mode = 'manual' AND o.order_purpose = 'wallet_topup'
		ORDER BY o.created_at ASC
	`)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var id, userID, email, ref string
		var screenshotPath *string
		var amountUSD float64
		var credits int
		var createdAt time.Time
		if err := rows.Scan(&id, &userID, &email, &amountUSD, &credits, &ref, &screenshotPath, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id":              id,
			"user_id":         userID,
			"email":           email,
			"amount_usd":      amountUSD,
			"credits":         credits,
			"ref":             ref,
			"screenshot_path": screenshotPath,
			"created_at":      createdAt,
		})
	}

	response.Success(w, map[string]any{"orders": out})
}

// ApproveScreenshot handles POST /api/wallet/admin/approve/{order_id}
// Admin approves payment → credits added to user wallet.
func (h *WalletHandler) ApproveScreenshot(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil || !claims.IsAdmin {
		response.Forbidden(w, "admin only")
		return
	}

	orderID := r.PathValue("order_id")
	if orderID == "" {
		response.BadRequest(w, "order_id required")
		return
	}

	var userID, ref string
	var credits int
	err := h.DB.Pool.QueryRow(r.Context(),
		`SELECT user_id, credits, gateway_ref FROM payment_orders WHERE id=$1 AND order_purpose='wallet_topup' AND status='pending' AND payment_mode='manual'`,
		orderID,
	).Scan(&userID, &credits, &ref)
	if err != nil {
		response.NotFound(w, "order not found or already processed")
		return
	}

	if err := h.applyTopup(r.Context(), userID, credits, ref); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"approved": true,
		"user_id":  userID,
		"credits":  credits,
	})
}

// ── Core wallet operations ────────────────────────────────────────────────────

func (h *WalletHandler) applyTopup(ctx context.Context, userID string, credits int, ref string) error {
	tx, err := h.DB.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var orderStatus string
	if err := tx.QueryRow(ctx,
		`SELECT status FROM payment_orders WHERE gateway_ref=$1 AND order_purpose='wallet_topup' FOR UPDATE`,
		ref,
	).Scan(&orderStatus); err != nil {
		return err
	}
	if orderStatus == "paid" {
		return tx.Commit(ctx)
	}
	if orderStatus != "pending" {
		return fmt.Errorf("payment order %s is %s", ref, orderStatus)
	}

	var balance int
	if err := tx.QueryRow(ctx,
		`UPDATE users SET credit_balance = credit_balance + $1 WHERE id=$2 RETURNING credit_balance`,
		credits, userID,
	).Scan(&balance); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO credit_transactions (user_id, amount, balance_after, description, gateway, gateway_ref)
		 VALUES ($1, $2, $3, $4, 'bakong', $5)`,
		userID, credits, balance,
		fmt.Sprintf("Top-up %d credits via Bakong", credits),
		ref,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE payment_orders SET status='paid', paid_at=now() WHERE gateway_ref=$1 AND order_purpose='wallet_topup'`,
		ref,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (h *WalletHandler) recordSDKTopup(ctx context.Context, userID string, credits int, ref string) (int, bool, error) {
	tx, err := h.DB.Pool.Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback(ctx)

	var existingStatus string
	err = tx.QueryRow(ctx,
		`SELECT status FROM payment_orders WHERE gateway_ref=$1 AND user_id=$2 AND order_purpose='wallet_topup' FOR UPDATE`,
		ref, userID,
	).Scan(&existingStatus)
	if err == nil {
		var balance int
		if scanErr := tx.QueryRow(ctx, `SELECT credit_balance FROM users WHERE id=$1`, userID).Scan(&balance); scanErr != nil {
			return 0, false, scanErr
		}
		if existingStatus == "paid" {
			if err := tx.Commit(ctx); err != nil {
				return 0, false, err
			}
			return balance, true, nil
		}
		return 0, false, fmt.Errorf("payment order %s is %s", ref, existingStatus)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, false, err
	}

	var balance int
	if err := tx.QueryRow(ctx,
		`UPDATE users SET credit_balance = credit_balance + $1 WHERE id=$2 RETURNING credit_balance`,
		credits, userID,
	).Scan(&balance); err != nil {
		return 0, false, err
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO credit_transactions (user_id, amount, balance_after, description, gateway, gateway_ref)
		 VALUES ($1, $2, $3, $4, 'bakong', $5)`,
		userID, credits, balance,
		fmt.Sprintf("Top-up %d credits via Bakong", credits),
		ref,
	); err != nil {
		return 0, false, err
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO payment_orders (
			user_id, gateway, amount_usd, credits, status, gateway_ref, expires_at, paid_at,
			payment_mode, order_purpose, discount_pct
		)
		 VALUES ($1, 'bakong', $2, $3, 'paid', $4, now(), now(), 'koma_qr', 'wallet_topup', 0)`,
		userID, float64(credits)*creditPriceUSD, credits, ref,
	); err != nil {
		return 0, false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, false, err
	}

	return balance, false, nil
}

func (h *WalletHandler) getBalance(ctx context.Context, userID string) (int, error) {
	var balance int
	err := h.DB.Pool.QueryRow(ctx,
		`SELECT credit_balance FROM users WHERE id=$1`, userID,
	).Scan(&balance)
	return balance, err
}

func (h *WalletHandler) getTransactions(ctx context.Context, userID string, limit int) ([]map[string]any, error) {
	rows, err := h.DB.Pool.Query(ctx,
		`SELECT id, amount, balance_after, description, gateway, created_at
		 FROM credit_transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`,
		userID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var id, desc string
		var gateway *string
		var amount, balAfter int
		var createdAt time.Time
		if err := rows.Scan(&id, &amount, &balAfter, &desc, &gateway, &createdAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"id":            id,
			"amount":        amount,
			"balance_after": balAfter,
			"description":   desc,
			"gateway":       gateway,
			"created_at":    createdAt,
		})
	}
	return out, rows.Err()
}

func (h *WalletHandler) createOrder(
	ctx context.Context,
	userID string,
	amountUSD float64,
	credits int,
	ref string,
	expiresAt time.Time,
	mode string,
	purpose string,
	planID string,
	discountPct int,
	providerQRCode string,
	providerMD5 string,
	providerPollToken string,
) error {
	_, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO payment_orders (
			user_id, gateway, amount_usd, credits, gateway_ref, expires_at,
			payment_mode, order_purpose, plan_id, discount_pct, provider_qr_code, provider_md5, provider_poll_token
		)
		 VALUES ($1, 'bakong', $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, $10, $11, $12)`,
		userID, amountUSD, credits, ref, expiresAt, mode, purpose, planID, discountPct, providerQRCode, providerMD5, providerPollToken,
	)
	return err
}

func (h *WalletHandler) updateOrderStatus(ctx context.Context, ref string, purpose string, status string) error {
	_, err := h.DB.Pool.Exec(ctx,
		`UPDATE payment_orders SET status=$3 WHERE gateway_ref=$1 AND order_purpose=$2 AND status='pending'`,
		ref, purpose, status,
	)
	return err
}
