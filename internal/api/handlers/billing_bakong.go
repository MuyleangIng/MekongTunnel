package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/jackc/pgx/v5"
)

const billingOrderTTL = 10 * time.Minute

func (h *BillingHandler) CreateBakongCheckout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Plan string `json:"plan"`
		Ref  string `json:"ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	plan := normalizeBillingPlan(body.Plan)
	if plan == "" {
		response.BadRequest(w, "plan is required")
		return
	}

	amountUSD, discountPct, err := h.bakongPriceForUser(r.Context(), claims.UserID, plan)
	if err != nil {
		response.BadRequest(w, err.Error())
		return
	}
	if amountUSD <= 0 {
		response.BadRequest(w, "Bakong checkout requires a positive amount")
		return
	}

	ref := strings.TrimSpace(body.Ref)
	if ref == "" {
		ref = fmt.Sprintf("MT-BILL-%d-%s", time.Now().UnixMilli(), claims.UserID[:8])
	}
	expiresAt := time.Now().Add(billingOrderTTL)

	checkout, err := h.createKomaCheckout(r.Context(), ref, amountUSD)
	if err != nil {
		log.Printf("[billing] failed to create Koma checkout: %v", err)
		response.Error(w, http.StatusBadGateway, "unable to create Bakong checkout")
		return
	}

	if err := h.createBakongOrder(
		r.Context(),
		claims.UserID,
		plan,
		amountUSD,
		discountPct,
		checkout.TransactionID,
		expiresAt,
		"koma_qr",
		checkout.QRDataURL,
		checkout.MD5,
		checkout.PollToken,
	); err != nil {
		log.Printf("[billing] failed to record Bakong order: %v", err)
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"ref":              checkout.TransactionID,
		"transaction_id":   checkout.TransactionID,
		"plan":             plan,
		"amount_usd":       amountUSD,
		"discount_pct":     discountPct,
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

// ConfirmBakongPayment handles POST /api/billing/bakong/confirm.
// The frontend calls this after the Bakong SDK reports payment success.
func (h *BillingHandler) ConfirmBakongPayment(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Plan string `json:"plan"`
		Ref  string `json:"ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	plan := normalizeBillingPlan(body.Plan)
	if plan == "" {
		response.BadRequest(w, "plan is required")
		return
	}

	ref := strings.TrimSpace(body.Ref)
	if ref == "" {
		response.BadRequest(w, "ref is required")
		return
	}

	amountUSD, discountPct, err := h.bakongPriceForUser(r.Context(), claims.UserID, plan)
	if err != nil {
		response.BadRequest(w, err.Error())
		return
	}

	alreadyRecorded, err := h.recordSDKBillingPayment(r.Context(), claims.UserID, plan, amountUSD, discountPct, ref)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{
		"ref":               ref,
		"plan":              plan,
		"amount_usd":        amountUSD,
		"discount_pct":      discountPct,
		"status":            "paid",
		"payment_confirmed": true,
		"already_recorded":  alreadyRecorded,
	})
}

func (h *BillingHandler) PollBakongOrder(w http.ResponseWriter, r *http.Request) {
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
		PlanID            string
		AmountUSD         float64
		DiscountPct       int
		Mode              string
		ProviderQRCode    *string
		ProviderMD5       *string
		ProviderPollToken *string
		ExpiresAt         time.Time
		PaidAt            *time.Time
	}

	var order orderState
	err := h.DB.Pool.QueryRow(r.Context(),
		`SELECT status, plan_id, amount_usd, discount_pct, payment_mode, provider_qr_code, provider_md5, provider_poll_token, expires_at, paid_at
		 FROM payment_orders
		 WHERE gateway_ref=$1 AND user_id=$2 AND order_purpose='billing_plan'`,
		ref, claims.UserID,
	).Scan(
		&order.Status,
		&order.PlanID,
		&order.AmountUSD,
		&order.DiscountPct,
		&order.Mode,
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
			log.Printf("[billing] order %s missing Koma poll fields", ref)
			response.Error(w, http.StatusBadGateway, "payment order is missing Bakong polling data")
			return
		}

		bakong, err = h.checkKomaStatus(r.Context(), *order.ProviderMD5, *order.ProviderPollToken)
		if err != nil {
			log.Printf("[billing] failed to poll Koma status for %s: %v", ref, err)
			response.Error(w, http.StatusBadGateway, "unable to check Bakong payment status")
			return
		}

		phase = deriveKomaPhase(order.Status, bakong)

		switch phase {
		case "paid":
			if err := h.applyBakongPlan(r.Context(), claims.UserID, order.PlanID, ref); err != nil {
				response.InternalError(w, err)
				return
			}
			order.Status = "paid"
			phase = "paid"
		case "failed":
			if err := h.updateBakongOrderStatus(r.Context(), ref, "failed"); err != nil {
				response.InternalError(w, err)
				return
			}
			order.Status = "failed"
		case "expired":
			if err := h.updateBakongOrderStatus(r.Context(), ref, "expired"); err != nil {
				response.InternalError(w, err)
				return
			}
			order.Status = "expired"
		default:
			if time.Now().After(order.ExpiresAt) {
				if err := h.updateBakongOrderStatus(r.Context(), ref, "expired"); err != nil {
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
		"plan":              order.PlanID,
		"status":            order.Status,
		"phase":             phase,
		"amount_usd":        order.AmountUSD,
		"discount_pct":      order.DiscountPct,
		"qr_data_url":       order.ProviderQRCode,
		"expires_at":        order.ExpiresAt,
		"paid_at":           order.PaidAt,
		"poll_interval_ms":  walletPollIntervalMS,
		"payment_confirmed": order.Status == "paid",
		"bakong":            bakong,
	})
}

func normalizeBillingPlan(plan string) string {
	return strings.ToLower(strings.TrimSpace(plan))
}

func (h *BillingHandler) bakongPriceForUser(ctx context.Context, userID, plan string) (float64, int, error) {
	plan = normalizeBillingPlan(plan)

	basePrice, ok := map[string]float64{
		"student": 5.00,
		"pro":     10.00,
		"org":     40.00,
	}[plan]
	if !ok {
		return 0, 0, fmt.Errorf("unknown plan")
	}

	discountPct := 0
	if plan == "org" {
		if org, member, err := h.DB.GetMyOrg(ctx, userID); err == nil &&
			org != nil && org.OwnerID != nil && *org.OwnerID == userID &&
			member != nil && member.Role == "owner" && org.BillingDiscountPercent > 0 {
			discountPct = org.BillingDiscountPercent
		}
	}

	finalPrice := basePrice * float64(100-discountPct) / 100
	if finalPrice < 0 {
		finalPrice = 0
	}

	return finalPrice, discountPct, nil
}

func (h *BillingHandler) createBakongOrder(
	ctx context.Context,
	userID string,
	plan string,
	amountUSD float64,
	discountPct int,
	ref string,
	expiresAt time.Time,
	mode string,
	providerQRCode string,
	providerMD5 string,
	providerPollToken string,
) error {
	_, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO payment_orders (
			user_id, gateway, amount_usd, credits, gateway_ref, expires_at,
			payment_mode, provider_qr_code, provider_md5, provider_poll_token,
			order_purpose, plan_id, discount_pct
		)
		 VALUES ($1, 'bakong', $2, 0, $3, $4, $5, $6, $7, $8, 'billing_plan', $9, $10)`,
		userID, amountUSD, ref, expiresAt, mode, providerQRCode, providerMD5, providerPollToken, plan, discountPct,
	)
	return err
}

func (h *BillingHandler) updateBakongOrderStatus(ctx context.Context, ref string, status string) error {
	_, err := h.DB.Pool.Exec(ctx,
		`UPDATE payment_orders SET status=$2 WHERE gateway_ref=$1 AND order_purpose='billing_plan' AND status='pending'`,
		ref, status,
	)
	return err
}

func (h *BillingHandler) applyBakongPlan(ctx context.Context, userID, plan, ref string) error {
	tx, err := h.DB.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var orderStatus string
	if err := tx.QueryRow(ctx,
		`SELECT status FROM payment_orders WHERE gateway_ref=$1 AND order_purpose='billing_plan' FOR UPDATE`,
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

	if _, err := tx.Exec(ctx,
		`UPDATE users SET plan=$1, subscription_plan=$1, trial_ends_at=NULL, updated_at=now() WHERE id=$2`,
		plan, userID,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE payment_orders SET status='paid', paid_at=now() WHERE gateway_ref=$1 AND order_purpose='billing_plan'`,
		ref,
	); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	if h.Notify != nil {
		go h.Notify.Send(context.Background(), userID, "plan_upgraded",
			"Plan upgraded to "+plan,
			"Your Bakong payment was confirmed and your "+plan+" plan is now active.",
			"/dashboard/billing")
	}

	return nil
}

func (h *BillingHandler) recordSDKBillingPayment(ctx context.Context, userID, plan string, amountUSD float64, discountPct int, ref string) (bool, error) {
	tx, err := h.DB.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)

	var existingStatus string
	err = tx.QueryRow(ctx,
		`SELECT status FROM payment_orders WHERE gateway_ref=$1 AND user_id=$2 AND order_purpose='billing_plan' FOR UPDATE`,
		ref, userID,
	).Scan(&existingStatus)
	if err == nil {
		if existingStatus == "paid" {
			if err := tx.Commit(ctx); err != nil {
				return false, err
			}
			return true, nil
		}
		if _, err := tx.Exec(ctx,
			`UPDATE payment_orders
			 SET status='paid', paid_at=now(), amount_usd=$2, plan_id=$3, discount_pct=$4
			 WHERE gateway_ref=$1 AND user_id=$5 AND order_purpose='billing_plan'`,
			ref, amountUSD, plan, discountPct, userID,
		); err != nil {
			return false, err
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	} else {
		if _, err := tx.Exec(ctx,
			`INSERT INTO payment_orders (
				user_id, gateway, amount_usd, credits, status, gateway_ref, expires_at, paid_at,
				payment_mode, order_purpose, plan_id, discount_pct
			)
			 VALUES ($1, 'bakong', $2, 0, 'paid', $3, now(), now(), 'koma_qr', 'billing_plan', $4, $5)`,
			userID, amountUSD, ref, plan, discountPct,
		); err != nil {
			return false, err
		}
	}

	if _, err := tx.Exec(ctx,
		`UPDATE users SET plan=$1, subscription_plan=$1, trial_ends_at=NULL, updated_at=now() WHERE id=$2`,
		plan, userID,
	); err != nil {
		return false, err
	}

	var existingReceiptCount int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM payment_receipts WHERE user_id=$1 AND plan=$2 AND method='bakong' AND receipt_url=$3`,
		userID, plan, "koma://"+ref,
	).Scan(&existingReceiptCount); err != nil {
		return false, err
	}
	if existingReceiptCount == 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO payment_receipts (
				user_id, plan, amount_usd, discount_pct, method, receipt_url, note,
				status, admin_note, reviewed_at, updated_at
			)
			VALUES ($1, $2, $3, $4, 'bakong', $5, $6, 'approved', $7, now(), now())`,
			userID,
			plan,
			amountUSD,
			discountPct,
			"koma://"+ref,
			"Bakong SDK success confirmed on the client",
			"Auto-approved from Bakong SDK success callback",
		); err != nil {
			return false, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return false, err
	}

	if h.Notify != nil {
		go h.Notify.Send(context.Background(), userID, "plan_upgraded",
			"Plan upgraded to "+plan,
			"Your Bakong payment was confirmed and your "+plan+" plan is now active.",
			"/dashboard/billing")
	}

	return false, nil
}
