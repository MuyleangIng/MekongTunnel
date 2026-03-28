package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
)

// ReceiptHandler handles manual payment receipts (PayPal / ABA / Bakong).
type ReceiptHandler struct {
	DB     *db.DB
	Notify *notify.Service
	Mailer *mailer.Mailer
}

// activatePlan updates the user's plan and sends a notification.
func (h *ReceiptHandler) activatePlan(ctx context.Context, userID, plan string) error {
	_, err := h.DB.UpdateUser(ctx, userID, map[string]any{
		"plan":              plan,
		"subscription_plan": plan,
	})
	if err != nil {
		return err
	}
	if h.Notify != nil {
		go h.Notify.Send(context.Background(), userID, "plan_upgraded",
			"Plan upgraded to "+plan,
			"Your payment was verified! Your "+plan+" plan is now active.",
			"/dashboard/billing")
	}
	return nil
}

// SubmitReceipt handles POST /api/billing/manual-payment — user submits a receipt.
func (h *ReceiptHandler) SubmitReceipt(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Plan       string  `json:"plan"`
		Method     string  `json:"method"`      // "paypal" | "aba" | "bakong"
		ReceiptURL string  `json:"receipt_url"` // uploaded file URL
		Note       string  `json:"note"`
		AmountUSD  float64 `json:"amount_usd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}
	if body.Plan == "" || body.Method == "" || body.ReceiptURL == "" {
		response.BadRequest(w, "plan, method, and receipt_url are required")
		return
	}
	if body.Method != "paypal" && body.Method != "aba" && body.Method != "bakong" {
		response.BadRequest(w, "method must be 'paypal', 'aba', or 'bakong'")
		return
	}

	planPrices := map[string]float64{"pro": 10.00, "org": 49.00, "student": 5.00}
	if _, ok := planPrices[body.Plan]; !ok {
		response.BadRequest(w, "unknown plan")
		return
	}

	// Block duplicate submissions: one pending/needs_resubmit receipt per plan.
	if dup, err := h.DB.HasActivePendingReceipt(r.Context(), claims.UserID, body.Plan); err == nil && dup {
		response.Conflict(w, "you already have a pending receipt for this plan — wait for admin review or contact support")
		return
	}

	basePrice := planPrices[body.Plan]
	discountPct := 0
	finalPrice := basePrice
	if org, member, err := h.DB.GetMyOrg(r.Context(), claims.UserID); err == nil &&
		org != nil && org.OwnerID != nil && *org.OwnerID == claims.UserID &&
		member != nil && member.Role == "owner" && org.BillingDiscountPercent > 0 {
		discountPct = org.BillingDiscountPercent
		finalPrice = basePrice * float64(100-discountPct) / 100
	}

	receipt, err := h.DB.CreatePaymentReceipt(r.Context(), claims.UserID, body.Plan,
		body.Method, body.ReceiptURL, finalPrice, discountPct, body.Note)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	// Notify all admins about the new receipt submission.
	if h.Notify != nil {
		methodLabel := map[string]string{"paypal": "PayPal", "aba": "ABA Pay", "bakong": "Bakong"}[body.Method]
		go h.Notify.SendToAdmins(context.Background(), "receipt_submitted",
			"New payment receipt submitted",
			fmt.Sprintf("A user submitted a %s receipt for the %s plan ($%.2f). Review it now.",
				methodLabel, body.Plan, finalPrice),
			"/admin/billing")
	}

	log.Printf("[billing] receipt submitted: user=%s plan=%s method=%s", claims.UserID, body.Plan, body.Method)
	response.Success(w, receipt)
}

// ListMyReceipts handles GET /api/billing/manual-payment — user's own receipts.
func (h *ReceiptHandler) ListMyReceipts(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	receipts, err := h.DB.ListUserReceipts(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if receipts == nil {
		receipts = []*db.PaymentReceipt{}
	}
	response.Success(w, map[string]any{"receipts": receipts})
}

// UserReceiptPendingCount handles GET /api/billing/manual-payment/count.
func (h *ReceiptHandler) UserReceiptPendingCount(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	n, err := h.DB.GetUserPendingReceiptCount(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"count": n})
}

// AdminListReceipts handles GET /api/admin/billing/receipts.
func (h *ReceiptHandler) AdminListReceipts(w http.ResponseWriter, r *http.Request) {
	receipts, err := h.DB.ListPendingReceipts(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if receipts == nil {
		receipts = []*db.PaymentReceipt{}
	}
	response.Success(w, map[string]any{"receipts": receipts})
}

// AdminReceiptCount handles GET /api/admin/billing/receipts/count.
func (h *ReceiptHandler) AdminReceiptCount(w http.ResponseWriter, r *http.Request) {
	n, err := h.DB.GetPendingReceiptCount(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Success(w, map[string]any{"count": n})
}

// AdminReviewReceipt handles POST /api/admin/billing/receipts/{id}/review.
func (h *ReceiptHandler) AdminReviewReceipt(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	receiptID := r.PathValue("id")
	if receiptID == "" {
		response.BadRequest(w, "receipt id required")
		return
	}

	var body struct {
		Status        string  `json:"status"`          // "approved" | "rejected" | "needs_resubmit"
		AdminNote     string  `json:"admin_note"`
		AllowResubmit bool    `json:"allow_resubmit"`  // true → status becomes "needs_resubmit"
		RefundBank    string  `json:"refund_bank"`     // bank account for manual refund
		RefundAmount  float64 `json:"refund_amount"`   // amount to refund
		RefundNote    string  `json:"refund_note"`     // refund instructions
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON")
		return
	}

	// Determine final status
	finalStatus := body.Status
	if body.AllowResubmit && body.Status == "rejected" {
		finalStatus = "needs_resubmit"
	}
	if finalStatus != "approved" && finalStatus != "rejected" && finalStatus != "needs_resubmit" {
		response.BadRequest(w, "status must be 'approved', 'rejected', or 'needs_resubmit'")
		return
	}

	receipt, err := h.DB.GetPaymentReceipt(r.Context(), receiptID)
	if err != nil {
		response.NotFound(w, "receipt not found")
		return
	}

	if err := h.DB.ReviewPaymentReceipt(r.Context(), receiptID, claims.UserID,
		finalStatus, body.AdminNote, body.RefundBank, body.RefundNote, body.RefundAmount, body.AllowResubmit); err != nil {
		response.InternalError(w, err)
		return
	}

	switch finalStatus {
	case "approved":
		if err := h.activatePlan(r.Context(), receipt.UserID, receipt.Plan); err != nil {
			log.Printf("[billing] activate plan for receipt %s: %v", receiptID, err)
		}
		if h.Notify != nil {
			go h.Notify.Send(context.Background(), receipt.UserID, "receipt_approved",
				"Payment receipt approved",
				"Your "+receipt.Method+" payment has been verified. Your "+receipt.Plan+" plan is now active!",
				"/dashboard/billing")
		}
		// Send receipt email
		if h.Mailer != nil {
			if user, err := h.DB.GetUserByID(context.Background(), receipt.UserID); err == nil && user != nil {
				go func() {
					html := receiptEmailHTML(receipt.ID, user.Name, receipt.Plan, receipt.Method, receipt.AmountUSD, receipt.DiscountPct)
					if err := h.Mailer.Send(user.Email, "✅ Payment confirmed — "+capitalise(receipt.Plan)+" plan activated", html); err != nil {
						log.Printf("[billing] receipt email: %v", err)
					}
				}()
			}
		}

	case "needs_resubmit":
		if h.Notify != nil {
			msg := "Your payment receipt needs correction. " + body.AdminNote
			if body.RefundAmount > 0 {
				msg = fmt.Sprintf("Amount mismatch detected ($%.2f expected). Please resubmit with the correct amount. "+body.AdminNote, receipt.AmountUSD)
			}
			go h.Notify.Send(context.Background(), receipt.UserID, "receipt_needs_resubmit",
				"Payment receipt needs resubmission",
				msg,
				"/dashboard/billing")
		}

	case "rejected":
		if h.Notify != nil {
			msg := "Your payment receipt could not be verified. " + body.AdminNote
			if body.RefundBank != "" {
				msg += fmt.Sprintf(" A refund of $%.2f will be sent to your account: %s", body.RefundAmount, body.RefundBank)
			}
			go h.Notify.Send(context.Background(), receipt.UserID, "receipt_rejected",
				"Payment receipt rejected",
				msg,
				"/dashboard/billing")
		}
	}

	log.Printf("[billing] receipt %s → %s by admin %s", receiptID, finalStatus, claims.UserID)
	response.Success(w, map[string]any{"status": finalStatus})
}

// AdminDeleteReceipt handles DELETE /api/admin/billing/receipts/{id}.
func (h *ReceiptHandler) AdminDeleteReceipt(w http.ResponseWriter, r *http.Request) {
	receiptID := r.PathValue("id")
	if receiptID == "" {
		response.BadRequest(w, "receipt id required")
		return
	}
	if err := h.DB.DeletePaymentReceipt(r.Context(), receiptID); err != nil {
		response.InternalError(w, err)
		return
	}
	log.Printf("[billing] receipt %s deleted", receiptID)
	response.Success(w, map[string]any{"deleted": true})
}

// ── helpers ───────────────────────────────────────────────────

func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func receiptEmailHTML(receiptID, name, plan, method string, amountUSD float64, discountPct int) string {
	methodLabel := map[string]string{"paypal": "PayPal", "aba": "ABA Pay", "bakong": "Bakong"}[method]
	if methodLabel == "" {
		methodLabel = method
	}
	discount := ""
	if discountPct > 0 {
		discount = fmt.Sprintf(`<tr><td style="padding:4px 0;color:#888">Discount</td><td style="padding:4px 0;text-align:right;color:#22c55e">-%d%%</td></tr>`, discountPct)
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Payment Receipt</title></head>
<body style="background:#0d0d1a;color:#e5e5f0;font-family:'Segoe UI',sans-serif;margin:0;padding:0">
<div style="max-width:520px;margin:40px auto;background:#16162a;border:1px solid #2a2a4a;border-radius:16px;overflow:hidden">
  <div style="background:linear-gradient(135deg,#f5a623,#e8972b);padding:28px 32px">
    <p style="margin:0;font-size:11px;font-weight:700;letter-spacing:2px;color:#7a4800;text-transform:uppercase">MekongTunnel</p>
    <h1 style="margin:8px 0 0;font-size:24px;color:#fff;font-weight:800">Payment Confirmed</h1>
  </div>
  <div style="padding:32px">
    <p style="color:#a0a0c0;margin:0 0 24px">Hi %s, your payment has been verified and your plan is now active.</p>
    <table style="width:100%%;border-collapse:collapse;margin-bottom:24px">
      <tr><td style="padding:4px 0;color:#888">Receipt ID</td><td style="padding:4px 0;text-align:right;font-family:monospace;font-size:12px;color:#a0a0c0">%s</td></tr>
      <tr><td style="padding:4px 0;color:#888">Plan</td><td style="padding:4px 0;text-align:right;font-weight:700;color:#f5a623;text-transform:uppercase">%s</td></tr>
      <tr><td style="padding:4px 0;color:#888">Payment method</td><td style="padding:4px 0;text-align:right;color:#e5e5f0">%s</td></tr>
      %s
      <tr style="border-top:1px solid #2a2a4a"><td style="padding:12px 0 4px;font-weight:700;color:#e5e5f0">Total paid</td><td style="padding:12px 0 4px;text-align:right;font-weight:800;font-size:20px;color:#22c55e">$%.2f USD</td></tr>
    </table>
    <div style="background:#0d0d1a;border:1px solid #2a2a4a;border-radius:12px;padding:16px;margin-bottom:24px">
      <p style="margin:0;font-size:13px;color:#a0a0c0">Your <strong style="color:#f5a623">%s</strong> plan is now active. Log in to start using all features.</p>
    </div>
    <a href="https://angkorsearch.dev/dashboard" style="display:inline-block;background:#f5a623;color:#fff;text-decoration:none;padding:12px 24px;border-radius:10px;font-weight:700;font-size:14px">Go to Dashboard →</a>
    <p style="margin:24px 0 0;font-size:11px;color:#555;border-top:1px solid #2a2a4a;padding-top:16px">MekongTunnel · mekongtunnel.dev · This is your payment receipt — keep it for your records.</p>
  </div>
</div></body></html>`,
		name, receiptID, strings.ToUpper(plan), methodLabel, discount, amountUSD, capitalise(plan))
}
