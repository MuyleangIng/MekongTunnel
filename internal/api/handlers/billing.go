package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
	stripe "github.com/stripe/stripe-go/v76"
	bpsession "github.com/stripe/stripe-go/v76/billingportal/session"
	checksession "github.com/stripe/stripe-go/v76/checkout/session"
	stripecoupon "github.com/stripe/stripe-go/v76/coupon"
	stripeinvoice "github.com/stripe/stripe-go/v76/invoice"
	stripeprice "github.com/stripe/stripe-go/v76/price"
	striperefund "github.com/stripe/stripe-go/v76/refund"
	stripesub "github.com/stripe/stripe-go/v76/subscription"
	"github.com/stripe/stripe-go/v76/webhook"
)

// BillingHandler handles /api/billing/* endpoints.
type BillingHandler struct {
	DB                  *db.DB
	StripeSecretKey     string
	StripeWebhookSecret string
	PlanPrices          map[string]string // plan → Stripe price ID
	FrontendURL         string
	Notify              *notify.Service
}

func (h *BillingHandler) setStripeKey() {
	stripe.Key = h.StripeSecretKey
}

// GetBilling handles GET /api/billing — returns plan + real Stripe invoices.
func (h *BillingHandler) GetBilling(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	result := map[string]any{
		"plan":                   user.Plan,
		"stripe_customer_id":     nil,
		"stripe_subscription_id": nil,
		"invoices":               []any{},
		"org_discount_percent":   0,
		"org_discount_note":      "",
	}

	if org, member, err := h.DB.GetMyOrg(r.Context(), claims.UserID); err == nil && org != nil && org.OwnerID != nil && *org.OwnerID == claims.UserID && member != nil && member.Role == "owner" {
		result["org_discount_percent"] = org.BillingDiscountPercent
		result["org_discount_note"] = org.BillingDiscountNote
	}

	if user.StripeCustomerID != nil {
		result["stripe_customer_id"] = *user.StripeCustomerID
	}
	if user.StripeSubscriptionID != nil {
		result["stripe_subscription_id"] = *user.StripeSubscriptionID
	}

	// Fetch subscription details (period end, status, cancel flag) from Stripe
	if h.StripeSecretKey != "" && user.StripeSubscriptionID != nil {
		h.setStripeKey()
		if sub, err := stripesub.Get(*user.StripeSubscriptionID, nil); err == nil {
			result["subscription_status"] = string(sub.Status)
			result["current_period_end"] = time.Unix(sub.CurrentPeriodEnd, 0).Format(time.RFC3339)
			result["cancel_at_period_end"] = sub.CancelAtPeriodEnd
		}
	}

	// Fetch real invoices from Stripe if customer exists
	if h.StripeSecretKey != "" && user.StripeCustomerID != nil {
		h.setStripeKey()
		params := &stripe.InvoiceListParams{
			Customer: user.StripeCustomerID,
		}
		params.Filters.AddFilter("limit", "", "10")
		iter := stripeinvoice.List(params)
		var invoices []map[string]any
		for iter.Next() {
			inv := iter.Invoice()
			invoices = append(invoices, map[string]any{
				"id":          inv.ID,
				"amount":      inv.AmountPaid,
				"currency":    string(inv.Currency),
				"status":      string(inv.Status),
				"date":        time.Unix(inv.Created, 0).Format("Jan 2, 2006"),
				"pdf":         inv.InvoicePDF,
				"description": inv.Description,
			})
		}
		if invoices != nil {
			result["invoices"] = invoices
		}
	}

	response.Success(w, result)
}

// CreateCheckout handles POST /api/billing/checkout.
func (h *BillingHandler) CreateCheckout(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		PlanID string `json:"plan_id"`
		Plan   string `json:"plan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	if body.PlanID != "" {
		body.Plan = body.PlanID
	}
	if body.Plan == "" {
		response.BadRequest(w, "plan is required")
		return
	}

	orgDiscountPercent := 0
	orgDiscountNote := ""
	if body.Plan == "org" {
		if org, member, err := h.DB.GetMyOrg(r.Context(), claims.UserID); err == nil && org != nil && org.OwnerID != nil && *org.OwnerID == claims.UserID && member != nil && member.Role == "owner" {
			orgDiscountPercent = org.BillingDiscountPercent
			orgDiscountNote = org.BillingDiscountNote
		}
	}

	if h.StripeSecretKey == "" {
		response.Success(w, map[string]any{
			"url":                  h.FrontendURL + "/billing/demo?plan=" + body.Plan,
			"org_discount_percent": orgDiscountPercent,
			"org_discount_note":    orgDiscountNote,
		})
		return
	}

	priceID, ok := h.PlanPrices[body.Plan]
	if !ok || priceID == "" {
		response.BadRequest(w, "no Stripe price configured for plan: "+body.Plan)
		return
	}

	h.setStripeKey()

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	params := &stripe.CheckoutSessionParams{
		Mode: stripe.String(string(stripe.CheckoutSessionModeSubscription)),
		LineItems: []*stripe.CheckoutSessionLineItemParams{
			{Price: stripe.String(priceID), Quantity: stripe.Int64(1)},
		},
		CustomerEmail: stripe.String(user.Email),
		SuccessURL:    stripe.String(h.FrontendURL + "/dashboard/billing?checkout=success"),
		CancelURL:     stripe.String(h.FrontendURL + "/pricing"),
		Metadata: map[string]string{
			"user_id": claims.UserID,
			"plan":    body.Plan,
		},
	}
	if orgDiscountPercent > 0 {
		couponParams := &stripe.CouponParams{
			PercentOff: stripe.Float64(float64(orgDiscountPercent)),
			Duration:   stripe.String(string(stripe.CouponDurationForever)),
			Name:       stripe.String(fmt.Sprintf("Approved ORG discount %d%%", orgDiscountPercent)),
		}
		couponParams.AddMetadata("user_id", claims.UserID)
		couponParams.AddMetadata("plan", body.Plan)
		couponParams.AddMetadata("discount_percent", strconv.Itoa(orgDiscountPercent))
		if orgDiscountNote != "" {
			couponParams.AddMetadata("discount_note", orgDiscountNote)
		}
		coupon, err := stripecoupon.New(couponParams)
		if err != nil {
			response.InternalError(w, err)
			return
		}
		params.Discounts = []*stripe.CheckoutSessionDiscountParams{
			{Coupon: stripe.String(coupon.ID)},
		}
		params.Metadata["org_discount_percent"] = strconv.Itoa(orgDiscountPercent)
		if orgDiscountNote != "" {
			params.Metadata["org_discount_note"] = orgDiscountNote
		}
		if orgDiscountPercent >= 100 {
			params.PaymentMethodCollection = stripe.String("if_required")
		}
	}
	// Reuse existing Stripe customer if we have one
	if user.StripeCustomerID != nil {
		params.CustomerEmail = nil
		params.Customer = user.StripeCustomerID
	}

	session, err := checksession.New(params)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"url": session.URL})
}

// CreatePortal handles POST /api/billing/portal.
func (h *BillingHandler) CreatePortal(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	user, err := h.DB.GetUserByID(r.Context(), claims.UserID)
	if err != nil {
		response.NotFound(w, "user not found")
		return
	}

	if h.StripeSecretKey == "" || user.StripeCustomerID == nil {
		response.BadRequest(w, "no Stripe subscription found")
		return
	}

	h.setStripeKey()

	params := &stripe.BillingPortalSessionParams{
		Customer:  user.StripeCustomerID,
		ReturnURL: stripe.String(h.FrontendURL + "/dashboard/billing"),
	}

	portalSession, err := bpsession.New(params)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"url": portalSession.URL})
}

// GetRevenue handles GET /api/admin/revenue — Stripe balance + MRR data.
func (h *BillingHandler) GetRevenue(w http.ResponseWriter, r *http.Request) {
	if h.StripeSecretKey == "" {
		response.Success(w, map[string]any{
			"mrr":            0,
			"total_revenue":  0,
			"pro_count":      0,
			"org_count":      0,
			"recent_charges": []any{},
		})
		return
	}

	h.setStripeKey()

	// Count paying users from DB
	stats, err := h.DB.GetAdminStats(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}

	proCount := stats.UsersByPlan["pro"]
	orgCount := stats.UsersByPlan["org"]

	// Fetch actual price amounts from Stripe so MRR matches real pricing
	var proUnitDollars, orgUnitDollars int64 = 10, 49 // fallback defaults
	if priceID, ok := h.PlanPrices["pro"]; ok && priceID != "" {
		if p, err := stripeprice.Get(priceID, nil); err == nil && p.UnitAmount > 0 {
			proUnitDollars = p.UnitAmount / 100
		}
	}
	if priceID, ok := h.PlanPrices["org"]; ok && priceID != "" {
		if p, err := stripeprice.Get(priceID, nil); err == nil && p.UnitAmount > 0 {
			orgUnitDollars = p.UnitAmount / 100
		}
	}
	mrr := int64(proCount)*proUnitDollars + int64(orgCount)*orgUnitDollars

	// Fetch recent successful charges
	params := &stripe.InvoiceListParams{}
	params.Filters.AddFilter("limit", "", "20")
	params.Filters.AddFilter("status", "", "paid")
	iter := stripeinvoice.List(params)

	var recentCharges []map[string]any
	var totalRevenue int64
	for iter.Next() {
		inv := iter.Invoice()
		totalRevenue += inv.AmountPaid
		charge := map[string]any{
			"id":           inv.ID,
			"customer":     inv.CustomerEmail,
			"amount":       inv.AmountPaid,
			"currency":     string(inv.Currency),
			"status":       string(inv.Status),
			"date":         time.Unix(inv.Created, 0).Format("Jan 2, 2006"),
			"subscription": inv.Subscription != nil,
			"pdf":          inv.InvoicePDF,
		}
		if inv.PaymentIntent != nil {
			charge["payment_intent_id"] = inv.PaymentIntent.ID
		}
		recentCharges = append(recentCharges, charge)
	}
	if recentCharges == nil {
		recentCharges = []map[string]any{}
	}

	response.Success(w, map[string]any{
		"mrr":            mrr,
		"total_revenue":  totalRevenue,
		"pro_count":      proCount,
		"org_count":      orgCount,
		"pro_price":      proUnitDollars,
		"org_price":      orgUnitDollars,
		"recent_charges": recentCharges,
	})
}

// GetSubscribers handles GET /api/admin/billing/subscribers.
// Returns every user with a Stripe subscription, enriched with live Stripe status.
func (h *BillingHandler) GetSubscribers(w http.ResponseWriter, r *http.Request) {
	users, err := h.DB.ListSubscribedUsers(r.Context())
	if err != nil {
		response.InternalError(w, err)
		return
	}

	type SubRecord struct {
		UserID            string `json:"user_id"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		Plan              string `json:"plan"`
		SubscriptionPlan  string `json:"subscription_plan"`
		SubscriptionID    string `json:"subscription_id"`
		Status            string `json:"status"`
		CancelAtPeriodEnd bool   `json:"cancel_at_period_end"`
		CurrentPeriodEnd  string `json:"current_period_end"`
	}

	records := make([]SubRecord, 0, len(users))

	if h.StripeSecretKey != "" {
		h.setStripeKey()
	}

	for _, u := range users {
		if u.StripeSubscriptionID == nil {
			continue
		}
		rec := SubRecord{
			UserID:           u.ID,
			Email:            u.Email,
			Name:             u.Name,
			Plan:             u.Plan,
			SubscriptionPlan: u.SubscriptionPlan,
			SubscriptionID:   *u.StripeSubscriptionID,
			Status:           "active",
		}

		// Enrich with live Stripe data if available
		if h.StripeSecretKey != "" {
			if sub, err := stripesub.Get(*u.StripeSubscriptionID, nil); err == nil {
				rec.Status = string(sub.Status)
				rec.CancelAtPeriodEnd = sub.CancelAtPeriodEnd
				rec.CurrentPeriodEnd = time.Unix(sub.CurrentPeriodEnd, 0).Format(time.RFC3339)
			}
		}

		records = append(records, rec)
	}

	response.Success(w, map[string]any{"subscribers": records})
}

// WebhookHandler handles POST /api/billing/webhook.
func (h *BillingHandler) WebhookHandler(w http.ResponseWriter, r *http.Request) {
	if h.StripeWebhookSecret == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		response.BadRequest(w, "cannot read body")
		return
	}

	sig := r.Header.Get("Stripe-Signature")
	event, err := webhook.ConstructEvent(body, sig, h.StripeWebhookSecret)
	if err != nil {
		log.Printf("[billing] webhook signature verification failed: %v", err)
		response.Error(w, http.StatusBadRequest, "invalid signature")
		return
	}

	h.setStripeKey()

	switch event.Type {
	case "checkout.session.completed":
		var cs stripe.CheckoutSession
		if err := json.Unmarshal(event.Data.Raw, &cs); err != nil {
			log.Printf("[billing] parse checkout session: %v", err)
			break
		}
		userID := cs.Metadata["user_id"]
		plan := cs.Metadata["plan"]
		if userID == "" || plan == "" {
			break
		}

		fields := map[string]any{
			"plan":              plan,
			"subscription_plan": plan,
		}
		// Save Stripe customer + subscription IDs
		if cs.Customer != nil {
			fields["stripe_customer_id"] = cs.Customer.ID
		}
		if cs.Subscription != nil {
			fields["stripe_subscription_id"] = cs.Subscription.ID
		}

		if _, err := h.DB.UpdateUser(r.Context(), userID, fields); err != nil {
			log.Printf("[billing] update user %s plan: %v", userID, err)
		} else {
			log.Printf("[billing] user %s upgraded to %s (customer: %v)", userID, plan, cs.Customer)
			if h.Notify != nil {
				go h.Notify.Send(context.Background(), userID, "plan_upgraded",
					"Plan upgraded to "+plan,
					"Your subscription to the "+plan+" plan is now active. Enjoy your new features!",
					"/dashboard/billing")
			}
		}

	case "customer.subscription.deleted":
		var sub stripe.Subscription
		if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
			log.Printf("[billing] parse subscription: %v", err)
			break
		}
		userID := sub.Metadata["user_id"]
		if userID == "" {
			// Look up by customer ID
			user, err := h.DB.GetUserByStripeCustomer(r.Context(), sub.Customer.ID)
			if err == nil && user != nil {
				userID = user.ID
			}
		}
		if userID != "" {
			if _, err := h.DB.UpdateUser(r.Context(), userID, map[string]any{
				"plan":                   "free",
				"subscription_plan":      "",
				"stripe_subscription_id": nil,
			}); err != nil {
				log.Printf("[billing] downgrade user %s: %v", userID, err)
			} else {
				log.Printf("[billing] user %s downgraded to free", userID)
				if h.Notify != nil {
					go h.Notify.Send(context.Background(), userID, "plan_downgraded",
						"Subscription ended",
						"Your subscription has ended and your plan has been set back to Free.",
						"/dashboard/billing")
				}
				// Free plan allows 1 tunnel — kill excess.
				if killed, err := h.DB.KillExcessTunnels(r.Context(), userID, 1); err != nil {
					log.Printf("[billing] kill excess tunnels for %s: %v", userID, err)
				} else if killed > 0 {
					log.Printf("[billing] killed %d excess tunnels for %s", killed, userID)
				}
			}
		}

	default:
		log.Printf("[billing] unhandled event: %s", event.Type)
	}

	w.WriteHeader(http.StatusOK)
}

// AdminRefund handles POST /api/admin/billing/refund — refunds a Stripe charge.
func (h *BillingHandler) AdminRefund(w http.ResponseWriter, r *http.Request) {
	if h.StripeSecretKey == "" {
		response.BadRequest(w, "Stripe not configured")
		return
	}

	var body struct {
		PaymentIntentID string `json:"payment_intent_id"`
		InvoiceID       string `json:"invoice_id"`
		Amount          int64  `json:"amount"` // cents, 0 = full refund
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}

	h.setStripeKey()

	// If invoice_id given, get the payment intent from it
	if body.PaymentIntentID == "" && body.InvoiceID != "" {
		inv, err := stripeinvoice.Get(body.InvoiceID, nil)
		if err != nil {
			response.BadRequest(w, "invoice not found: "+err.Error())
			return
		}
		if inv.PaymentIntent != nil {
			body.PaymentIntentID = inv.PaymentIntent.ID
		}
	}

	if body.PaymentIntentID == "" {
		response.BadRequest(w, "payment_intent_id or invoice_id is required")
		return
	}

	params := &stripe.RefundParams{
		PaymentIntent: stripe.String(body.PaymentIntentID),
	}
	if body.Amount > 0 {
		params.Amount = stripe.Int64(body.Amount)
	}

	ref, err := striperefund.New(params)
	if err != nil {
		response.BadRequest(w, "refund failed: "+err.Error())
		return
	}

	log.Printf("[billing] refund created: %s for pi %s amount=%d", ref.ID, body.PaymentIntentID, ref.Amount)
	response.Success(w, map[string]any{
		"refund_id": ref.ID,
		"amount":    ref.Amount,
		"status":    string(ref.Status),
	})
}

// AdminSendReceipt handles POST /api/admin/billing/receipt — sends invoice receipt via Stripe.
func (h *BillingHandler) AdminSendReceipt(w http.ResponseWriter, r *http.Request) {
	if h.StripeSecretKey == "" {
		response.BadRequest(w, "Stripe not configured")
		return
	}

	var body struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.InvoiceID == "" {
		response.BadRequest(w, "invoice_id is required")
		return
	}

	h.setStripeKey()

	// Fetch invoice to check collection method
	inv, err := stripeinvoice.Get(body.InvoiceID, nil)
	if err != nil {
		response.BadRequest(w, "invoice not found: "+err.Error())
		return
	}

	// Subscription invoices use charge_automatically — Stripe already sends receipts.
	// Only send_invoice collection method supports manual sending.
	if inv.CollectionMethod != stripe.InvoiceCollectionMethodSendInvoice {
		log.Printf("[billing] receipt auto-sent (charge_automatically) for invoice %s to %s", body.InvoiceID, inv.CustomerEmail)
		response.Success(w, map[string]any{
			"message": "auto_sent",
			"email":   inv.CustomerEmail,
		})
		return
	}

	_, err = stripeinvoice.SendInvoice(body.InvoiceID, nil)
	if err != nil {
		response.BadRequest(w, "failed to send receipt: "+err.Error())
		return
	}

	log.Printf("[billing] receipt sent for invoice %s", body.InvoiceID)
	response.Success(w, map[string]any{"message": "receipt sent", "email": inv.CustomerEmail})
}
