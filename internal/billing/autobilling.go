// Package billing runs the daily auto-billing job for deploy subscriptions.
//
// Lifecycle:
//
//	active  → (renewal day, no credits) → grace (7 days, email sent)
//	grace   → (7 days pass)             → stopped (files kept, server off)
//	stopped → (30 days pass)            → marked for admin review / auto-delete
package billing

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/mailer"
)

const (
	gracePeriod  = 7 * 24 * time.Hour
	deletePeriod = 30 * 24 * time.Hour
)

type Job struct {
	DB          *db.DB
	Mailer      *mailer.Mailer
	FrontendURL string
}

// Run processes all subscriptions due today. Call this once per day.
func (j *Job) Run(ctx context.Context) {
	log.Println("[billing] starting daily auto-billing run ...")

	j.processRenewals(ctx)
	j.processGraceExpiry(ctx)
	j.processStoppedExpiry(ctx)

	log.Println("[billing] daily auto-billing run complete")
}

// ── Renewals ─────────────────────────────────────────────────────────────────

func (j *Job) processRenewals(ctx context.Context) {
	rows, err := j.DB.Pool.Query(ctx, `
		SELECT s.id, s.user_id, s.credits_per_month, s.deployment_id,
		       u.email, u.credit_balance
		FROM deploy_subscriptions s
		JOIN users u ON u.id = s.user_id
		WHERE s.status = 'active' AND s.renews_at <= now()
	`)
	if err != nil {
		log.Printf("[billing] renewal query error: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var subID, userID, email string
		var deploymentID *string
		var creditsNeeded, balance int
		if err := rows.Scan(&subID, &userID, &creditsNeeded, &deploymentID, &email, &balance); err != nil {
			continue
		}

		if balance >= creditsNeeded {
			j.chargeRenewal(ctx, subID, userID, creditsNeeded, balance)
		} else {
			j.startGrace(ctx, subID, userID, email, creditsNeeded, balance)
		}
	}
}

func (j *Job) chargeRenewal(ctx context.Context, subID, userID string, credits, currentBalance int) {
	tx, err := j.DB.Pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)

	newBalance := currentBalance - credits
	if _, err := tx.Exec(ctx,
		`UPDATE users SET credit_balance=$1 WHERE id=$2`,
		newBalance, userID,
	); err != nil {
		return
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO credit_transactions (user_id, amount, balance_after, description, gateway)
		 VALUES ($1, $2, $3, $4, 'system')`,
		userID, -credits, newBalance, fmt.Sprintf("Monthly deploy storage renewal (%d credits)", credits),
	); err != nil {
		return
	}

	if _, err := tx.Exec(ctx,
		`UPDATE deploy_subscriptions SET renews_at = renews_at + interval '1 month' WHERE id=$1`,
		subID,
	); err != nil {
		return
	}

	tx.Commit(ctx)
	log.Printf("[billing] charged %d credits for subscription %s (user %s)", credits, subID, userID)
}

func (j *Job) startGrace(ctx context.Context, subID, userID, email string, needed, have int) {
	if _, err := j.DB.Pool.Exec(ctx,
		`UPDATE deploy_subscriptions SET status='grace', grace_started_at=now() WHERE id=$1`,
		subID,
	); err != nil {
		log.Printf("[billing] grace update error: %v", err)
		return
	}

	log.Printf("[billing] subscription %s → grace (user %s, need %d have %d)", subID, userID, needed, have)
	j.sendGraceEmail(email, needed, have)
}

// ── Grace expiry → stop ───────────────────────────────────────────────────────

func (j *Job) processGraceExpiry(ctx context.Context) {
	rows, err := j.DB.Pool.Query(ctx, `
		SELECT s.id, s.user_id, s.deployment_id, d.files_path, d.subdomain, u.email
		FROM deploy_subscriptions s
		JOIN users u ON u.id = s.user_id
		LEFT JOIN deployments d ON d.id = s.deployment_id
		WHERE s.status = 'grace'
		  AND s.grace_started_at + $1 <= now()
	`, gracePeriod)
	if err != nil {
		log.Printf("[billing] grace expiry query error: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var subID, userID, email string
		var deployID, filesPath, subdomain *string
		if err := rows.Scan(&subID, &userID, &deployID, &filesPath, &subdomain, &email); err != nil {
			continue
		}

		j.stopDeployment(ctx, subID, deployID, userID)
		j.sendStoppedEmail(email, subdomain)
		log.Printf("[billing] subscription %s → stopped (grace expired, user %s)", subID, userID)
	}
}

func (j *Job) stopDeployment(ctx context.Context, subID string, deployID *string, userID string) {
	tx, err := j.DB.Pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`UPDATE deploy_subscriptions SET status='stopped', stopped_at=now() WHERE id=$1`, subID,
	); err != nil {
		return
	}

	if deployID != nil {
		if _, err := tx.Exec(ctx,
			`UPDATE deployments SET status='stopped', stopped_at=now() WHERE id=$1`, *deployID,
		); err != nil {
			return
		}
	}

	tx.Commit(ctx)
}

// ── Stopped expiry → mark for admin ──────────────────────────────────────────

func (j *Job) processStoppedExpiry(ctx context.Context) {
	rows, err := j.DB.Pool.Query(ctx, `
		SELECT s.id, s.deployment_id, u.email, d.subdomain
		FROM deploy_subscriptions s
		JOIN users u ON u.id = s.user_id
		LEFT JOIN deployments d ON d.id = s.deployment_id
		WHERE s.status = 'stopped'
		  AND s.stopped_at + $1 <= now()
	`, deletePeriod)
	if err != nil {
		log.Printf("[billing] stopped expiry query error: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var subID string
		var deployID, email, subdomain *string
		if err := rows.Scan(&subID, &deployID, &email, &subdomain); err != nil {
			continue
		}

		// Mark deployment for admin review (not auto-deleted — admin decides)
		if deployID != nil {
			if _, err := j.DB.Pool.Exec(ctx,
				`UPDATE deployments SET status='stopped' WHERE id=$1`,
				*deployID,
			); err != nil {
				log.Printf("[billing] mark-for-review error for deploy %s: %v", *deployID, err)
				continue
			}
		}

		log.Printf("[billing] subscription %s marked for admin review (user email: %s, sub: %s)",
			subID, strPtr(email), strPtr(subdomain))
	}
}

// ── Emails ────────────────────────────────────────────────────────────────────

func (j *Job) sendGraceEmail(email string, needed, have int) {
	if j.Mailer == nil {
		return
	}
	subject := "⚠️ MekongTunnel — Your deploy storage renewal failed"
	body := fmt.Sprintf(`
<h2>Your deploy storage subscription couldn't renew</h2>
<p>You need <strong>%d credits</strong> to renew but only have <strong>%d credits</strong>.</p>
<p>Your deployment will stay active for <strong>7 more days</strong>.</p>
<p>Top up your credits before then to keep it running:</p>
<p><a href="%s/dashboard/wallet" style="background:#6366f1;color:white;padding:12px 24px;border-radius:6px;text-decoration:none">Top Up Credits</a></p>
<p style="color:#888;font-size:12px">If you don't top up within 7 days, your deployment will be stopped (but not deleted).</p>
`, needed, have, j.FrontendURL)
	j.Mailer.Send(email, subject, body)
}

func (j *Job) sendStoppedEmail(email string, subdomain *string) {
	if j.Mailer == nil {
		return
	}
	sub := strPtr(subdomain)
	subject := "🔴 MekongTunnel — Your deployment has been stopped"
	body := fmt.Sprintf(`
<h2>Your deployment has been stopped</h2>
<p>Deployment <strong>%s</strong> has been stopped due to insufficient credits.</p>
<p>Your files are still saved. Top up credits and restart your deployment within <strong>30 days</strong> to restore it.</p>
<p><a href="%s/dashboard/wallet" style="background:#6366f1;color:white;padding:12px 24px;border-radius:6px;text-decoration:none">Top Up & Restart</a></p>
<p style="color:#888;font-size:12px">After 30 days without payment, your files will be reviewed for deletion by our team.</p>
`, sub, j.FrontendURL)
	j.Mailer.Send(email, subject, body)
}

func strPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
