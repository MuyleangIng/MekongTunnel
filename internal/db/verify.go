package db

import (
	"context"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// UpsertVerifyRequest creates or updates the user's verify request.
// - approved  → no-op, return as-is
// - pending / reviewing → UPDATE in-place with new data, reset to pending
// - rejected / none → INSERT a fresh record
func (db *DB) UpsertVerifyRequest(ctx context.Context, userID, reqType, orgName, reason, documentURL string) (*models.VerifyRequest, error) {
	existing, _ := db.GetVerifyRequestByUser(ctx, userID)

	if existing != nil {
		switch existing.Status {
		case "approved":
			// Don't touch an approved request.
			return existing, nil
		case "rejected":
			// Fall through to INSERT a new record below.
		default:
			// pending / reviewing → UPDATE with the new document and reset to pending.
			row := db.Pool.QueryRow(ctx, `
				UPDATE verify_requests
				SET type = $2, org_name = $3, reason = $4, document_url = $5,
				    status = 'pending', reject_reason = '', admin_note = '', updated_at = now()
				WHERE id = $1
				RETURNING id, user_id, type, status, org_name, reject_reason, reason, document_url, admin_note, created_at, updated_at`,
				existing.ID, reqType, orgName, reason, documentURL)
			return scanVerifyRequest(row)
		}
	}

	// No prior request, or previous was rejected → insert fresh.
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO verify_requests (user_id, type, org_name, reason, document_url)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, user_id, type, status, org_name, reject_reason, reason, document_url, admin_note, created_at, updated_at`,
		userID, reqType, orgName, reason, documentURL)
	return scanVerifyRequest(row)
}

// GetVerifyRequestByUser returns the most recent verify request for a user.
func (db *DB) GetVerifyRequestByUser(ctx context.Context, userID string) (*models.VerifyRequest, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, type, status, org_name, reject_reason, reason, document_url, admin_note, created_at, updated_at
		FROM verify_requests
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 1`, userID)
	return scanVerifyRequest(row)
}

// ListVerifyRequests returns all verify requests, with user info, ordered by newest first.
func (db *DB) ListVerifyRequests(ctx context.Context, status string) ([]*models.VerifyRequest, error) {
	query := `
		SELECT vr.id, vr.user_id, vr.type, vr.status, vr.org_name, vr.reject_reason,
		       vr.reason, vr.document_url, vr.admin_note,
		       vr.created_at, vr.updated_at,
		       u.name, u.email, u.plan,
		       (u.stripe_subscription_id IS NOT NULL AND u.stripe_subscription_id != '') AS has_subscription
		FROM verify_requests vr
		JOIN users u ON u.id = vr.user_id`
	args := []any{}
	if status != "" {
		query += " WHERE vr.status = $1"
		args = append(args, status)
	}
	query += " ORDER BY vr.created_at DESC"

	rows, err := db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*models.VerifyRequest
	for rows.Next() {
		vr := &models.VerifyRequest{}
		if err := rows.Scan(
			&vr.ID, &vr.UserID, &vr.Type, &vr.Status, &vr.OrgName, &vr.RejectReason,
			&vr.Reason, &vr.DocumentURL, &vr.AdminNote,
			&vr.CreatedAt, &vr.UpdatedAt,
			&vr.UserName, &vr.UserEmail,
			&vr.UserPlan, &vr.UserHasSubscription,
		); err != nil {
			return nil, err
		}
		results = append(results, vr)
	}
	return results, nil
}

// planRank maps plan names to an integer rank for comparison.
var planRank = map[string]int{
	"free":    0,
	"student": 1,
	"teacher": 1,
	"pro":     2,
	"org":     3,
}

// UpdateVerifyRequest updates the status (and optionally reject reason) of a request.
// If approved, it upgrades the user's plan — but only if the new plan outranks the current one.
// Pass force=true to override this protection.
func (db *DB) UpdateVerifyRequest(ctx context.Context, id, status, rejectReason string, force bool) (*models.VerifyRequest, bool, error) {
	row := db.Pool.QueryRow(ctx, `
		UPDATE verify_requests
		SET status = $1, reject_reason = $2, updated_at = $3
		WHERE id = $4
		RETURNING id, user_id, type, status, org_name, reject_reason, reason, document_url, admin_note, created_at, updated_at`,
		status, rejectReason, time.Now(), id)
	vr, err := scanVerifyRequest(row)
	if err != nil {
		return nil, false, err
	}

	planSkipped := false
	if status == "approved" {
		// Org plan requires payment after approval — do not auto-set plan.
		// Payment webhook will set plan=org when Stripe confirms.
		if vr.Type != "org" {
			user, err := db.GetUserByID(ctx, vr.UserID)
			if err != nil {
				return nil, false, err
			}
			currentRank := planRank[user.Plan]
			newRank := planRank[vr.Type]
			if force || newRank > currentRank {
				if _, err := db.UpdateUser(ctx, vr.UserID, map[string]any{"plan": vr.Type}); err != nil {
					return nil, false, err
				}
			} else {
				planSkipped = true
			}
		}
	}

	return vr, planSkipped, nil
}

// SetAdminNote updates the admin_note field (used for "request resubmission" messages).
func (db *DB) SetAdminNote(ctx context.Context, id, note string) (*models.VerifyRequest, error) {
	row := db.Pool.QueryRow(ctx, `
		UPDATE verify_requests
		SET admin_note = $1, updated_at = $2
		WHERE id = $3
		RETURNING id, user_id, type, status, org_name, reject_reason, reason, document_url, admin_note, created_at, updated_at`,
		note, time.Now(), id)
	return scanVerifyRequest(row)
}

// ResetVerifyRequest resets a request to pending and clears the document URL,
// forcing the user to upload a new document. Used by admins.
func (db *DB) ResetVerifyRequest(ctx context.Context, id, adminNote string) (*models.VerifyRequest, error) {
	row := db.Pool.QueryRow(ctx, `
		UPDATE verify_requests
		SET status = 'pending', document_url = '', reject_reason = '', admin_note = $2, updated_at = now()
		WHERE id = $1
		RETURNING id, user_id, type, status, org_name, reject_reason, reason, document_url, admin_note, created_at, updated_at`,
		id, adminNote)
	return scanVerifyRequest(row)
}

// DeleteVerifyRequest permanently removes a verify request.
func (db *DB) DeleteVerifyRequest(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM verify_requests WHERE id = $1`, id)
	return err
}

// GetVerifyRequestByID returns a single verify request by its ID.
func (db *DB) GetVerifyRequestByID(ctx context.Context, id string) (*models.VerifyRequest, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, type, status, org_name, reject_reason, reason, document_url, admin_note, created_at, updated_at
		FROM verify_requests WHERE id = $1`, id)
	return scanVerifyRequest(row)
}

// GetApprovedVerifyType returns the type (e.g. "student", "teacher") of the user's
// most recent approved verify request, or "" if none exists.
func (db *DB) GetApprovedVerifyType(ctx context.Context, userID string) (string, error) {
	var vType string
	err := db.Pool.QueryRow(ctx, `
		SELECT type FROM verify_requests
		WHERE user_id = $1 AND status = 'approved'
		ORDER BY updated_at DESC
		LIMIT 1`, userID).Scan(&vType)
	if err != nil {
		return "", nil // no approved request — not an error
	}
	return vType, nil
}

func scanVerifyRequest(row interface{ Scan(...any) error }) (*models.VerifyRequest, error) {
	vr := &models.VerifyRequest{}
	err := row.Scan(
		&vr.ID, &vr.UserID, &vr.Type, &vr.Status, &vr.OrgName, &vr.RejectReason,
		&vr.Reason, &vr.DocumentURL, &vr.AdminNote,
		&vr.CreatedAt, &vr.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return vr, nil
}
