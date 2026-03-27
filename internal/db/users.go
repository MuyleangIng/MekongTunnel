package db

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// ─── helpers ─────────────────────────────────────────────────

// scanUser scans a full users row (all columns in schema order).
func scanUser(row interface {
	Scan(...any) error
}) (*models.User, error) {
	u := &models.User{}
	err := row.Scan(
		&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.AvatarURL,
		&u.Plan, &u.AccountType, &u.EmailVerified,
		&u.TOTPSecret, &u.TOTPEnabled, &u.EmailOTPEnabled, &u.IsAdmin, &u.Suspended,
		&u.GithubID, &u.GithubLogin, &u.GoogleID,
		&u.StripeCustomerID, &u.StripeSubscriptionID, &u.SubscriptionPlan,
		&u.CreatedAt, &u.UpdatedAt, &u.LastSeenAt,
		&u.TrialEndsAt, &u.NewsletterSubscribed, &u.NewsletterUnsubscribeToken,
	)
	if err != nil {
		return nil, err
	}
	return u, nil
}

const userColumns = `
	id, email, name, password_hash, avatar_url,
	plan, account_type, email_verified,
	totp_secret, totp_enabled, email_otp_enabled, is_admin, suspended,
	github_id, github_login, google_id,
	stripe_customer_id, stripe_subscription_id, subscription_plan,
	created_at, updated_at, last_seen_at,
	trial_ends_at, newsletter_subscribed, newsletter_unsubscribe_token`

// ─── CRUD ────────────────────────────────────────────────────

func (db *DB) CreateUser(ctx context.Context, email, name, passwordHash string) (*models.User, error) {
	var ph *string
	if passwordHash != "" {
		ph = &passwordHash
	}
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO users (email, name, password_hash)
		VALUES ($1, $2, $3)
		RETURNING `+userColumns,
		email, name, ph)
	return scanUser(row)
}

func (db *DB) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	row := db.Pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
	return scanUser(row)
}

func (db *DB) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	row := db.Pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1`, email)
	return scanUser(row)
}

func (db *DB) GetUserByGithubID(ctx context.Context, githubID string) (*models.User, error) {
	row := db.Pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE github_id = $1`, githubID)
	return scanUser(row)
}

func (db *DB) GetUserByGoogleID(ctx context.Context, googleID string) (*models.User, error) {
	row := db.Pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE google_id = $1`, googleID)
	return scanUser(row)
}

func (db *DB) GetUserByStripeCustomer(ctx context.Context, customerID string) (*models.User, error) {
	row := db.Pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE stripe_customer_id = $1`, customerID)
	return scanUser(row)
}

// UpdateUser performs a dynamic UPDATE on the users table.
// fields keys must be valid column names.
func (db *DB) UpdateUser(ctx context.Context, id string, fields map[string]any) (*models.User, error) {
	if len(fields) == 0 {
		return db.GetUserByID(ctx, id)
	}
	fields["updated_at"] = time.Now()

	setClauses := make([]string, 0, len(fields))
	args := make([]any, 0, len(fields)+1)
	i := 1
	for col, val := range fields {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", col, i))
		args = append(args, val)
		i++
	}
	args = append(args, id)

	query := fmt.Sprintf(`UPDATE users SET %s WHERE id = $%d RETURNING `+userColumns,
		strings.Join(setClauses, ", "), i)

	row := db.Pool.QueryRow(ctx, query, args...)
	return scanUser(row)
}

func (db *DB) SetEmailVerified(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1`, id)
	return err
}

func (db *DB) SetTOTPSecret(ctx context.Context, id, secret string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET totp_secret = $1, updated_at = now() WHERE id = $2`, secret, id)
	return err
}

func (db *DB) EnableTOTP(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET totp_enabled = true, updated_at = now() WHERE id = $1`, id)
	return err
}

func (db *DB) DisableTOTP(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET totp_enabled = false, totp_secret = NULL, updated_at = now() WHERE id = $1`, id)
	return err
}

func (db *DB) SaveBackupCodes(ctx context.Context, userID string, codeHashes []string) error {
	// Delete existing codes first.
	if _, err := db.Pool.Exec(ctx,
		`DELETE FROM totp_backup_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	for _, h := range codeHashes {
		if _, err := db.Pool.Exec(ctx,
			`INSERT INTO totp_backup_codes (user_id, code_hash) VALUES ($1, $2)`, userID, h); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) UseBackupCode(ctx context.Context, userID, codeHash string) error {
	result, err := db.Pool.Exec(ctx, `
		UPDATE totp_backup_codes SET used_at = now()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
		userID, codeHash)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("backup code not found or already used")
	}
	return nil
}

func (db *DB) UpdatePassword(ctx context.Context, id, hash string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2`, hash, id)
	return err
}

func (db *DB) UpdatePlan(ctx context.Context, id, plan string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET plan = $1, updated_at = now() WHERE id = $2`, plan, id)
	return err
}

func (db *DB) SuspendUser(ctx context.Context, id string, suspended bool) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET suspended = $1, updated_at = now() WHERE id = $2`, suspended, id)
	return err
}

func (db *DB) UpdateLastSeen(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET last_seen_at = now() WHERE id = $1`, id)
	return err
}

func (db *DB) DeleteUser(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

// ─── Refresh tokens ──────────────────────────────────────────

func (db *DB) CreateRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		userID, tokenHash, expiresAt)
	return err
}

func (db *DB) GetRefreshToken(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, created_at, revoked_at
		FROM refresh_tokens WHERE token_hash = $1`, tokenHash)
	rt := &models.RefreshToken{}
	err := row.Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &rt.ExpiresAt, &rt.CreatedAt, &rt.RevokedAt)
	if err != nil {
		return nil, err
	}
	return rt, nil
}

func (db *DB) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE token_hash = $1`, tokenHash)
	return err
}

// ─── Password reset tokens ───────────────────────────────────

func (db *DB) CreatePasswordResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		userID, tokenHash, expiresAt)
	return err
}

func (db *DB) GetPasswordResetToken(ctx context.Context, tokenHash string) (*models.PasswordResetToken, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, used_at, created_at
		FROM password_reset_tokens WHERE token_hash = $1`, tokenHash)
	t := &models.PasswordResetToken{}
	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (db *DB) MarkPasswordResetTokenUsed(ctx context.Context, tokenHash string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE password_reset_tokens SET used_at = now() WHERE token_hash = $1`, tokenHash)
	return err
}

// ─── Email verify tokens ─────────────────────────────────────

func (db *DB) CreateEmailVerifyToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO email_verify_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		userID, tokenHash, expiresAt)
	return err
}

func (db *DB) GetEmailVerifyToken(ctx context.Context, tokenHash string) (*models.EmailVerifyToken, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, used_at, created_at
		FROM email_verify_tokens WHERE token_hash = $1`, tokenHash)
	t := &models.EmailVerifyToken{}
	err := row.Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (db *DB) MarkEmailVerifyTokenUsed(ctx context.Context, tokenHash string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE email_verify_tokens SET used_at = now() WHERE token_hash = $1`, tokenHash)
	return err
}

// ─── OAuth linking ───────────────────────────────────────────

func (db *DB) LinkGithubAccount(ctx context.Context, userID, githubID, githubLogin string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET github_id = $1, github_login = $2, updated_at = now() WHERE id = $3`,
		githubID, githubLogin, userID)
	return err
}

func (db *DB) LinkGoogleAccount(ctx context.Context, userID, googleID string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET google_id = $1, updated_at = now() WHERE id = $2`,
		googleID, userID)
	return err
}

// ListSubscribedUsers returns all users who have an active Stripe subscription.
func (db *DB) ListSubscribedUsers(ctx context.Context) ([]*models.User, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT `+userColumns+` FROM users WHERE stripe_subscription_id IS NOT NULL AND stripe_subscription_id != '' ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*models.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// ─── Admin queries ───────────────────────────────────────────

func (db *DB) ListUsers(ctx context.Context, search, plan string, limit, offset int) ([]*models.User, int, error) {
	conditions := []string{"1=1"}
	args := []any{}
	i := 1

	if search != "" {
		conditions = append(conditions, fmt.Sprintf("(email ILIKE $%d OR name ILIKE $%d)", i, i+1))
		pattern := "%" + search + "%"
		args = append(args, pattern, pattern)
		i += 2
	}
	if plan != "" {
		conditions = append(conditions, fmt.Sprintf("plan = $%d", i))
		args = append(args, plan)
		i++
	}

	where := strings.Join(conditions, " AND ")

	// Total count.
	var total int
	if err := db.Pool.QueryRow(ctx,
		fmt.Sprintf("SELECT COUNT(*) FROM users WHERE %s", where), args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Page.
	args = append(args, limit, offset)
	rows, err := db.Pool.Query(ctx,
		fmt.Sprintf("SELECT %s FROM users WHERE %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
			userColumns, where, i, i+1), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []*models.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func (db *DB) GetAdminStats(ctx context.Context) (*models.AdminStats, error) {
	stats := &models.AdminStats{UsersByPlan: make(map[string]int)}

	// Users aggregate.
	err := db.Pool.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE email_verified),
			COUNT(*) FILTER (WHERE is_admin),
			COUNT(*) FILTER (WHERE suspended)
		FROM users`).Scan(
		&stats.TotalUsers, &stats.VerifiedUsers,
		&stats.AdminUsers, &stats.SuspendedUsers)
	if err != nil {
		return nil, err
	}

	// Tunnels aggregate.
	err = db.Pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE status = 'active') FROM tunnels`).Scan(
		&stats.TotalTunnels, &stats.ActiveTunnels)
	if err != nil {
		return nil, err
	}

	// Misc counts.
	_ = db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM organizations`).Scan(&stats.TotalOrgs)
	_ = db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_tokens WHERE revoked_at IS NULL`).Scan(&stats.TotalAPITokens)
	_ = db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM blocked_ips WHERE unblocked_at IS NULL`).Scan(&stats.TotalBlockedIPs)
	_ = db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM abuse_events`).Scan(&stats.TotalAbuseEvents)
	_ = db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM newsletter_subscribers WHERE unsubscribed_at IS NULL`).Scan(&stats.NewsletterSubs)

	// Users by plan.
	planRows, err := db.Pool.Query(ctx, `SELECT plan, COUNT(*) FROM users GROUP BY plan`)
	if err != nil {
		return nil, err
	}
	defer planRows.Close()
	for planRows.Next() {
		var p string
		var c int
		if err := planRows.Scan(&p, &c); err != nil {
			return nil, err
		}
		stats.UsersByPlan[p] = c
	}

	return stats, planRows.Err()
}

// ─── Email OTP (login second factor) ─────────────────────────

func (db *DB) EnableEmailOTP(ctx context.Context, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET email_otp_enabled = true, updated_at = now() WHERE id = $1`, userID)
	return err
}

func (db *DB) DisableEmailOTP(ctx context.Context, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET email_otp_enabled = false, updated_at = now() WHERE id = $1`, userID)
	return err
}

// CreateEmailOTPCode stores a hashed OTP code valid for 5 minutes.
// Deletes any previous unused codes for this user first.
func (db *DB) CreateEmailOTPCode(ctx context.Context, userID, codeHash string, expiresAt time.Time) error {
	if db.redis != nil {
		if ttl := time.Until(expiresAt); ttl > 0 {
			if err := db.redis.StoreEmailOTP(ctx, userID, codeHash, ttl); err == nil {
				return nil
			}
		}
	}

	_, _ = db.Pool.Exec(ctx,
		`DELETE FROM email_otp_codes WHERE user_id = $1 AND used_at IS NULL`, userID)
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO email_otp_codes (user_id, code_hash, expires_at) VALUES ($1, $2, $3)`,
		userID, codeHash, expiresAt)
	return err
}

// VerifyEmailOTPCode checks the most recent valid code for the user.
// Returns true and marks it used if valid; returns false otherwise.
func (db *DB) VerifyEmailOTPCode(ctx context.Context, userID, codeHash string) (bool, error) {
	if db.redis != nil {
		ok, err := db.redis.VerifyEmailOTP(ctx, userID, codeHash)
		if err == nil && ok {
			return true, nil
		}
		if err != nil {
			// Fall back to the database path when Redis is unavailable or transiently failing.
		}
	}

	row := db.Pool.QueryRow(ctx, `
		SELECT id FROM email_otp_codes
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL AND expires_at > now()
		ORDER BY created_at DESC LIMIT 1`,
		userID, codeHash)
	var id string
	if err := row.Scan(&id); err != nil {
		return false, nil // not found or expired
	}
	_, err := db.Pool.Exec(ctx,
		`UPDATE email_otp_codes SET used_at = now() WHERE id = $1`, id)
	return err == nil, err
}

// ─── Trial ─────────────────────────────────────────────────────

// SetTrial sets the trial_ends_at for a user. Pass nil to clear it.
func (db *DB) SetTrial(ctx context.Context, userID string, endsAt *time.Time) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET trial_ends_at = $2 WHERE id = $1`, userID, endsAt)
	return err
}

// ─── Newsletter (user preference) ─────────────────────────────

// SetNewsletterSubscribed sets newsletter_subscribed for an authenticated user.
func (db *DB) SetNewsletterSubscribed(ctx context.Context, userID string, subscribed bool) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET newsletter_subscribed = $2 WHERE id = $1`, userID, subscribed)
	return err
}

// GetUserByNewsletterToken returns the user for a given unsubscribe token.
func (db *DB) GetUserByNewsletterToken(ctx context.Context, token string) (*models.User, error) {
	row := db.Pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE newsletter_unsubscribe_token = $1`, token)
	return scanUser(row)
}

// GetNewsletterRecipients returns emails of subscribed users (for sending campaigns).
func (db *DB) GetNewsletterRecipients(ctx context.Context) ([]struct{ Email, Name string }, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT email, name FROM users WHERE newsletter_subscribed = TRUE AND email_verified = TRUE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []struct{ Email, Name string }
	for rows.Next() {
		var r struct{ Email, Name string }
		if err := rows.Scan(&r.Email, &r.Name); err == nil {
			out = append(out, r)
		}
	}
	return out, nil
}

// SaveNewsletterCampaign records a sent campaign.
func (db *DB) SaveNewsletterCampaign(ctx context.Context, subject, bodyHTML, sentBy string, count int) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO newsletter_campaigns (subject, body_html, sent_by, recipient_count)
		VALUES ($1, $2, $3, $4)`,
		subject, bodyHTML, sentBy, count)
	return err
}

// GetNewsletterCampaigns returns past campaigns (newest first).
func (db *DB) GetNewsletterCampaigns(ctx context.Context) ([]models.NewsletterCampaign, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, subject, body_html, sent_by, sent_at, recipient_count
		FROM newsletter_campaigns ORDER BY sent_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.NewsletterCampaign
	for rows.Next() {
		var c models.NewsletterCampaign
		if err := rows.Scan(&c.ID, &c.Subject, &c.BodyHTML, &c.SentBy, &c.SentAt, &c.RecipientCount); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}
