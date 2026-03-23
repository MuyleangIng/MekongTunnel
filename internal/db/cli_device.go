package db

import (
	"context"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// CreateDeviceSession inserts a new CLI device session that expires in 15 minutes.
func (db *DB) CreateDeviceSession(ctx context.Context) (*models.CLIDeviceSession, error) {
	expires := time.Now().Add(15 * time.Minute)
	row := db.Pool.QueryRow(ctx,
		`INSERT INTO cli_device_sessions (expires_at)
		 VALUES ($1)
		 RETURNING id, expires_at, created_at`,
		expires)

	s := &models.CLIDeviceSession{}
	err := row.Scan(&s.ID, &s.ExpiresAt, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// GetDeviceSession returns the session by ID regardless of approval state.
func (db *DB) GetDeviceSession(ctx context.Context, id string) (*models.CLIDeviceSession, error) {
	row := db.Pool.QueryRow(ctx,
		`SELECT id, COALESCE(user_id::text,''), COALESCE(token_hash,''), COALESCE(token_prefix,''),
		        COALESCE(raw_token,''), approved_at, expires_at, created_at
		 FROM cli_device_sessions WHERE id = $1`, id)

	s := &models.CLIDeviceSession{}
	err := row.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.TokenPrefix,
		&s.RawToken, &s.ApprovedAt, &s.ExpiresAt, &s.CreatedAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ApproveDeviceSession records the generated API token and marks the session approved.
// rawToken is stored temporarily so the CLI can retrieve it exactly once.
func (db *DB) ApproveDeviceSession(ctx context.Context, sessionID, userID, rawToken, tokenPrefix, tokenHash string) error {
	now := time.Now()
	_, err := db.Pool.Exec(ctx,
		`UPDATE cli_device_sessions
		 SET user_id = $1, raw_token = $2, token_prefix = $3, token_hash = $4, approved_at = $5
		 WHERE id = $6 AND approved_at IS NULL AND expires_at > now()`,
		userID, rawToken, tokenPrefix, tokenHash, now, sessionID)
	return err
}

// ConsumeDeviceToken returns the raw token once and clears it from the DB
// so it is unreadable on subsequent polls (the CLI stores it locally).
//
// Uses a transaction with FOR UPDATE so the SELECT reads the value BEFORE
// the UPDATE clears it. PostgreSQL RETURNING returns post-update values,
// so a plain UPDATE … SET raw_token='' RETURNING raw_token would always
// return '' — this transaction approach avoids that.
func (db *DB) ConsumeDeviceToken(ctx context.Context, sessionID string) (string, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	// Read the current token, locking the row.
	var raw string
	err = tx.QueryRow(ctx,
		`SELECT raw_token FROM cli_device_sessions
		 WHERE id = $1 AND raw_token != '' AND approved_at IS NOT NULL
		 FOR UPDATE`, sessionID).Scan(&raw)
	if err != nil {
		return "", err // not found or already consumed
	}

	// Clear it so subsequent polls return no token.
	if _, err = tx.Exec(ctx,
		`UPDATE cli_device_sessions SET raw_token = '' WHERE id = $1`, sessionID); err != nil {
		return "", err
	}

	return raw, tx.Commit(ctx)
}

// DeleteExpiredDeviceSessions removes sessions older than their expiry.
func (db *DB) DeleteExpiredDeviceSessions(ctx context.Context) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM cli_device_sessions WHERE expires_at < now()`)
	return err
}
