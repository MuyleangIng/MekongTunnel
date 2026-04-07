package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
	"github.com/jackc/pgx/v5"
)

// ── Telegram link sessions ─────────────────────────────────────

// CreateTelegramLinkSession creates a short-lived session (10 min TTL) for browser approval.
func (db *DB) CreateTelegramLinkSession(ctx context.Context, chatID, userID int64, username, firstName, lastName string) (*models.TelegramLinkSession, error) {
	code, err := randomHex(24)
	if err != nil {
		return nil, err
	}

	expires := time.Now().Add(10 * time.Minute)
	s := &models.TelegramLinkSession{}
	row := db.Pool.QueryRow(ctx,
		`INSERT INTO telegram_link_sessions
		 (code, telegram_chat_id, telegram_user_id, telegram_username, telegram_first_name, telegram_last_name, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING id, code, telegram_chat_id, telegram_user_id,
		           COALESCE(telegram_username,''), COALESCE(telegram_first_name,''), COALESCE(telegram_last_name,''),
		           status, created_at, expires_at`,
		code, chatID, userID, nullableStr(username), nullableStr(firstName), nullableStr(lastName), expires,
	)
	err = row.Scan(&s.ID, &s.Code, &s.TelegramChatID, &s.TelegramUserID,
		&s.TelegramUsername, &s.TelegramFirstName, &s.TelegramLastName,
		&s.Status, &s.CreatedAt, &s.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// GetTelegramLinkSessionByCode returns a session by its approval code.
func (db *DB) GetTelegramLinkSessionByCode(ctx context.Context, code string) (*models.TelegramLinkSession, error) {
	s := &models.TelegramLinkSession{}
	row := db.Pool.QueryRow(ctx,
		`SELECT id, code, telegram_chat_id, telegram_user_id,
		        COALESCE(telegram_username,''), COALESCE(telegram_first_name,''), COALESCE(telegram_last_name,''),
		        status, approved_user_id, created_at, expires_at, approved_at, cancelled_at
		 FROM telegram_link_sessions WHERE code = $1`, code)
	err := row.Scan(&s.ID, &s.Code, &s.TelegramChatID, &s.TelegramUserID,
		&s.TelegramUsername, &s.TelegramFirstName, &s.TelegramLastName,
		&s.Status, &s.ApprovedUserID, &s.CreatedAt, &s.ExpiresAt, &s.ApprovedAt, &s.CancelledAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ApproveTelegramLinkSession marks the session approved, revokes any prior link for the
// same user or chat, then upserts a new telegram_links row.
func (db *DB) ApproveTelegramLinkSession(ctx context.Context, code, userID string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	now := time.Now()

	// Fetch session.
	s := &models.TelegramLinkSession{}
	row := tx.QueryRow(ctx,
		`SELECT id, telegram_chat_id, telegram_user_id,
		        COALESCE(telegram_username,''), COALESCE(telegram_first_name,''), COALESCE(telegram_last_name,''),
		        status, expires_at
		 FROM telegram_link_sessions WHERE code = $1 FOR UPDATE`, code)
	err = row.Scan(&s.ID, &s.TelegramChatID, &s.TelegramUserID,
		&s.TelegramUsername, &s.TelegramFirstName, &s.TelegramLastName,
		&s.Status, &s.ExpiresAt)
	if err != nil {
		return err
	}
	if s.Status != "pending" {
		return errorf("session is not pending")
	}
	if s.ExpiresAt.Before(now) {
		return errorf("session expired")
	}

	// Revoke any prior active link for this chat or this user.
	if _, err := tx.Exec(ctx,
		`UPDATE telegram_links SET status='revoked', unlinked_at=$1
		 WHERE (user_id=$2 OR telegram_chat_id=$3) AND status='active'`,
		now, userID, s.TelegramChatID); err != nil {
		return err
	}

	// Insert new link.
	if _, err := tx.Exec(ctx,
		`INSERT INTO telegram_links
		 (user_id, telegram_chat_id, telegram_user_id, telegram_username, telegram_first_name, telegram_last_name)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		userID, s.TelegramChatID, s.TelegramUserID,
		nullableStr(s.TelegramUsername), nullableStr(s.TelegramFirstName), nullableStr(s.TelegramLastName)); err != nil {
		return err
	}

	// Mark session approved.
	if _, err := tx.Exec(ctx,
		`UPDATE telegram_link_sessions SET status='approved', approved_user_id=$1, approved_at=$2 WHERE id=$3`,
		userID, now, s.ID); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// CancelTelegramLinkSession marks a pending session as cancelled.
func (db *DB) CancelTelegramLinkSession(ctx context.Context, code string) error {
	tag, err := db.Pool.Exec(ctx,
		`UPDATE telegram_link_sessions SET status='cancelled', cancelled_at=now()
		 WHERE code=$1 AND status='pending'`, code)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ── Telegram links ─────────────────────────────────────────────

// GetTelegramLinkByChatID returns the active link for a Telegram chat, or nil.
func (db *DB) GetTelegramLinkByChatID(ctx context.Context, chatID int64) (*models.TelegramLink, error) {
	l := &models.TelegramLink{}
	row := db.Pool.QueryRow(ctx,
		`SELECT id, user_id, telegram_chat_id, telegram_user_id,
		        COALESCE(telegram_username,''), COALESCE(telegram_first_name,''), COALESCE(telegram_last_name,''),
		        status, linked_at, last_seen_at, unlinked_at
		 FROM telegram_links WHERE telegram_chat_id=$1 AND status='active' LIMIT 1`, chatID)
	err := row.Scan(&l.ID, &l.UserID, &l.TelegramChatID, &l.TelegramUserID,
		&l.TelegramUsername, &l.TelegramFirstName, &l.TelegramLastName,
		&l.Status, &l.LinkedAt, &l.LastSeenAt, &l.UnlinkedAt)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// GetTelegramLinkByUserID returns the active link for a user, or nil.
func (db *DB) GetTelegramLinkByUserID(ctx context.Context, userID string) (*models.TelegramLink, error) {
	l := &models.TelegramLink{}
	row := db.Pool.QueryRow(ctx,
		`SELECT id, user_id, telegram_chat_id, telegram_user_id,
		        COALESCE(telegram_username,''), COALESCE(telegram_first_name,''), COALESCE(telegram_last_name,''),
		        status, linked_at, last_seen_at, unlinked_at
		 FROM telegram_links WHERE user_id=$1 AND status='active' LIMIT 1`, userID)
	err := row.Scan(&l.ID, &l.UserID, &l.TelegramChatID, &l.TelegramUserID,
		&l.TelegramUsername, &l.TelegramFirstName, &l.TelegramLastName,
		&l.Status, &l.LinkedAt, &l.LastSeenAt, &l.UnlinkedAt)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// RevokeTelegramLinkByUserID sets the link status to revoked (web-side unlink).
func (db *DB) RevokeTelegramLinkByUserID(ctx context.Context, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE telegram_links SET status='revoked', unlinked_at=now()
		 WHERE user_id=$1 AND status='active'`, userID)
	return err
}

// TouchTelegramLink updates last_seen_at for activity tracking.
func (db *DB) TouchTelegramLink(ctx context.Context, chatID int64) {
	_, _ = db.Pool.Exec(ctx,
		`UPDATE telegram_links SET last_seen_at=now() WHERE telegram_chat_id=$1 AND status='active'`, chatID)
}

// ── helpers ────────────────────────────────────────────────────

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func nullableStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func errorf(msg string) error {
	return &dbError{msg}
}

type dbError struct{ msg string }

func (e *dbError) Error() string { return e.msg }
