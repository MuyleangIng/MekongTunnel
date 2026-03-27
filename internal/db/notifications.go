package db

import (
	"context"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

func (db *DB) CreateNotification(ctx context.Context, userID, notifType, title, body, link string) (*models.Notification, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO notifications (user_id, type, title, body, link)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, user_id, type, title, body, link, read_at, created_at`,
		userID, notifType, title, body, link)
	return scanNotification(row)
}

func (db *DB) GetAdminIDs(ctx context.Context) ([]string, error) {
	rows, err := db.Pool.Query(ctx, `SELECT id FROM users WHERE is_admin = true AND suspended = false`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (db *DB) ListNotifications(ctx context.Context, userID string, limit, offset int) ([]*models.Notification, int, int, error) {
	var total, unread int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE read_at IS NULL) FROM notifications WHERE user_id = $1`, userID).
		Scan(&total, &unread); err != nil {
		return nil, 0, 0, err
	}

	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, type, title, body, link, read_at, created_at
		FROM notifications WHERE user_id = $1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		userID, limit, offset)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()
	var notifs []*models.Notification
	for rows.Next() {
		n, err := scanNotification(rows)
		if err != nil {
			return nil, 0, 0, err
		}
		notifs = append(notifs, n)
	}
	return notifs, total, unread, rows.Err()
}

func (db *DB) CountNotifications(ctx context.Context, userID string) (int, int, error) {
	var total, unread int
	if err := db.Pool.QueryRow(ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE read_at IS NULL) FROM notifications WHERE user_id = $1`, userID).
		Scan(&total, &unread); err != nil {
		return 0, 0, err
	}
	return total, unread, nil
}

func (db *DB) CountUnreadNotifications(ctx context.Context, userID string) (int, error) {
	_, unread, err := db.CountNotifications(ctx, userID)
	return unread, err
}

func (db *DB) MarkNotificationRead(ctx context.Context, id, userID string) (int, error) {
	var unread int
	err := db.Pool.QueryRow(ctx, `
		WITH updated AS (
			UPDATE notifications
			SET read_at = $1
			WHERE id = $2 AND user_id = $3 AND read_at IS NULL
			RETURNING 1
		)
		SELECT COUNT(*) FROM notifications WHERE user_id = $3 AND read_at IS NULL`,
		time.Now(), id, userID).Scan(&unread)
	return unread, err
}

func (db *DB) MarkAllNotificationsRead(ctx context.Context, userID string) (int, error) {
	var unread int
	err := db.Pool.QueryRow(ctx, `
		WITH updated AS (
			UPDATE notifications
			SET read_at = $1
			WHERE user_id = $2 AND read_at IS NULL
			RETURNING 1
		)
		SELECT COUNT(*) FROM notifications WHERE user_id = $2 AND read_at IS NULL`,
		time.Now(), userID).Scan(&unread)
	return unread, err
}

func (db *DB) DeleteNotification(ctx context.Context, id, userID string) (int, error) {
	var unread int
	err := db.Pool.QueryRow(ctx, `
		WITH deleted AS (
			DELETE FROM notifications WHERE id = $1 AND user_id = $2
			RETURNING 1
		)
		SELECT COUNT(*) FROM notifications WHERE user_id = $2 AND read_at IS NULL`,
		id, userID).Scan(&unread)
	return unread, err
}

func (db *DB) DeleteAllNotifications(ctx context.Context, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM notifications WHERE user_id = $1`, userID)
	return err
}

func scanNotification(row interface{ Scan(...any) error }) (*models.Notification, error) {
	n := &models.Notification{}
	err := row.Scan(&n.ID, &n.UserID, &n.Type, &n.Title, &n.Body, &n.Link, &n.ReadAt, &n.CreatedAt)
	if err != nil {
		return nil, err
	}
	return n, nil
}
