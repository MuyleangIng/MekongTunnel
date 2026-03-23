package db

import (
	"context"
)

// SubscribeNewsletter adds an email to the newsletter_subscribers table.
// If the email is already subscribed (and hasn't unsubscribed), it is a no-op.
// If the email previously unsubscribed, it re-subscribes.
func (db *DB) SubscribeNewsletter(ctx context.Context, email string) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO newsletter_subscribers (email)
		VALUES ($1)
		ON CONFLICT (email) DO UPDATE SET unsubscribed_at = NULL`,
		email)
	return err
}

// UnsubscribeNewsletter marks an email as unsubscribed.
func (db *DB) UnsubscribeNewsletter(ctx context.Context, email string) error {
	_, err := db.Pool.Exec(ctx, `
		UPDATE newsletter_subscribers SET unsubscribed_at = now()
		WHERE email = $1 AND unsubscribed_at IS NULL`,
		email)
	return err
}
