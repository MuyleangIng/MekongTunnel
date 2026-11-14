package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Passkey is a stored WebAuthn credential. Credential holds the raw JSON of
// the go-webauthn Credential so this package does not depend on that library.
type Passkey struct {
	ID         string          `json:"id"`
	UserID     string          `json:"-"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"-"`
	CreatedAt  time.Time       `json:"created_at"`
	LastUsedAt *time.Time      `json:"last_used_at"`
}

// ErrPasskeyNotFound is returned when no passkey matches the lookup.
var ErrPasskeyNotFound = errors.New("passkey not found")

func (db *DB) CreatePasskey(ctx context.Context, userID, id, name string, credential []byte) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO passkeys (id, user_id, name, credential) VALUES ($1, $2, $3, $4)`,
		id, userID, name, credential)
	return err
}

func (db *DB) ListPasskeys(ctx context.Context, userID string) ([]Passkey, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, name, credential, created_at, last_used_at
		FROM passkeys WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Passkey{}
	for rows.Next() {
		var p Passkey
		if err := rows.Scan(&p.ID, &p.UserID, &p.Name, &p.Credential, &p.CreatedAt, &p.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdatePasskeyAfterLogin stores the refreshed credential (new sign counter)
// and records when it was last used.
func (db *DB) UpdatePasskeyAfterLogin(ctx context.Context, id string, credential []byte) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE passkeys SET credential = $2, last_used_at = now() WHERE id = $1`,
		id, credential)
	return err
}

func (db *DB) RenamePasskey(ctx context.Context, userID, id, name string) error {
	tag, err := db.Pool.Exec(ctx,
		`UPDATE passkeys SET name = $3 WHERE id = $1 AND user_id = $2`, id, userID, name)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPasskeyNotFound
	}
	return nil
}

func (db *DB) DeletePasskey(ctx context.Context, userID, id string) error {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM passkeys WHERE id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrPasskeyNotFound
	}
	return nil
}

// PasskeyOwner returns the user ID that owns a credential ID.
func (db *DB) PasskeyOwner(ctx context.Context, id string) (string, error) {
	var userID string
	err := db.Pool.QueryRow(ctx, `SELECT user_id FROM passkeys WHERE id = $1`, id).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrPasskeyNotFound
	}
	return userID, err
}
