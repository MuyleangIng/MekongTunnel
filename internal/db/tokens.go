package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

// CreateAPIToken inserts a new API token record and returns it.
func (db *DB) CreateAPIToken(ctx context.Context, userID, name, tokenHash, prefix string) (*models.ApiToken, error) {
	row := db.Pool.QueryRow(ctx, `
		INSERT INTO api_tokens (user_id, name, token_hash, prefix)
		VALUES ($1, $2, $3, $4)
		RETURNING id, user_id, name, token_hash, prefix, last_used_at, revoked_at, created_at`,
		userID, name, tokenHash, prefix)

	t := &models.ApiToken{}
	err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.Prefix,
		&t.LastUsedAt, &t.RevokedAt, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// GetAPITokenByHash looks up an active (non-revoked) API token by its SHA-256 hash.
func (db *DB) GetAPITokenByHash(ctx context.Context, hash string) (*models.ApiToken, error) {
	row := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, name, token_hash, prefix, last_used_at, revoked_at, created_at
		FROM api_tokens
		WHERE token_hash = $1 AND revoked_at IS NULL`, hash)

	t := &models.ApiToken{}
	err := row.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.Prefix,
		&t.LastUsedAt, &t.RevokedAt, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// ListAPITokens returns all non-revoked tokens for a user, newest first.
func (db *DB) ListAPITokens(ctx context.Context, userID string) ([]*models.ApiToken, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, name, token_hash, prefix, last_used_at, revoked_at, created_at
		FROM api_tokens
		WHERE user_id = $1 AND revoked_at IS NULL
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*models.ApiToken
	for rows.Next() {
		t := &models.ApiToken{}
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.TokenHash, &t.Prefix,
			&t.LastUsedAt, &t.RevokedAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// RevokeAPIToken marks a token as revoked, validating ownership.
func (db *DB) RevokeAPIToken(ctx context.Context, id, userID string) error {
	now := time.Now()
	_, err := db.Pool.Exec(ctx,
		`UPDATE api_tokens SET revoked_at = $1 WHERE id = $2 AND user_id = $3`,
		now, id, userID)
	return err
}

// UpdateAPITokenLastUsed updates the last_used_at timestamp for a token.
func (db *DB) UpdateAPITokenLastUsed(ctx context.Context, id string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE api_tokens SET last_used_at = now() WHERE id = $1`, id)
	return err
}

// ValidateToken hashes rawToken with SHA-256 and looks it up in api_tokens.
// Returns the owning userID on success, or an error if not found / revoked.
// Implements proxy.TokenValidator.
func (db *DB) ValidateToken(ctx context.Context, rawToken string) (string, error) {
	h := sha256.Sum256([]byte(rawToken))
	hash := hex.EncodeToString(h[:])
	tok, err := db.GetAPITokenByHash(ctx, hash)
	if err != nil {
		return "", fmt.Errorf("invalid or revoked token")
	}
	// Update last_used_at asynchronously — don't block the SSH handshake.
	go func() { _ = db.UpdateAPITokenLastUsed(context.Background(), tok.ID) }()
	return tok.UserID, nil
}

// GetFirstReservedSubdomain returns the first active reserved subdomain for userID,
// or "" if the user has none. Implements proxy.TokenValidator.
func (db *DB) GetFirstReservedSubdomain(ctx context.Context, userID string) (string, error) {
	var sub string
	err := db.Pool.QueryRow(ctx,
		`SELECT subdomain FROM reserved_subdomains WHERE user_id = $1 ORDER BY created_at ASC LIMIT 1`,
		userID,
	).Scan(&sub)
	if err != nil {
		return "", nil // no reserved subdomain — not an error, just use random
	}
	return sub, nil
}
