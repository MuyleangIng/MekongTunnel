package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const apiTokenPrefix = "mkt_"

// GenerateAPIToken creates a new API token.
//
// Returns:
//   - fullToken  — the complete token to display to the user once (mkt_ + 32 hex chars)
//   - prefix     — first 10 chars of fullToken, safe to store for display
//   - hash       — SHA-256 hex of fullToken, stored in the database
//   - err
func GenerateAPIToken() (fullToken, prefix, hash string, err error) {
	b := make([]byte, 16) // 32 hex chars
	if _, err = rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate api token: %w", err)
	}
	fullToken = apiTokenPrefix + hex.EncodeToString(b)
	prefix = fullToken[:10]
	hash = HashToken(fullToken)
	return fullToken, prefix, hash, nil
}
