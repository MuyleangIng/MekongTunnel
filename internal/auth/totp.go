package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// GenerateTOTPSecret creates a new TOTP secret for accountName/issuer.
// Returns the raw secret, the otpauth:// URL, and the QR code as a base64-encoded PNG.
func GenerateTOTPSecret(accountName, issuer string) (secret, otpauthURL, qrCodeBase64 string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", "", fmt.Errorf("generate totp key: %w", err)
	}

	secret = key.Secret()
	otpauthURL = key.URL()

	// Generate QR code as PNG bytes, then base64-encode.
	// High error correction + 300px = reliable scanning from all authenticator apps.
	var buf bytes.Buffer
	png, err := qrcode.Encode(otpauthURL, qrcode.High, 300)
	if err != nil {
		return "", "", "", fmt.Errorf("generate qr code: %w", err)
	}
	buf.Write(png)
	qrCodeBase64 = base64.StdEncoding.EncodeToString(buf.Bytes())

	return secret, otpauthURL, qrCodeBase64, nil
}

// ValidateTOTP checks whether code is a valid TOTP token for secret.
func ValidateTOTP(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateBackupCodes generates count random single-use backup codes.
// Returns (plain codes, hashed codes, error).
func GenerateBackupCodes(count int) ([]string, []string, error) {
	plains := make([]string, count)
	hashes := make([]string, count)
	for i := 0; i < count; i++ {
		b := make([]byte, 5) // 10 hex chars → easy to type as XXXXX-XXXXX
		if _, err := rand.Read(b); err != nil {
			return nil, nil, fmt.Errorf("generate backup code: %w", err)
		}
		plain := hex.EncodeToString(b)
		plains[i] = fmt.Sprintf("%s-%s", plain[:5], plain[5:])
		hashes[i] = HashToken(plains[i])
	}
	return plains, hashes, nil
}
