// Package auth provides authentication helpers for MekongTunnel.
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package auth

import (
	"errors"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims carries user identity in a JWT.
type JWTClaims struct {
	UserID  string `json:"uid"`
	Email   string `json:"email"`
	Plan    string `json:"plan"`
	IsAdmin bool   `json:"admin"`
	// temp_2fa marks a short-lived token used only to complete 2FA verification.
	Temp2FA bool `json:"temp_2fa,omitempty"`
	jwt.RegisteredClaims
}

// GenerateAccessToken creates a 15-minute signed JWT for the given user.
func GenerateAccessToken(user *models.User, secret string) (string, error) {
	claims := JWTClaims{
		UserID:  user.ID,
		Email:   user.Email,
		Plan:    user.Plan,
		IsAdmin: user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			Issuer:    "mekongtunnel",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// GenerateRefreshToken creates a 30-day signed JWT for the given user ID.
func GenerateRefreshToken(userID string, secret string) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
			Issuer:    "mekongtunnel-refresh",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// GenerateTemp2FAToken creates a 5-minute JWT used only to complete TOTP verification.
func GenerateTemp2FAToken(userID, email, secret string) (string, error) {
	claims := JWTClaims{
		UserID:  userID,
		Email:   email,
		Temp2FA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			Issuer:    "mekongtunnel-2fa",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateToken parses and validates a JWT string, returning its claims.
func ValidateToken(tokenStr, secret string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &JWTClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}
