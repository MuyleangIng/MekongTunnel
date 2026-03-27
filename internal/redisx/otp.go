package redisx

import (
	"context"
	"time"
)

// StoreEmailOTP stores the latest valid OTP hash for a user in Redis.
func (c *Client) StoreEmailOTP(ctx context.Context, userID, codeHash string, ttl time.Duration) error {
	if !c.Enabled() {
		return nil
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	currentKey := c.key("otp", "email", "current", userID)
	previousHash, ok, err := c.getString(ctx, currentKey)
	if err != nil {
		return err
	}
	if ok && previousHash != "" {
		_ = c.delete(ctx, c.key("otp", "email", "code", userID, previousHash))
	}

	otpKey := c.key("otp", "email", "code", userID, codeHash)
	pipe := c.raw.TxPipeline()
	pipe.Set(ctx, otpKey, "1", ttl)
	pipe.Set(ctx, currentKey, codeHash, ttl)
	_, err = pipe.Exec(ctx)
	return err
}

// VerifyEmailOTP validates and consumes an OTP hash for a user.
func (c *Client) VerifyEmailOTP(ctx context.Context, userID, codeHash string) (bool, error) {
	if !c.Enabled() {
		return false, nil
	}

	otpKey := c.key("otp", "email", "code", userID, codeHash)
	deleted, err := c.raw.Del(ctx, otpKey).Result()
	if err != nil {
		return false, err
	}
	if deleted == 0 {
		return false, nil
	}

	_ = c.delete(ctx, c.key("otp", "email", "current", userID))
	return true, nil
}
