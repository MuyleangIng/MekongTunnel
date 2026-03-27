package redisx

import (
	"context"
	"time"
)

// AllowRateLimit enforces a Redis-backed fixed-window counter for a given subject.
func (c *Client) AllowRateLimit(ctx context.Context, bucket, subject string, limit int, window time.Duration) (bool, int, time.Duration, error) {
	if !c.Enabled() || limit <= 0 || window <= 0 {
		return true, limit, 0, nil
	}

	key := c.key("ratelimit", bucket, subject)
	pipe := c.raw.TxPipeline()
	countCmd := pipe.Incr(ctx, key)
	ttlCmd := pipe.PTTL(ctx, key)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return true, limit, 0, err
	}

	count := int(countCmd.Val())
	retryAfter := ttlCmd.Val()
	if retryAfter <= 0 {
		if err := c.raw.Expire(ctx, key, window).Err(); err != nil {
			return true, limit, 0, err
		}
		retryAfter = window
	}

	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}
	return count <= limit, remaining, retryAfter, nil
}
