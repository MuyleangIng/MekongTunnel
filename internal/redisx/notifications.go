package redisx

import (
	"context"
	"encoding/json"
)

type notificationEnvelope struct {
	UserID  string          `json:"user_id"`
	Payload json.RawMessage `json:"payload"`
}

// PublishNotification fan-outs a notification to every API instance subscribed to Redis.
func (c *Client) PublishNotification(ctx context.Context, userID string, payload []byte) error {
	if !c.Enabled() {
		return nil
	}
	msg, err := json.Marshal(notificationEnvelope{
		UserID:  userID,
		Payload: append([]byte(nil), payload...),
	})
	if err != nil {
		return err
	}
	return c.raw.Publish(ctx, c.notificationChannelKey(), msg).Err()
}

// SubscribeNotifications listens for notification events and forwards them to the handler.
func (c *Client) SubscribeNotifications(ctx context.Context, handler func(userID string, payload []byte)) error {
	if !c.Enabled() || handler == nil {
		return nil
	}

	pubsub := c.raw.Subscribe(ctx, c.notificationChannelKey())
	defer pubsub.Close()

	if _, err := pubsub.Receive(ctx); err != nil {
		return err
	}

	for {
		msg, err := pubsub.ReceiveMessage(ctx)
		if err != nil {
			return err
		}

		var env notificationEnvelope
		if err := json.Unmarshal([]byte(msg.Payload), &env); err != nil {
			continue
		}
		handler(env.UserID, env.Payload)
	}
}
