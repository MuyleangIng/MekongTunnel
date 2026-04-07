package telegrambot

// Update is the top-level Telegram webhook update object.
type Update struct {
	UpdateID int64    `json:"update_id"`
	Message  *Message `json:"message,omitempty"`
}

// Message is a Telegram message object (subset of fields we use).
type Message struct {
	MessageID int64    `json:"message_id"`
	From      *User    `json:"from,omitempty"`
	Chat      Chat     `json:"chat"`
	Text      string   `json:"text,omitempty"`
	Date      int64    `json:"date"`
}

// User is the Telegram user/bot sender.
type User struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name,omitempty"`
	Username  string `json:"username,omitempty"`
}

// Chat is the Telegram chat descriptor.
type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"` // "private", "group", "supergroup", "channel"
}
