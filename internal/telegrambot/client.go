// Package telegrambot implements the Telegram bot integration for MekongTunnel.
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package telegrambot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const telegramAPIBase = "https://api.telegram.org/bot"

// Client sends messages to Telegram via the Bot API.
type Client struct {
	token      string
	httpClient *http.Client
}

// NewClient creates a new Telegram bot HTTP client.
func NewClient(token string) *Client {
	return &Client{
		token: token,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type sendMessagePayload struct {
	ChatID    int64  `json:"chat_id"`
	Text      string `json:"text"`
	ParseMode string `json:"parse_mode,omitempty"`
}

// SendMessage sends a plain or Markdown text message to a Telegram chat.
func (c *Client) SendMessage(chatID int64, text string) error {
	return c.sendMessage(chatID, text, "")
}

// SendMarkdown sends a Markdown-formatted message.
func (c *Client) SendMarkdown(chatID int64, text string) error {
	return c.sendMessage(chatID, text, "Markdown")
}

func (c *Client) sendMessage(chatID int64, text, parseMode string) error {
	payload := sendMessagePayload{
		ChatID:    chatID,
		Text:      text,
		ParseMode: parseMode,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s%s/sendMessage", telegramAPIBase, c.token)
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram sendMessage: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram sendMessage: status %d", resp.StatusCode)
	}
	return nil
}

// SetWebhook registers the webhook URL with Telegram.
func (c *Client) SetWebhook(webhookURL, secretToken string) error {
	payload := map[string]any{
		"url":          webhookURL,
		"secret_token": secretToken,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s%s/setWebhook", telegramAPIBase, c.token)
	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram setWebhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram setWebhook: status %d", resp.StatusCode)
	}
	return nil
}
