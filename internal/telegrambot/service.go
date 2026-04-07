package telegrambot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
	"github.com/jackc/pgx/v5"
)

// Config holds the Telegram bot configuration read from environment.
type Config struct {
	BotToken        string
	WebhookSecret   string
	BotUsername     string
	BotName         string
	FrontendURL     string
	ApprovePath     string // e.g. "/telegram-link"
	TunnelServerURL string
	Enabled         bool
}

// Service ties together the DB, HTTP client, and command router.
type Service struct {
	cfg        Config
	db         *db.DB
	client     *Client
	httpClient *http.Client
}

// New creates and returns a Service. Call RegisterWebhook separately after startup if needed.
func New(cfg Config, database *db.DB) *Service {
	return &Service{
		cfg:        cfg,
		db:         database,
		client:     NewClient(cfg.BotToken),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// HandleWebhook processes a single Telegram Update delivered via webhook.
// It verifies the secret header, parses the update, and dispatches to the router.
func (s *Service) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// Verify Telegram secret token header.
	if s.cfg.WebhookSecret != "" {
		if r.Header.Get("X-Telegram-Bot-Api-Secret-Token") != s.cfg.WebhookSecret {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var update Update
	if err := json.Unmarshal(body, &update); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Accept only private chats for MVP.
	if update.Message == nil || update.Message.Chat.Type != "private" {
		w.WriteHeader(http.StatusOK)
		return
	}

	go func(upd Update) {
		// The webhook request returns immediately, so its context is canceled
		// before command handlers finish any DB or HTTP work.
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.dispatch(ctx, &upd)
	}(update)
	w.WriteHeader(http.StatusOK)
}

// dispatch routes a single message to the appropriate command handler.
func (s *Service) dispatch(ctx context.Context, update *Update) {
	msg := update.Message
	if msg == nil || msg.From == nil {
		return
	}

	chatID := msg.Chat.ID
	text := strings.TrimSpace(msg.Text)

	// Touch last_seen_at for linked users.
	go s.db.TouchTelegramLink(ctx, chatID)

	cmd, arg := parseCommand(text)
	switch cmd {
	case "/start":
		s.handleStart(ctx, chatID, msg.From, arg)
	case "/help":
		s.handleHelp(ctx, chatID)
	case "/link":
		s.handleLink(ctx, chatID, msg.From)
	case "/me":
		s.handleMe(ctx, chatID)
	case "/services":
		s.handleServices(ctx, chatID)
	case "/logs":
		s.handleLogs(ctx, chatID, arg)
	case "/subdomains":
		s.handleSubdomains(ctx, chatID)
	case "/domains":
		s.handleDomains(ctx, chatID)
	case "/domain":
		s.handleDomain(ctx, chatID, arg)
	case "/unlink":
		s.handleUnlink(ctx, chatID)
	default:
		s.send(chatID, "Unknown command. Use /help to see what I can do.")
	}
}

// ── command handlers ─────────────────────────────────────────

func (s *Service) handleStart(ctx context.Context, chatID int64, from *User, arg string) {
	if strings.EqualFold(arg, "link") {
		s.handleLink(ctx, chatID, from)
		return
	}

	link, err := s.activeLink(ctx, chatID)
	if err != nil {
		log.Printf("[telegrambot] load link: %v", err)
		s.send(chatID, "Failed to check your link status. Please try again.")
		return
	}
	if link != nil {
		user, err := s.db.GetUserByID(ctx, link.UserID)
		if err == nil && user != nil && user.Suspended {
			s.send(chatID, suspendedAccountMsg)
			return
		}
		s.send(chatID, "Welcome back! Your Mekong account is linked.\n\nUse /help to see available commands.")
		return
	}
	s.send(chatID, fmt.Sprintf(
		"Hi %s! 👋\n\nLink your Mekong account to view active tunnels, logs, subdomains, and domain status.\n\nUse /link to begin.",
		from.FirstName,
	))
}

func (s *Service) handleHelp(ctx context.Context, chatID int64) {
	s.send(chatID, helpText)
}

func (s *Service) handleLink(ctx context.Context, chatID int64, from *User) {
	// Check if already linked.
	existing, err := s.activeLink(ctx, chatID)
	if err != nil {
		log.Printf("[telegrambot] load link: %v", err)
		s.send(chatID, "Failed to check your link status. Please try again.")
		return
	}
	if existing != nil {
		s.send(chatID, "Your Telegram account is already linked to a Mekong account.\n\nUse /unlink first if you want to re-link.")
		return
	}

	sess, err := s.db.CreateTelegramLinkSession(ctx, chatID, from.ID, from.Username, from.FirstName, from.LastName)
	if err != nil {
		log.Printf("[telegrambot] create link session: %v", err)
		s.send(chatID, "Failed to create link session. Please try again.")
		return
	}

	approvePath := s.cfg.ApprovePath
	if approvePath == "" {
		approvePath = "/telegram-link"
	}
	approveURL := joinURLPath(s.cfg.FrontendURL, approvePath) + "?code=" + url.QueryEscape(sess.Code)

	s.send(chatID, fmt.Sprintf(
		"Open the link below to connect your Mekong account:\n\n%s\n\nThis link expires in 10 minutes.",
		approveURL,
	))
}

func (s *Service) handleMe(ctx context.Context, chatID int64) {
	_, user, ok := s.requireLinkedUser(ctx, chatID)
	if !ok {
		return
	}

	s.sendMarkdown(chatID, FormatUser(user))
}

func (s *Service) handleServices(ctx context.Context, chatID int64) {
	link, _, ok := s.requireLinkedUser(ctx, chatID)
	if !ok {
		return
	}

	tunnels, err := s.db.ListTunnelsByUser(ctx, link.UserID, "active")
	if err != nil {
		s.send(chatID, "Failed to fetch tunnels.")
		return
	}

	s.sendMarkdown(chatID, FormatTunnels(tunnels))
}

func (s *Service) handleLogs(ctx context.Context, chatID int64, arg string) {
	link, _, ok := s.requireLinkedUser(ctx, chatID)
	if !ok {
		return
	}
	if arg == "" {
		s.send(chatID, "Usage: /logs <subdomain-or-id>")
		return
	}

	// Find the tunnel by subdomain in the user's history.
	tunnels, err := s.db.ListTunnelsByUser(ctx, link.UserID, "")
	if err != nil {
		s.send(chatID, "Failed to fetch tunnels.")
		return
	}

	var tunnelID string
	for _, t := range tunnels {
		if t.Subdomain == arg || t.ID == arg {
			if t.Status != string(models.TunnelActive) {
				s.send(chatID, "Recent logs are only available while the tunnel is active.")
				return
			}
			tunnelID = t.ID
			arg = t.Subdomain
			break
		}
	}
	if tunnelID == "" {
		s.send(chatID, fmt.Sprintf("No tunnel found for: %s", arg))
		return
	}

	lines, err := s.recentLogs(ctx, arg, 20)
	if err != nil {
		log.Printf("[telegrambot] recent logs for %s (%s): %v", arg, tunnelID, err)
		s.send(chatID, "Failed to fetch recent logs.")
		return
	}
	if len(lines) == 0 {
		s.send(chatID, fmt.Sprintf("No recent logs are available for `%s` right now.", arg))
		return
	}

	s.send(chatID, FormatLogsPlain(lines, arg))
}

func (s *Service) handleSubdomains(ctx context.Context, chatID int64) {
	link, _, ok := s.requireLinkedUser(ctx, chatID)
	if !ok {
		return
	}

	subs, err := s.db.ListReservedSubdomains(ctx, link.UserID)
	if err != nil {
		s.send(chatID, "Failed to fetch subdomains.")
		return
	}

	s.sendMarkdown(chatID, FormatSubdomains(subs))
}

func (s *Service) handleDomains(ctx context.Context, chatID int64) {
	link, _, ok := s.requireLinkedUser(ctx, chatID)
	if !ok {
		return
	}

	domains, err := s.db.ListCustomDomains(ctx, link.UserID)
	if err != nil {
		s.send(chatID, "Failed to fetch domains.")
		return
	}

	s.sendMarkdown(chatID, FormatDomains(domains))
}

func (s *Service) handleDomain(ctx context.Context, chatID int64, host string) {
	link, _, ok := s.requireLinkedUser(ctx, chatID)
	if !ok {
		return
	}
	if host == "" {
		s.send(chatID, "Usage: /domain <hostname>")
		return
	}

	domains, err := s.db.ListCustomDomains(ctx, link.UserID)
	if err != nil {
		s.send(chatID, "Failed to fetch domains.")
		return
	}

	for _, d := range domains {
		if d.Domain == host {
			s.sendMarkdown(chatID, FormatDomain(d))
			return
		}
	}
	s.send(chatID, fmt.Sprintf("Domain not found: %s", host))
}

func (s *Service) handleUnlink(ctx context.Context, chatID int64) {
	link, err := s.activeLink(ctx, chatID)
	if err != nil {
		log.Printf("[telegrambot] load link: %v", err)
		s.send(chatID, "Failed to check your link status. Please try again.")
		return
	}
	if link == nil {
		s.send(chatID, "Your Telegram account is not linked to any Mekong account.")
		return
	}

	if err := s.db.RevokeTelegramLinkByUserID(ctx, link.UserID); err != nil {
		log.Printf("[telegrambot] unlink: %v", err)
		s.send(chatID, "Failed to unlink. Please try again.")
		return
	}

	s.send(chatID, "Your Telegram account has been unlinked from Mekong.")
}

// ── helpers ──────────────────────────────────────────────────

func (s *Service) NotifyLinkApproved(chatID int64, user *models.User) {
	if user == nil {
		return
	}

	display := user.Email
	if name := strings.TrimSpace(user.Name); name != "" {
		display = fmt.Sprintf("%s (%s)", name, user.Email)
	}

	go s.send(chatID, fmt.Sprintf(
		"Your Telegram account is now linked to %s.\n\nUse /help to see available commands.",
		display,
	))
}

func (s *Service) NotifyLinkCancelled(chatID int64) {
	go s.send(chatID, "The pending Mekong link request was cancelled.")
}

func (s *Service) NotifyUnlinked(chatID int64) {
	go s.send(chatID, "Your Telegram account has been unlinked from Mekong.")
}

func (s *Service) send(chatID int64, text string) {
	if err := s.client.SendMessage(chatID, text); err != nil {
		log.Printf("[telegrambot] send to %d: %v", chatID, err)
	}
}

func (s *Service) sendMarkdown(chatID int64, text string) {
	if err := s.client.SendMarkdown(chatID, text); err != nil {
		// Fallback to plain text if Markdown parse fails.
		if err2 := s.client.SendMessage(chatID, stripMarkdown(text)); err2 != nil {
			log.Printf("[telegrambot] send to %d: %v", chatID, err2)
		}
	}
}

// parseCommand splits "/command arg" into ("command", "arg").
func parseCommand(text string) (cmd, arg string) {
	parts := strings.SplitN(text, " ", 2)
	raw := parts[0]
	// Strip bot username suffix: /start@MekongTunnelBot → /start
	if idx := strings.Index(raw, "@"); idx != -1 {
		raw = raw[:idx]
	}
	cmd = strings.ToLower(raw)
	if len(parts) > 1 {
		arg = strings.TrimSpace(parts[1])
	}
	return
}

func stripMarkdown(s string) string {
	r := strings.NewReplacer("*", "", "_", "", "`", "", "\\", "")
	return r.Replace(s)
}

func (s *Service) activeLink(ctx context.Context, chatID int64) (*models.TelegramLink, error) {
	link, err := s.db.GetTelegramLinkByChatID(ctx, chatID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return link, nil
}

func (s *Service) requireLinkedUser(ctx context.Context, chatID int64) (*models.TelegramLink, *models.User, bool) {
	link, err := s.activeLink(ctx, chatID)
	if err != nil {
		log.Printf("[telegrambot] load link: %v", err)
		s.send(chatID, "Failed to load your account link.")
		return nil, nil, false
	}
	if link == nil {
		s.send(chatID, notLinkedMsg)
		return nil, nil, false
	}

	user, err := s.db.GetUserByID(ctx, link.UserID)
	if err != nil {
		log.Printf("[telegrambot] load user %s: %v", link.UserID, err)
		s.send(chatID, "Failed to fetch your Mekong account.")
		return nil, nil, false
	}
	if user.Suspended {
		s.send(chatID, suspendedAccountMsg)
		return nil, nil, false
	}
	return link, user, true
}

func (s *Service) recentLogs(ctx context.Context, subdomain string, limit int) ([]string, error) {
	baseURL := strings.TrimRight(s.cfg.TunnelServerURL, "/")
	if baseURL == "" {
		return nil, fmt.Errorf("tunnel server URL is not configured")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/tunnels/logs/"+url.PathEscape(subdomain), nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("tunnel log lookup failed: %s", strings.TrimSpace(string(body)))
	}

	var payload struct {
		Lines []string `json:"lines"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	if limit > 0 && len(payload.Lines) > limit {
		payload.Lines = payload.Lines[len(payload.Lines)-limit:]
	}
	return payload.Lines, nil
}

func joinURLPath(baseURL, path string) string {
	baseURL = strings.TrimRight(baseURL, "/")
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return baseURL + path
}

const notLinkedMsg = "Your Telegram account is not linked to a Mekong account.\n\nUse /link to connect your account."
const suspendedAccountMsg = "Your Mekong account is suspended. Manage your account in the dashboard to restore Telegram access."

const helpText = `*Mekong Tunnel Bot*

Available commands:

/link - Link Telegram to your Mekong account
/me - Show your account info
/services - List active tunnels
/logs <id> - Show recent logs
/subdomains - List reserved subdomains
/domains - List custom domains
/domain <host> - Check one domain
/unlink - Unlink from your account
/help - Show this message`
