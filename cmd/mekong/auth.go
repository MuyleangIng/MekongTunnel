// auth.go — mekong login / logout / whoami commands and local config management.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

var (
	authAPIBase  = envOrDefault("MEKONG_AUTH_API_BASE", "https://api.angkorsearch.dev")
	authWebBase  = envOrDefault("MEKONG_AUTH_WEB_BASE", "https://angkorsearch.dev")
	tunnelDomain = envOrDefault("MEKONG_TUNNEL_DOMAIN", "proxy.angkorsearch.dev")
)

const (
	pollEvery = 3 * time.Second
	pollMax   = 5 * time.Minute
)

// authConfig is saved to ~/.mekong/config.json after a successful login.
type authConfig struct {
	Token  string `json:"token"`
	Email  string `json:"email,omitempty"`
	UserID string `json:"user_id,omitempty"`
}

func authConfigPath() string {
	return filepath.Join(mekongDir(), "config.json")
}

func loadAuthConfig() (*authConfig, error) {
	b, err := os.ReadFile(authConfigPath())
	if err != nil {
		return nil, err
	}
	var cfg authConfig
	return &cfg, json.Unmarshal(b, &cfg)
}

func saveAuthConfig(cfg *authConfig) error {
	_ = os.MkdirAll(mekongDir(), 0755)
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(authConfigPath(), b, 0600)
}

// ── Device flow response types ───────────────────────────────────────────────

type deviceCreateResp struct {
	SessionID    string `json:"session_id"`
	LoginURL     string `json:"login_url"`
	ExpiresIn    int    `json:"expires_in"`
	PollInterval int    `json:"poll_interval"`
}

type devicePollResp struct {
	Status string `json:"status"` // pending | approved | expired
	Token  string `json:"token,omitempty"`
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

func apiPost(path string, body any) ([]byte, int, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, 0, err
		}
	}
	resp, err := http.Post(authAPIBase+path, "application/json", &buf)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

func apiGet(path string) ([]byte, int, error) {
	resp, err := http.Get(authAPIBase + path)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

// unwrapData decodes {"data": ...} envelope.
func unwrapData(b []byte, dst any) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return err
	}
	if env.Data == nil {
		return fmt.Errorf("empty response")
	}
	return json.Unmarshal(env.Data, dst)
}

func resolveAPIToken(explicit string) string {
	apiToken := strings.TrimSpace(explicit)
	if apiToken == "" {
		apiToken = strings.TrimSpace(os.Getenv("MEKONG_TOKEN"))
	}
	if apiToken == "" {
		if cfg, err := loadAuthConfig(); err == nil {
			apiToken = strings.TrimSpace(cfg.Token)
		}
	}
	return apiToken
}

func requireAPIToken(explicit string) (string, error) {
	apiToken := resolveAPIToken(explicit)
	if apiToken == "" {
		return "", fmt.Errorf("no API token found; run 'mekong login' first")
	}
	return apiToken, nil
}

// ── openBrowser ───────────────────────────────────────────────────────────────

func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "windows":
		cmd, args = "cmd", []string{"/c", "start", url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	_ = exec.CommandContext(context.Background(), cmd, args...).Start()
}

func printLoginInstructions(url string) {
	fmt.Printf("\n")
	fmt.Printf(yellow + "  Login URL" + reset + "\n")
	fmt.Printf(gray + "  ─────────────────────────────────────────\n" + reset)
	fmt.Printf(gray+"  Open    "+reset+purple+"%s"+reset+"\n", url)
	fmt.Printf(gray + "  Browser " + reset + cyan + "Press Enter to open it again" + reset + "\n\n")
}

func startSpinner(label string) chan struct{} {
	done := make(chan struct{})
	go func() {
		frames := []string{"|", "/", "-", `\`}
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		i := 0
		for {
			select {
			case <-done:
				fmt.Printf("\r\033[K")
				return
			case <-ticker.C:
				fmt.Printf("\r%s  %s %s%s", gray, label, frames[i%len(frames)], reset)
				i++
			}
		}
	}()
	return done
}

func stopSpinner(done chan struct{}) {
	if done == nil {
		return
	}
	close(done)
	// Give the goroutine a brief moment to clear the line before more output.
	time.Sleep(25 * time.Millisecond)
}

// ── mekong login ─────────────────────────────────────────────────────────────

func runLogin() error {
	fmt.Printf("\n%s  Connecting to %s...%s\n", gray, authWebBase, reset)

	// 1. Create a device session
	b, status, err := apiPost("/api/cli/device", nil)
	if err != nil {
		return fmt.Errorf("network error: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("server returned %d", status)
	}

	var sess deviceCreateResp
	if err := unwrapData(b, &sess); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}

	// 2. Print login URL and try to open the browser
	printLoginInstructions(sess.LoginURL)

	// Non-blocking read: if user presses Enter, open browser
	doneCh := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		os.Stdin.Read(buf) //nolint:errcheck
		close(doneCh)
	}()

	// Try auto-open after a short delay
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser(sess.LoginURL)
	}()

	spinDone := startSpinner("Waiting for authorization")

	// 3. Poll until approved or expired
	deadline := time.Now().Add(pollMax)
	interval := time.Duration(sess.PollInterval) * time.Second
	if interval < time.Second {
		interval = 3 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for time.Now().Before(deadline) {
		select {
		case <-ticker.C:
			pb, _, err := apiGet("/api/cli/device?session_id=" + sess.SessionID)
			if err != nil {
				continue
			}
			var poll devicePollResp
			if err := unwrapData(pb, &poll); err != nil {
				continue
			}
			switch poll.Status {
			case "approved":
				if poll.Token == "" {
					// race — token already consumed? shouldn't happen
					stopSpinner(spinDone)
					return fmt.Errorf("session approved but token was already consumed")
				}
				stopSpinner(spinDone)
				return finishLogin(poll.Token)
			case "expired":
				stopSpinner(spinDone)
				return fmt.Errorf("session expired — run 'mekong login' again")
			}
		case <-doneCh:
			openBrowser(sess.LoginURL)
			// Enter pressed — just continue polling and allow another browser open.
			doneCh = make(chan struct{}) // reset so we don't re-trigger
		}
	}
	stopSpinner(spinDone)
	return fmt.Errorf("login timed out — run 'mekong login' again")
}

// finishLogin is called once the token is received from the poll.
// It saves the token and fetches the user's email for display.
func finishLogin(token string) error {
	// Fetch user info using the API token (/token-info accepts mkt_xxx, not JWT)
	req, _ := http.NewRequest("GET", authAPIBase+"/api/auth/token-info", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	var email, userID string
	if err == nil {
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var user struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		}
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(b, &env) == nil && env.Data != nil {
			_ = json.Unmarshal(env.Data, &user)
			email = user.Email
			userID = user.ID
		}
	}

	cfg := &authConfig{Token: token, Email: email, UserID: userID}
	if err := saveAuthConfig(cfg); err != nil {
		return fmt.Errorf("could not save credentials: %w", err)
	}

	fmt.Printf("\n")
	fmt.Printf(green + "  ✔  Logged in" + reset)
	if email != "" {
		fmt.Printf(gray+" as "+reset+yellow+"%s"+reset, email)
	}
	fmt.Printf("\n\n")
	fmt.Printf(gray + "  Saved login is now the default auth for this machine.\n" + reset)
	fmt.Printf(gray + "  Run: " + reset + cyan + "mekong 3000" + reset + gray + "  for a random URL, or  " + reset + cyan + "mekong 3000 --subdomain myapp" + reset + gray + "  for a reserved one" + reset + "\n")
	fmt.Printf(gray + "  See: " + reset + cyan + "mekong subdomains" + reset + gray + "  for your reserved names.\n\n" + reset)
	return nil
}

// ── mekong logout ────────────────────────────────────────────────────────────

func runLogout() {
	cfg, err := loadAuthConfig()
	if err != nil {
		fmt.Printf("%s  Already logged out.%s\n", gray, reset)
		return
	}
	email := cfg.Email
	_ = os.Remove(authConfigPath())
	fmt.Printf("\n")
	if email != "" {
		fmt.Printf(yellow+"  ✔  Logged out "+gray+"(was: %s)"+reset+"\n\n", email)
	} else {
		fmt.Printf(yellow + "  ✔  Logged out" + reset + "\n\n")
	}
}

// ── mekong whoami ────────────────────────────────────────────────────────────

func runWhoami() {
	cfg, err := loadAuthConfig()
	if err != nil {
		fmt.Printf("\n%s  Not logged in.%s Run "+cyan+"mekong login"+reset+"\n\n", gray, reset)
		return
	}

	// Try to fetch fresh user info
	req, _ := http.NewRequest("GET", authAPIBase+"/api/auth/token-info", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)

	fmt.Printf("\n")
	if err != nil || resp.StatusCode != 200 {
		// Fallback to cached info
		fmt.Print(gray + "  Token   " + reset + purple + strings.Repeat("*", 8) + reset + "\n")
		if cfg.Email != "" {
			fmt.Printf(gray+"  Email   "+reset+purple+"%s"+reset+"\n", cfg.Email)
		}
		fmt.Printf(gray + "  (could not reach server to verify)" + reset + "\n\n")
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	var user struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Plan  string `json:"plan"`
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(b, &env) == nil && env.Data != nil {
		_ = json.Unmarshal(env.Data, &user)
	}

	if user.Email != "" {
		// Update cached email in case it changed
		cfg.Email = user.Email
		cfg.UserID = user.ID
		_ = saveAuthConfig(cfg)
	}

	prefix := cfg.Token
	if len(prefix) > 12 {
		prefix = prefix[:12] + strings.Repeat("*", len(cfg.Token)-12)
	}

	fmt.Printf(gray + "  ─────────────────────────────────────────\n" + reset)
	if user.Name != "" {
		fmt.Printf(gray+"  Name    "+reset+yellow+"%s"+reset+"\n", user.Name)
	}
	fmt.Printf(gray+"  Email   "+reset+yellow+"%s"+reset+"\n", user.Email)
	fmt.Printf(gray+"  Plan    "+reset+yellow+"%s"+reset+"\n", user.Plan)
	fmt.Printf(gray+"  Token   "+reset+purple+"%s"+reset+"\n", prefix)
	fmt.Printf(gray + "  ─────────────────────────────────────────\n" + reset)
	fmt.Printf("\n")
}
