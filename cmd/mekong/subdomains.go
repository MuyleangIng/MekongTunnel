package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var apiDo = func(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}

type reservedSubdomain struct {
	ID        string    `json:"id"`
	Subdomain string    `json:"subdomain"`
	CreatedAt time.Time `json:"created_at"`
}

type reservedSubdomainList struct {
	Subdomains []reservedSubdomain `json:"subdomains"`
	Count      int                 `json:"count"`
	Limit      int                 `json:"limit"`
}

func normalizeRequestedSubdomain(raw string) (string, error) {
	subdomain := strings.ToLower(strings.TrimSpace(raw))
	if subdomain == "" {
		return "", nil
	}
	for _, c := range subdomain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
			return "", fmt.Errorf("invalid subdomain %q: use lowercase letters, digits, and hyphens only", raw)
		}
	}
	return subdomain, nil
}

func apiRequest(method, path string, body any, token string) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, 0, err
		}
		reader = &buf
	}

	req, err := http.NewRequest(method, authAPIBase+path, reader)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := apiDo(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

func apiError(status int, body []byte) error {
	var env struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err == nil && env.Error != "" {
		return errors.New(env.Error)
	}
	return fmt.Errorf("server returned %d", status)
}

func fetchReservedSubdomains(token string) (reservedSubdomainList, error) {
	b, status, err := apiRequest(http.MethodGet, "/api/cli/subdomains", nil, token)
	if err != nil {
		return reservedSubdomainList{}, fmt.Errorf("list reserved subdomains: %w", err)
	}
	if status != http.StatusOK {
		return reservedSubdomainList{}, apiError(status, b)
	}

	var data reservedSubdomainList
	if err := unwrapData(b, &data); err != nil {
		return reservedSubdomainList{}, fmt.Errorf("unexpected response: %w", err)
	}
	return data, nil
}

func findReservedSubdomain(list []reservedSubdomain, subdomain string) (reservedSubdomain, bool) {
	normalized, _ := normalizeRequestedSubdomain(subdomain)
	for _, sub := range list {
		if sub.Subdomain == normalized {
			return sub, true
		}
	}
	return reservedSubdomain{}, false
}

func subdomainCommandUsage() string {
	return "mekong subdomain [list|add|delete] [name]"
}

func runSubdomainCommand(args []string) error {
	if len(args) == 0 {
		return runSubdomainsCommand(nil)
	}

	switch args[0] {
	case "list", "ls":
		return runSubdomainsCommand(args[1:])
	case "add", "create", "reserve":
		return runReserveCommand(args[1:])
	case "delete", "remove", "rm", "unreserve":
		return runDeleteCommand(args[1:])
	case "help", "--help", "-h":
		printSubdomainHelp()
		return nil
	}

	if len(args) == 1 {
		return runReserveCommand(args)
	}

	return fmt.Errorf("usage: %s", subdomainCommandUsage())
}

func runSubdomainsCommand(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: mekong subdomains")
	}

	token, err := requireAPIToken("")
	if err != nil {
		return err
	}

	data, err := fetchReservedSubdomains(token)
	if err != nil {
		return err
	}

	fmt.Printf("\n")
	fmt.Printf(gray + "  Reserved subdomains" + reset + "\n")
	fmt.Printf(gray + "  ─────────────────────────────────────────\n" + reset)
	if data.Limit < 0 {
		fmt.Printf(gray+"  Count   "+reset+yellow+"%d / unlimited"+reset+"\n", data.Count)
	} else {
		fmt.Printf(gray+"  Count   "+reset+yellow+"%d / %d"+reset+"\n", data.Count, data.Limit)
	}

	if len(data.Subdomains) == 0 {
		fmt.Printf(gray + "  None yet. Create one with " + reset + cyan + "mekong subdomain myapp" + reset + "\n\n")
		return nil
	}

	for _, sub := range data.Subdomains {
		fmt.Printf(gray+"  Name    "+reset+yellow+"%s"+reset+"\n", sub.Subdomain)
		fmt.Printf(gray+"  URL     "+reset+purple+"https://%s.%s"+reset+"\n", sub.Subdomain, tunnelDomain)
		fmt.Printf(gray+"  Use     "+reset+cyan+"mekong 3000 --subdomain %s"+reset+"\n", sub.Subdomain)
		fmt.Printf(gray+"  Delete  "+reset+cyan+"mekong subdomain delete %s"+reset+"\n", sub.Subdomain)
		fmt.Printf(gray+"  Added   "+reset+purple+"%s"+reset+"\n", sub.CreatedAt.Format("2006-01-02 15:04"))
		fmt.Printf(gray + "  ─────────────────────────────────────────\n" + reset)
	}
	fmt.Printf("\n")
	return nil
}

func runReserveCommand(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: mekong subdomain <name>")
	}

	subdomain, err := normalizeRequestedSubdomain(args[0])
	if err != nil {
		return err
	}
	if subdomain == "" {
		return fmt.Errorf("subdomain is required")
	}

	token, err := requireAPIToken("")
	if err != nil {
		return err
	}

	b, status, err := apiRequest(http.MethodPost, "/api/cli/subdomains", map[string]string{
		"subdomain": subdomain,
	}, token)
	if err != nil {
		return fmt.Errorf("create reserved subdomain: %w", err)
	}
	if status != http.StatusCreated {
		return apiError(status, b)
	}

	var created reservedSubdomain
	if err := unwrapData(b, &created); err != nil {
		return fmt.Errorf("unexpected response: %w", err)
	}

	fmt.Printf("\n")
	fmt.Printf(green + "  ✔  Reserved subdomain created" + reset + "\n")
	fmt.Printf(gray+"     Name   "+reset+yellow+"%s"+reset+"\n", created.Subdomain)
	fmt.Printf(gray+"     URL    "+reset+purple+"https://%s.%s"+reset+"\n", created.Subdomain, tunnelDomain)
	fmt.Printf(gray+"     Use    "+reset+cyan+"mekong 3000 --subdomain %s"+reset+"\n\n", created.Subdomain)
	return nil
}

// parseYesFlag extracts --yes / -y from args, returning the flag and remaining args.
func parseYesFlag(args []string) (yes bool, rest []string) {
	for _, a := range args {
		if a == "--yes" || a == "-y" {
			yes = true
		} else {
			rest = append(rest, a)
		}
	}
	return yes, rest
}

// confirmPrompt asks the user to confirm a destructive action.
// Returns true if the user confirmed (or --yes was passed).
func confirmPrompt(msg string) bool {
	fmt.Printf("\n  %s\n  Confirm? [y/N] ", msg)
	reader := bufio.NewReader(os.Stdin)
	reply, _ := reader.ReadString('\n')
	reply = strings.TrimSpace(strings.ToLower(reply))
	return reply == "y" || reply == "yes"
}

func runDeleteCommand(args []string) error {
	yes, args := parseYesFlag(args)
	if len(args) != 1 {
		return fmt.Errorf("usage: mekong subdomain delete <name> [--yes]")
	}

	subdomain, err := normalizeRequestedSubdomain(args[0])
	if err != nil {
		return err
	}
	if subdomain == "" {
		return fmt.Errorf("subdomain is required")
	}

	token, err := requireAPIToken("")
	if err != nil {
		return err
	}

	data, err := fetchReservedSubdomains(token)
	if err != nil {
		return err
	}

	target, ok := findReservedSubdomain(data.Subdomains, subdomain)
	if !ok {
		return fmt.Errorf("reserved subdomain %q not found", subdomain)
	}

	if !yes {
		if !confirmPrompt(fmt.Sprintf("Delete reserved subdomain %q?", target.Subdomain)) {
			fmt.Printf("  Aborted.\n\n")
			return nil
		}
	}

	_, status, err := apiRequest(http.MethodDelete, "/api/cli/subdomains/"+url.PathEscape(target.ID), nil, token)
	if err != nil {
		return fmt.Errorf("delete reserved subdomain: %w", err)
	}
	if status != http.StatusNoContent {
		return fmt.Errorf("delete reserved subdomain: server returned %d", status)
	}

	fmt.Printf("\n")
	fmt.Printf(green + "  ✔  Reserved subdomain deleted" + reset + "\n")
	fmt.Printf(gray+"     Name   "+reset+yellow+"%s"+reset+"\n", target.Subdomain)
	fmt.Printf(gray+"     Next   "+reset+cyan+"mekong subdomain %s"+reset+gray+"  to claim it again"+reset+"\n\n", target.Subdomain)
	return nil
}
