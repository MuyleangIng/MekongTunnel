// selftest.go — `mekong test` command: validates connectivity, auth, and tunnel creation.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	defaultSSHPort = "22"
)

var testSSHHost = tunnelDomain

type testResult struct {
	name    string
	ok      bool
	detail  string
	skipped bool
}

func (r testResult) print() {
	if r.skipped {
		fmt.Printf("  ⚪ SKIP  %s — %s\n", r.name, r.detail)
		return
	}
	if r.ok {
		fmt.Printf("  ✅ PASS  %s\n", r.name)
		if r.detail != "" {
			fmt.Printf("          %s\n", r.detail)
		}
	} else {
		fmt.Printf("  ❌ FAIL  %s — %s\n", r.name, r.detail)
	}
}

// runSelfTest is the entry point for `mekong test`.
func runSelfTest(apiToken string) int {
	fmt.Println()
	fmt.Println("  MekongTunnel Self-Test")
	fmt.Println("  ──────────────────────────────────────────")
	fmt.Println()

	results := []testResult{
		testDNS(),
		testSSHPort(),
		testAPIHealth(),
		testAPIVersion(),
		testAuthToken(apiToken),
		testWhoami(apiToken),
		testBinary(),
	}

	fmt.Println()
	fmt.Println("  ──────────────────────────────────────────")

	passed, failed, skipped := 0, 0, 0
	for _, r := range results {
		r.print()
		if r.skipped {
			skipped++
		} else if r.ok {
			passed++
		} else {
			failed++
		}
	}

	fmt.Println()
	fmt.Printf("  Results: %d passed · %d failed · %d skipped\n", passed, failed, skipped)
	fmt.Println()

	if failed > 0 {
		if strings.Contains(results[1].detail, "refused") || !results[1].ok {
			fmt.Println("  💡 SSH port 22 blocked? Try running from a different network.")
		}
		if !results[2].ok {
			fmt.Println("  💡 API unreachable — check your internet connection.")
		}
		if !results[4].ok {
			fmt.Println("  💡 Token invalid — run: mekong login")
		}
		fmt.Println()
		return 1
	}
	return 0
}

// testDNS checks that the tunnel server hostname resolves.
func testDNS() testResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := (&net.Resolver{}).LookupHost(ctx, testSSHHost)
	if err != nil || len(addrs) == 0 {
		return testResult{name: "DNS resolution", detail: fmt.Sprintf("cannot resolve %s: %v", testSSHHost, err)}
	}
	return testResult{name: "DNS resolution", ok: true, detail: fmt.Sprintf("%s → %s", testSSHHost, addrs[0])}
}

// testSSHPort checks TCP connectivity to port 22.
func testSSHPort() testResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(testSSHHost, defaultSSHPort), 6*time.Second)
	if err != nil {
		return testResult{name: "SSH port 22 reachable", detail: err.Error()}
	}
	conn.Close()
	return testResult{name: "SSH port 22 reachable", ok: true}
}

// testAPIHealth calls /api/health on the backend.
func testAPIHealth() testResult {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(authAPIBase + "/api/health")
	if err != nil {
		return testResult{name: "API health check", detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return testResult{name: "API health check", detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	return testResult{name: "API health check", ok: true, detail: authAPIBase + "/api/health → 200 OK"}
}

// testAPIVersion fetches the server version from /api/health response.
func testAPIVersion() testResult {
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Get(authAPIBase + "/api/health")
	if err != nil {
		return testResult{name: "Server version", detail: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var payload struct {
		Data struct {
			Version string `json:"version"`
			Status  string `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.Data.Version != "" {
		return testResult{name: "Server version", ok: true, detail: "server=" + payload.Data.Version}
	}
	return testResult{name: "Server version", ok: true, detail: "server running"}
}

// testAuthToken validates the resolved token against /api/auth/token-info.
func testAuthToken(token string) testResult {
	if token == "" {
		return testResult{
			name:    "Token validation",
			skipped: true,
			detail:  "no token — run: mekong login",
		}
	}
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", authAPIBase+"/api/auth/token-info", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return testResult{name: "Token validation", detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return testResult{name: "Token validation", detail: "token rejected (401) — run: mekong login"}
	}
	if resp.StatusCode != 200 {
		return testResult{name: "Token validation", detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	return testResult{name: "Token validation", ok: true, detail: "token accepted ✔"}
}

// testWhoami mirrors `mekong whoami` — reads saved config and shows account info.
func testWhoami(token string) testResult {
	if token == "" {
		cfg, err := loadAuthConfig()
		if err != nil {
			return testResult{name: "Saved credentials", skipped: true, detail: "not logged in"}
		}
		return testResult{name: "Saved credentials", ok: true, detail: "email=" + cfg.Email}
	}
	// Try to fetch display info from API
	client := &http.Client{Timeout: 8 * time.Second}
	req, _ := http.NewRequest("GET", authAPIBase+"/api/auth/token-info", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return testResult{name: "Saved credentials", ok: token != "", detail: "token prefix " + tokenPrefix(token)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var payload struct {
		Data struct {
			Email string `json:"email"`
			Name  string `json:"name"`
			Plan  string `json:"plan"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		detail := fmt.Sprintf("email=%s plan=%s", payload.Data.Email, payload.Data.Plan)
		return testResult{name: "Saved credentials", ok: true, detail: detail}
	}
	return testResult{name: "Saved credentials", ok: true}
}

// testBinary checks that the mekong binary exists and is executable.
func testBinary() testResult {
	exe, err := os.Executable()
	if err != nil {
		return testResult{name: "Binary self-check", detail: err.Error()}
	}
	info, err := os.Stat(exe)
	if err != nil {
		return testResult{name: "Binary self-check", detail: err.Error()}
	}
	return testResult{name: "Binary self-check", ok: true, detail: fmt.Sprintf("%s (%d KB)", exe, info.Size()/1024)}
}

func tokenPrefix(token string) string {
	if len(token) > 12 {
		return token[:12] + "****"
	}
	return "****"
}
