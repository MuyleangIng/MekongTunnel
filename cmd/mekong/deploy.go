// deploy.go — mekong deploy command.
// Packages and uploads a local project directory to the MekongTunnel
// hosting service, returning a live HTTPS URL.
//
// Usage:
//
//	mekong deploy ./dist          (static HTML/CSS/JS)
//	mekong deploy ./              (plain HTML project)
//	mekong deploy ./.next         (Next.js — run npm run build first)
//	mekong deploy ./src           (PHP project)
//	mekong deploy list            (list active deployments)
//	mekong deploy stop <sub>      (stop a deployment)
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	deployMaxBytes = 100 << 20 // 100MB default
)

// deployTypeInfo holds detected project info.
type deployTypeInfo struct {
	Type  string
	Label string
	Hint  string
}

type deployUploadResponse struct {
	ID        string     `json:"id"`
	URL       string     `json:"url"`
	Subdomain string     `json:"subdomain"`
	Type      string     `json:"type"`
	SizeBytes int64      `json:"size_bytes"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
}

type deployListResponse struct {
	Deployments []deployItem `json:"deployments"`
}

type deployItem struct {
	ID        string     `json:"id"`
	URL       string     `json:"url"`
	Subdomain string     `json:"subdomain"`
	Type      string     `json:"type"`
	Status    string     `json:"status"`
	SizeBytes int64      `json:"size_bytes"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
}

func runDeployCommand(args []string) error {
	tok := resolveAPIToken("")
	if tok == "" {
		return fmt.Errorf("not logged in\n  Run: mekong login")
	}

	if len(args) == 0 {
		return runDeployList(tok)
	}

	switch args[0] {
	case "list", "ls":
		return runDeployList(tok)
	case "stop", "rm", "delete", "down":
		if len(args) < 2 {
			return fmt.Errorf("usage: mekong deploy stop <subdomain>")
		}
		return runDeployStop(tok, args[1])
	case "redeploy", "update", "push":
		if len(args) < 3 {
			return fmt.Errorf("usage: mekong deploy redeploy <subdomain> <path>")
		}
		return runDeployRedeploy(tok, args[1], args[2])
	case "open":
		if len(args) < 2 {
			return fmt.Errorf("usage: mekong deploy open <subdomain>")
		}
		return runDeployOpen(tok, args[1])
	case "quota":
		return runDeployQuota(tok)
	case "info":
		if len(args) < 2 {
			return fmt.Errorf("usage: mekong deploy info <subdomain>")
		}
		return runDeployInfo(tok, args[1])
	}

	return runDeployUpload(tok, args[0])
}

// ── Upload ───────────────────────────────────────────────────────────────────

func runDeployUpload(tok, path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("path not found: %s", absPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("path must be a directory")
	}

	dtype := detectDeployType(absPath)

	// For Vue/React types, automatically resolve to the build output directory
	if buildDir, ok := deployBuildOnlyDirs[dtype.Type]; ok {
		candidate := filepath.Join(absPath, buildDir)
		if info2, err2 := os.Stat(candidate); err2 == nil && info2.IsDir() {
			absPath = candidate
		}
	}

	// For nextjs-standalone: resolve from project root to .next/standalone/
	// and auto-copy public/ + .next/static/ into it (Next.js standalone requirement).
	if dtype.Type == "nextjs-standalone" {
		absPath = prepareNextjsStandalone(absPath)
	}

	fmt.Printf("\n%s  Detected:%s  %s (%s)%s\n", cyan, reset, dtype.Label, dtype.Type, reset)
	if dtype.Hint != "" {
		fmt.Printf("%s  Note:%s     %s%s\n", yellow, reset, dtype.Hint, reset)
	}
	fmt.Printf("%s  Packaging:%s %s ...%s\n", cyan, reset, absPath, reset)

	var buf bytes.Buffer
	written, err := zipDir(absPath, &buf, dtype.Type)
	if err != nil {
		return fmt.Errorf("failed to package project: %w", err)
	}

	fmt.Printf("%s  ✓%s  Packaged %d files (%s)\n", green, reset, written, fmtBytes(int64(buf.Len())))

	if buf.Len() > deployMaxBytes {
		return fmt.Errorf("package too large (%s) — max 100MB\n  Tip: add a .mekongignore file to exclude large files", fmtBytes(int64(buf.Len())))
	}

	fmt.Printf("%s  Uploading ...%s\n", cyan, reset)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("type", dtype.Type)
	fw, err := mw.CreateFormFile("archive", "deploy.zip")
	if err != nil {
		return err
	}
	if _, err := io.Copy(fw, &buf); err != nil {
		return err
	}
	mw.Close()

	req, err := http.NewRequest(http.MethodPost, authAPIBase+"/api/deploy", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("deploy requires a student plan or higher\n  Upgrade: %s/billing", authWebBase)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result deployUploadResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	fmt.Printf("\n%s  ✅  Deploy complete!%s\n\n", green, reset)
	fmt.Printf("  %s🌐  URL%s       %s%s%s\n", cyan, reset, green, result.URL, reset)
	fmt.Printf("  %s📁  Type%s      %s%s\n", cyan, reset, result.Type, reset)
	fmt.Printf("  %s💾  Size%s      %s%s\n", cyan, reset, fmtBytes(result.SizeBytes), reset)
	if result.ExpiresAt != nil {
		fmt.Printf("  %s⏱  Expires%s   %s%s\n", cyan, reset, result.ExpiresAt.Format("Jan 2, 2006"), reset)
	}
	fmt.Println()
	fmt.Printf("  %sTo stop:  mekong deploy stop %s%s\n", gray, result.Subdomain, reset)
	fmt.Printf("  %sTo list:  mekong deploy list%s\n\n", gray, reset)

	return nil
}

// ── List ─────────────────────────────────────────────────────────────────────

func runDeployList(tok string) error {
	req, err := http.NewRequest(http.MethodGet, authAPIBase+"/api/deploy", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("not logged in — run: mekong login")
	}

	var result deployListResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	if len(result.Deployments) == 0 {
		fmt.Printf("\n%s  No active deployments%s\n\n", gray, reset)
		fmt.Printf("  Deploy a project:  mekong deploy ./dist\n\n")
		return nil
	}

	fmt.Printf("\n%s  Your Deployments%s\n\n", cyan, reset)
	for _, d := range result.Deployments {
		sc := green
		if d.Status != "active" {
			sc = yellow
		}
		fmt.Printf("  %s●%s  %s%s%s\n", sc, reset, green, d.URL, reset)
		fmt.Printf("     Type: %-10s Status: %s%s%s\n", d.Type, sc, d.Status, reset)
		fmt.Printf("     Size: %-10s Created: %s\n", fmtBytes(d.SizeBytes), d.CreatedAt.Format("Jan 2, 2006"))
		if d.ExpiresAt != nil {
			fmt.Printf("     Expires: %s\n", d.ExpiresAt.Format("Jan 2, 2006"))
		}
		fmt.Printf("     Stop:  mekong deploy stop %s\n", d.Subdomain)
		fmt.Println()
	}

	return nil
}

// ── Stop ─────────────────────────────────────────────────────────────────────

func runDeployStop(tok, subdomain string) error {
	req, err := http.NewRequest(http.MethodDelete, authAPIBase+"/api/deploy/"+subdomain, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("deployment %q not found", subdomain)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to stop (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	fmt.Printf("\n%s  ✓  Deployment %s stopped%s\n\n", green, subdomain, reset)
	return nil
}

// ── Redeploy ──────────────────────────────────────────────────────────────────

func runDeployRedeploy(tok, subdomain, path string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("path not found: %s", absPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("path must be a directory")
	}

	dtype := detectDeployType(absPath)
	if buildDir, ok := deployBuildOnlyDirs[dtype.Type]; ok {
		if candidate := filepath.Join(absPath, buildDir); func() bool {
			i, e := os.Stat(candidate)
			return e == nil && i.IsDir()
		}() {
			absPath = candidate
		}
	}
	if dtype.Type == "nextjs-standalone" {
		absPath = prepareNextjsStandalone(absPath)
	}

	fmt.Printf("\n%s  Redeploying:%s %s → %s (%s)%s\n", cyan, reset, subdomain, dtype.Label, dtype.Type, reset)
	fmt.Printf("%s  Packaging:%s  %s ...%s\n", cyan, reset, absPath, reset)

	var buf bytes.Buffer
	written, err := zipDir(absPath, &buf, dtype.Type)
	if err != nil {
		return fmt.Errorf("failed to package project: %w", err)
	}
	fmt.Printf("%s  ✓%s  Packaged %d files (%s)\n", green, reset, written, fmtBytes(int64(buf.Len())))

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("type", dtype.Type)
	fw, err := mw.CreateFormFile("archive", "deploy.zip")
	if err != nil {
		return err
	}
	if _, err := io.Copy(fw, &buf); err != nil {
		return err
	}
	mw.Close()

	req, err := http.NewRequest(http.MethodPut, authAPIBase+"/api/deploy/"+subdomain, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var result struct {
		Subdomain string     `json:"subdomain"`
		URL       string     `json:"url"`
		SizeBytes int64      `json:"size_bytes"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	fmt.Printf("\n%s  ✅  Redeploy complete!%s\n\n", green, reset)
	fmt.Printf("  %s🌐  URL%s      %s%s%s\n", cyan, reset, green, result.URL, reset)
	fmt.Printf("  %s💾  Size%s     %s%s\n", cyan, reset, fmtBytes(result.SizeBytes), reset)
	if result.ExpiresAt != nil {
		fmt.Printf("  %s⏱  Expires%s  %s%s\n", cyan, reset, result.ExpiresAt.Format("Jan 2, 2006"), reset)
	}
	fmt.Println()
	return nil
}

// ── Open ──────────────────────────────────────────────────────────────────────

func runDeployOpen(tok, subdomain string) error {
	req, err := http.NewRequest(http.MethodGet, authAPIBase+"/api/deploy/"+subdomain, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("deployment %q not found", subdomain)
	}

	var result struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil || result.URL == "" {
		return fmt.Errorf("could not resolve URL for %s", subdomain)
	}

	fmt.Printf("\n%s  🌐  %s%s\n\n", green, result.URL, reset)
	openBrowser(result.URL)
	return nil
}

// ── Quota ─────────────────────────────────────────────────────────────────────

func runDeployQuota(tok string) error {
	req, err := http.NewRequest(http.MethodGet, authAPIBase+"/api/deploy/quota", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		UsedBytes          int64  `json:"used_bytes"`
		QuotaBytes         int64  `json:"quota_bytes"`
		FreeBytes          int64  `json:"free_bytes"`
		Plan               string `json:"plan"`
		MaxDeployments     int    `json:"max_deployments"`
		ActiveDeployments  int    `json:"active_deployments"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	pct := 0
	if result.QuotaBytes > 0 {
		pct = int(float64(result.UsedBytes) / float64(result.QuotaBytes) * 100)
	}
	barFull := 20
	barFilled := barFull * pct / 100
	bar := "[" + strings.Repeat("█", barFilled) + strings.Repeat("░", barFull-barFilled) + "]"

	fmt.Printf("\n%s  Storage Quota%s\n\n", cyan, reset)
	fmt.Printf("  %s%s%s  %s / %s  (%d%%)\n", yellow, bar, reset, fmtBytes(result.UsedBytes), fmtBytes(result.QuotaBytes), pct)
	fmt.Printf("  Free:        %s%s%s\n", green, fmtBytes(result.FreeBytes), reset)
	fmt.Printf("  Plan:        %s\n", result.Plan)
	fmt.Printf("  Deployments: %d / %d active\n\n", result.ActiveDeployments, result.MaxDeployments)
	return nil
}

// ── Info ──────────────────────────────────────────────────────────────────────

func runDeployInfo(tok, subdomain string) error {
	req, err := http.NewRequest(http.MethodGet, authAPIBase+"/api/deploy/"+subdomain, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("deployment %q not found", subdomain)
	}

	var d struct {
		URL            string     `json:"url"`
		Type           string     `json:"type"`
		Status         string     `json:"status"`
		Tunnel         string     `json:"tunnel"`
		SizeBytes      int64      `json:"size_bytes"`
		RedeployCount  int        `json:"redeploy_count"`
		CreatedAt      time.Time  `json:"created_at"`
		ExpiresAt      *time.Time `json:"expires_at"`
		LastDeployedAt *time.Time `json:"last_deployed_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	sc := green
	if d.Status != "active" {
		sc = yellow
	}
	tc := green
	if d.Tunnel != "up" {
		tc = yellow
	}

	fmt.Printf("\n%s  Deployment: %s%s\n\n", cyan, subdomain, reset)
	fmt.Printf("  %s🌐  URL%s       %s%s%s\n", cyan, reset, green, d.URL, reset)
	fmt.Printf("  %s📁  Type%s      %s%s\n", cyan, reset, d.Type, reset)
	fmt.Printf("  %s●  Status%s    %s%s%s\n", sc, reset, sc, d.Status, reset)
	fmt.Printf("  %s⚡  Tunnel%s    %s%s%s\n", tc, reset, tc, d.Tunnel, reset)
	fmt.Printf("  %s💾  Size%s      %s%s\n", cyan, reset, fmtBytes(d.SizeBytes), reset)
	fmt.Printf("  %s🔄  Redeploys%s %d%s\n", cyan, reset, d.RedeployCount, reset)
	fmt.Printf("  %s📅  Created%s   %s%s\n", cyan, reset, d.CreatedAt.Format("Jan 2, 2006"), reset)
	if d.LastDeployedAt != nil {
		fmt.Printf("  %s🕐  Updated%s   %s%s\n", cyan, reset, d.LastDeployedAt.Format("Jan 2, 2006 15:04"), reset)
	}
	if d.ExpiresAt != nil {
		fmt.Printf("  %s⏱  Expires%s   %s%s\n", cyan, reset, d.ExpiresAt.Format("Jan 2, 2006"), reset)
	}
	fmt.Printf("\n  %sTo redeploy:  mekong deploy redeploy %s <path>%s\n", gray, subdomain, reset)
	fmt.Printf("  %sTo stop:      mekong deploy stop %s%s\n\n", gray, subdomain, reset)
	return nil
}

// ── Project type detection ───────────────────────────────────────────────────

func detectDeployType(path string) deployTypeInfo {
	base := filepath.Base(path)

	// Explicit .next/standalone directory
	if base == "standalone" {
		if _, err := os.Stat(filepath.Join(path, "server.js")); err == nil {
			return deployTypeInfo{
				Type:  "nextjs-standalone",
				Label: "Next.js Standalone",
				Hint:  "detected server.js — will run with node",
			}
		}
	}

	// Project root with .next/standalone/server.js → standalone build
	if _, err := os.Stat(filepath.Join(path, ".next", "standalone", "server.js")); err == nil {
		return deployTypeInfo{
			Type:  "nextjs-standalone",
			Label: "Next.js Standalone",
			Hint:  "detected .next/standalone/ — make sure you ran: npm run build",
		}
	}

	// Explicit .next directory
	if base == ".next" {
		return deployTypeInfo{
			Type:  "nextjs",
			Label: "Next.js",
			Hint:  "make sure you ran: npm run build",
		}
	}

	// .next inside the directory → check for API routes
	if _, err := os.Stat(filepath.Join(path, ".next")); err == nil {
		// Next.js with API routes (pages/api or app/api)
		hasAPI := false
		for _, apiDir := range []string{"pages/api", "app/api", "src/pages/api", "src/app/api"} {
			if _, err := os.Stat(filepath.Join(path, apiDir)); err == nil {
				hasAPI = true
				break
			}
		}
		if hasAPI {
			return deployTypeInfo{
				Type:  "nextjs-api",
				Label: "Next.js (with API routes)",
				Hint:  "deploying Next.js app with API routes — make sure you ran: npm run build",
			}
		}
		return deployTypeInfo{
			Type:  "nextjs",
			Label: "Next.js",
			Hint:  "deploying .next/ output — make sure you ran: npm run build",
		}
	}

	// next.js export output (out/)
	if _, err := os.Stat(filepath.Join(path, "out", "index.html")); err == nil {
		return deployTypeInfo{
			Type:  "static",
			Label: "Next.js static export",
			Hint:  "detected next export output in out/",
		}
	}

	// Vue.js — vue.config.js or vite.config with dist/
	hasVueConfig := false
	for _, f := range []string{"vue.config.js", "vue.config.ts", "vue.config.mjs"} {
		if _, err := os.Stat(filepath.Join(path, f)); err == nil {
			hasVueConfig = true
			break
		}
	}
	if hasVueConfig {
		// Vue + Vite build output
		if _, err := os.Stat(filepath.Join(path, "dist", "index.html")); err == nil {
			return deployTypeInfo{
				Type:  "vue",
				Label: "Vue.js (built)",
				Hint:  "detected dist/ — make sure you ran: npm run build",
			}
		}
		return deployTypeInfo{
			Type:  "vue",
			Label: "Vue.js",
			Hint:  "run: npm run build, then deploy the dist/ folder",
		}
	}

	// React + Vite — vite.config present + dist/
	hasViteConfig := false
	for _, f := range []string{"vite.config.js", "vite.config.ts", "vite.config.mjs"} {
		if _, err := os.Stat(filepath.Join(path, f)); err == nil {
			hasViteConfig = true
			break
		}
	}
	if hasViteConfig {
		if _, err := os.Stat(filepath.Join(path, "dist", "index.html")); err == nil {
			return deployTypeInfo{
				Type:  "react-vite",
				Label: "React + Vite (built)",
				Hint:  "detected dist/ — make sure you ran: npm run build",
			}
		}
		return deployTypeInfo{
			Type:  "react-vite",
			Label: "React + Vite",
			Hint:  "run: npm run build, then deploy the dist/ folder",
		}
	}

	// Create React App — build/ with static/ subfolder
	if _, err := os.Stat(filepath.Join(path, "build", "static")); err == nil {
		return deployTypeInfo{
			Type:  "react",
			Label: "React (Create React App)",
			Hint:  "detected CRA build/ output — make sure you ran: npm run build",
		}
	}

	// PHP files present
	hasPHP := false
	filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil || hasPHP {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(p, ".php") {
			hasPHP = true
		}
		return nil
	})
	if hasPHP {
		return deployTypeInfo{Type: "php", Label: "PHP"}
	}

	// Docs site — has .md files but no index.html at root
	hasMD := false
	hasIndexHTML := false
	if entries, err := os.ReadDir(path); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				switch strings.ToLower(e.Name()) {
				case "index.html", "index.htm":
					hasIndexHTML = true
				}
				if strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
					hasMD = true
				}
			}
		}
	}
	if hasMD && !hasIndexHTML {
		return deployTypeInfo{
			Type:  "docs",
			Label: "Docs site (Markdown)",
			Hint:  "Markdown files will be rendered as HTML with cross-file navigation",
		}
	}

	return deployTypeInfo{Type: "static", Label: "Static site"}
}

// ── Zip ──────────────────────────────────────────────────────────────────────

var deploySkipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	".svn":         true,
	"vendor":       true, // PHP composer — include only if needed
}

// deployBuildOnlyTypes are types where we only ship the build output directory.
var deployBuildOnlyDirs = map[string]string{
	"vue":        "dist",
	"react-vite": "dist",
	"react":      "build",
}

var deploySkipDotDirs = true // skip .hidden dirs except .next

func zipDir(src string, w io.Writer, deployType string) (int, error) {
	zw := zip.NewWriter(w)
	defer zw.Close()

	fileCount := 0
	err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		name := d.Name()

		if d.IsDir() {
			if deploySkipDirs[name] {
				return filepath.SkipDir
			}
			// Skip hidden dirs except .next (needed for Next.js)
			if deploySkipDotDirs && strings.HasPrefix(name, ".") && name != ".next" {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hidden files
		if strings.HasPrefix(name, ".") {
			return nil
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		fw, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}

		if _, err := io.Copy(fw, f); err != nil {
			return err
		}

		fileCount++
		return nil
	})

	return fileCount, err
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// prepareNextjsStandalone resolves the project root or .next dir to .next/standalone/,
// then copies public/ and .next/static/ into it (required for Next.js standalone to serve assets).
// Returns the path to .next/standalone/ that should be zipped.
func prepareNextjsStandalone(path string) string {
	// Resolve: if path is the project root, descend into .next/standalone
	standalone := path
	if _, err := os.Stat(filepath.Join(path, ".next", "standalone", "server.js")); err == nil {
		standalone = filepath.Join(path, ".next", "standalone")
	} else if _, err := os.Stat(filepath.Join(path, "standalone", "server.js")); err == nil {
		standalone = filepath.Join(path, "standalone")
	}

	// Infer project root: standalone is typically <root>/.next/standalone
	root := filepath.Dir(filepath.Dir(standalone)) // <root>/.next/standalone → <root>

	// Copy public/ → .next/standalone/public/
	publicSrc := filepath.Join(root, "public")
	publicDst := filepath.Join(standalone, "public")
	if info, err := os.Stat(publicSrc); err == nil && info.IsDir() {
		if err := copyDirInto(publicSrc, publicDst); err != nil {
			fmt.Printf("%s  warn: could not copy public/: %v%s\n", yellow, err, reset)
		} else {
			fmt.Printf("%s  ✓%s  Copied public/ → standalone/public/\n", green, reset)
		}
	}

	// Copy .next/static/ → .next/standalone/.next/static/
	staticSrc := filepath.Join(root, ".next", "static")
	staticDst := filepath.Join(standalone, ".next", "static")
	if info, err := os.Stat(staticSrc); err == nil && info.IsDir() {
		if err := copyDirInto(staticSrc, staticDst); err != nil {
			fmt.Printf("%s  warn: could not copy .next/static/: %v%s\n", yellow, err, reset)
		} else {
			fmt.Printf("%s  ✓%s  Copied .next/static/ → standalone/.next/static/\n", green, reset)
		}
	}

	return standalone
}

// copyDirInto copies src directory tree into dst (creating dst if needed).
func copyDirInto(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func fmtBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
