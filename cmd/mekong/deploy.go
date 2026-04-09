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

// ── Project type detection ───────────────────────────────────────────────────

func detectDeployType(path string) deployTypeInfo {
	base := filepath.Base(path)

	// Explicit .next directory
	if base == ".next" {
		return deployTypeInfo{
			Type:  "nextjs",
			Label: "Next.js",
			Hint:  "make sure you ran: npm run build",
		}
	}

	// .next inside the directory
	if _, err := os.Stat(filepath.Join(path, ".next")); err == nil {
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

	return deployTypeInfo{Type: "static", Label: "Static site"}
}

// ── Zip ──────────────────────────────────────────────────────────────────────

var deploySkipDirs = map[string]bool{
	"node_modules": true,
	".git":         true,
	".svn":         true,
	"vendor":       true, // PHP composer — include only if needed
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
