// deploy.go — handles mekong deploy: upload, list, stop static/nextjs/php sites.
// Each user gets 1 active deployment at a time (50MB max, 30-day TTL).
//
// Architecture: files are extracted to DeployDir/<subdomain>/ on the app server,
// then a local HTTP file server is started and an SSH reverse tunnel (identical to
// the mekong CLI protocol) forwards incoming connections from the tunnel server.
// No rsync, no file sync — everything runs from the app server.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/domain"
	"golang.org/x/crypto/ssh"
)

const (
	deployMaxBytes = 50 << 20 // 50MB per upload
	deployTTL      = 30 * 24 * time.Hour
)

// deployMaxPerPlan returns how many active deployments a plan allows.
func deployMaxPerPlan(plan string) int {
	switch plan {
	case "student":
		return 1
	case "pro":
		return 3
	case "enterprise", "team":
		return 10
	default:
		return 0 // free: no deployments
	}
}

// validDeployTypes is the set of accepted type values.
var validDeployTypes = map[string]bool{
	"static":     true,
	"nextjs":     true,
	"nextjs-api": true,
	"php":        true,
	"vue":        true,
	"react":      true,
	"react-vite": true,
}

// DeployHandler handles /api/deploy endpoints.
type DeployHandler struct {
	DB           *db.DB
	DeployDir    string // local staging dir e.g. /opt/mekong/deployments
	Domain       string // e.g. proxy.mekongtunnel.dev
	TunnelAddr   string // tunnel server SSH address e.g. "34.158.38.176:22"
	TunnelSecret string // shared tunnel-edge secret used to claim deployment subdomains

	// internal tunnel registry (populated at runtime)
	mu      sync.RWMutex
	tunnels map[string]*activeTunnel // subdomain → running tunnel
}

// activeTunnel tracks a running file-server + SSH reverse tunnel pair.
type activeTunnel struct {
	cancel     context.CancelFunc
	fileServer *http.Server
	logFile    *os.File
}

// tcpIPForwardReq is the SSH wire payload for the "tcpip-forward" global request.
type tcpIPForwardReq struct {
	BindAddr string
	BindPort uint32
}

// forwardedTCPIPData is the SSH wire payload for the "forwarded-tcpip" channel open.
type forwardedTCPIPData struct {
	DestAddr   string
	DestPort   uint32
	OriginAddr string
	OriginPort uint32
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

type deployRecord struct {
	ID             string     `db:"id"`
	UserID         string     `db:"user_id"`
	Subdomain      string     `db:"subdomain"`
	Domain         string     `db:"domain"`
	Type           string     `db:"type"`
	Status         string     `db:"status"`
	FilesPath      string     `db:"files_path"`
	SizeBytes      int64      `db:"size_bytes"`
	CreatedAt      time.Time  `db:"created_at"`
	ExpiresAt      *time.Time `db:"expires_at"`
	StoppedAt      *time.Time `db:"stopped_at"`
	RedeployCount  int        `db:"redeploy_count"`
	LastDeployedAt *time.Time `db:"last_deployed_at"`
}

func (r *deployRecord) URL() string {
	return "https://" + r.Subdomain + "." + r.Domain
}

// Init restores active deployments from DB on server startup.
// Call this once after creating the handler.
func (h *DeployHandler) Init(ctx context.Context) {
	if h.tunnels == nil {
		h.tunnels = make(map[string]*activeTunnel)
	}
	if h.TunnelAddr == "" {
		return
	}
	rows, err := h.DB.Pool.Query(ctx,
		`SELECT subdomain, files_path FROM deployments WHERE status='active' AND (expires_at IS NULL OR expires_at > now())`,
	)
	if err != nil {
		log.Printf("[deploy] init: failed to query active deployments: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var sub, filesPath string
		if err := rows.Scan(&sub, &filesPath); err != nil {
			continue
		}
		if _, err := os.Stat(filesPath); err != nil {
			continue // files missing, skip
		}
		log.Printf("[deploy] restoring tunnel for %s", sub)
		if err := h.startTunnel(sub, filesPath); err != nil {
			log.Printf("[deploy] restore failed for %s: %v", sub, err)
		}
	}
}

// Upload handles POST /api/deploy — receives a zip, extracts it, starts SSH tunnel.
func (h *DeployHandler) Upload(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	plan := claims.Plan
	maxDeploys := deployMaxPerPlan(plan)
	if maxDeploys == 0 {
		response.Forbidden(w, "deploy requires a student plan or higher — upgrade at mekongtunnel.dev/billing")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, deployMaxBytes+1024)
	if err := r.ParseMultipartForm(deployMaxBytes); err != nil {
		response.BadRequest(w, "archive too large — max 50MB")
		return
	}

	deployType := strings.ToLower(r.FormValue("type"))
	if deployType == "" {
		deployType = "static"
	}
	if !validDeployTypes[deployType] {
		response.BadRequest(w, "invalid type — must be one of: static, nextjs, nextjs-api, php, vue, react, react-vite")
		return
	}

	file, _, err := r.FormFile("archive")
	if err != nil {
		response.BadRequest(w, "missing archive file")
		return
	}
	defer file.Close()

	ctx := r.Context()
	active, err := h.countActiveDeployments(ctx, claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if active >= maxDeploys {
		// Stop oldest deployment to make room (or reject if pro/enterprise want strict limit)
		if err := h.stopOldestDeployment(ctx, claims.UserID); err != nil {
			response.Error(w, http.StatusConflict, fmt.Sprintf(
				"deployment limit reached (%d/%d for %s plan) — stop an existing deployment first",
				active, maxDeploys, plan,
			))
			return
		}
	}

	// Quota check
	quotaOK, usedBytes, quotaBytes, err := h.checkQuota(ctx, claims.UserID, int64(r.ContentLength))
	if err != nil {
		response.InternalError(w, err)
		return
	}
	if !quotaOK {
		response.Error(w, http.StatusPaymentRequired, fmt.Sprintf(
			"storage quota exceeded — used %s of %s quota. Purchase more storage at mekongtunnel.dev/billing",
			fmtMB(usedBytes), fmtMB(quotaBytes),
		))
		return
	}

	sub := strings.ToLower(strings.TrimSpace(r.FormValue("subdomain")))
	if sub != "" {
		for _, c := range sub {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				response.BadRequest(w, "subdomain may only contain lowercase letters, digits, and hyphens")
				return
			}
		}
		if len(sub) < 3 || len(sub) > 40 {
			response.BadRequest(w, "subdomain must be 3–40 characters")
			return
		}
		reserved := map[string]bool{
			"www": true, "api": true, "proxy": true, "admin": true,
			"mail": true, "smtp": true, "ftp": true, "ssh": true,
			"tunnel": true, "app": true, "dev": true, "staging": true,
			"dashboard": true, "billing": true, "static": true,
		}
		if reserved[sub] {
			response.BadRequest(w, "subdomain is reserved — choose a different name")
			return
		}
		existing, _ := h.getDeployment(ctx, sub)
		if existing != nil && existing.UserID != claims.UserID {
			response.BadRequest(w, "subdomain already taken")
			return
		}
	} else {
		sub, _ = domain.Generate()
	}

	deployPath := filepath.Join(h.DeployDir, sub)
	if err := os.MkdirAll(deployPath, 0755); err != nil {
		response.InternalError(w, err)
		return
	}
	_ = os.Remove(h.deployLogPath(sub))

	zipData, err := io.ReadAll(file)
	if err != nil {
		os.RemoveAll(deployPath)
		response.InternalError(w, err)
		return
	}

	if err := extractZip(zipData, deployPath); err != nil {
		os.RemoveAll(deployPath)
		response.BadRequest(w, "invalid zip archive: "+err.Error())
		return
	}

	sizeBytes := int64(len(zipData))
	expiresAt := time.Now().Add(deployTTL)

	rec, err := h.createDeployment(ctx, deployRecord{
		UserID:    claims.UserID,
		Subdomain: sub,
		Domain:    h.Domain,
		Type:      deployType,
		FilesPath: deployPath,
		SizeBytes: sizeBytes,
		ExpiresAt: &expiresAt,
	})
	if err != nil {
		os.RemoveAll(deployPath)
		response.InternalError(w, err)
		return
	}

	if err := h.startTunnel(sub, deployPath); err != nil {
		log.Printf("[deploy] tunnel start error for %s: %v", sub, err)
		_, _ = h.DB.Pool.Exec(ctx, `DELETE FROM deployments WHERE id=$1`, rec.ID)
		_ = os.RemoveAll(deployPath)
		response.InternalError(w, fmt.Errorf("start deployment tunnel: %w", err))
		return
	}

	_, usedAfter, quotaBytes, _ := h.checkQuota(ctx, claims.UserID, 0)
	response.Created(w, map[string]any{
		"id":          rec.ID,
		"url":         rec.URL(),
		"subdomain":   rec.Subdomain,
		"type":        rec.Type,
		"size_bytes":  rec.SizeBytes,
		"expires_at":  rec.ExpiresAt,
		"created_at":  rec.CreatedAt,
		"quota_used":  usedAfter,
		"quota_total": quotaBytes,
	})
}

// List handles GET /api/deploy — returns user's deployments.
func (h *DeployHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	recs, err := h.listDeployments(r.Context(), claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	_, used, total, _ := h.checkQuota(r.Context(), claims.UserID, 0)
	maxDeploys := deployMaxPerPlan(claims.Plan)

	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		h.mu.RLock()
		_, tunnelUp := h.tunnels[rec.Subdomain]
		h.mu.RUnlock()
		tunnelStatus := "down"
		if tunnelUp {
			tunnelStatus = "up"
		}
		out = append(out, map[string]any{
			"id":               rec.ID,
			"url":              rec.URL(),
			"subdomain":        rec.Subdomain,
			"type":             rec.Type,
			"status":           rec.Status,
			"tunnel":           tunnelStatus,
			"size_bytes":       rec.SizeBytes,
			"expires_at":       rec.ExpiresAt,
			"created_at":       rec.CreatedAt,
			"redeploy_count":   rec.RedeployCount,
			"last_deployed_at": rec.LastDeployedAt,
		})
	}

	response.Success(w, map[string]any{
		"deployments":     out,
		"quota_used":      used,
		"quota_total":     total,
		"max_deployments": maxDeploys,
	})
}

// Stop handles DELETE /api/deploy/{subdomain} — stops a deployment.
func (h *DeployHandler) Stop(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	sub := r.PathValue("subdomain")
	if sub == "" {
		response.BadRequest(w, "subdomain required")
		return
	}

	ctx := r.Context()
	rec, err := h.getDeployment(ctx, sub)
	if err != nil || rec == nil {
		response.NotFound(w, "deployment not found")
		return
	}
	if rec.UserID != claims.UserID && !claims.IsAdmin {
		response.Forbidden(w, "not your deployment")
		return
	}

	if err := h.stopDeployment(ctx, rec); err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"stopped": true, "subdomain": sub})
}

// Delete handles DELETE /api/deploy/{subdomain}/delete — stops and removes from DB.
func (h *DeployHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	sub := r.PathValue("subdomain")
	if sub == "" {
		response.BadRequest(w, "subdomain required")
		return
	}

	ctx := r.Context()
	rec, err := h.getDeployment(ctx, sub)
	if err != nil || rec == nil {
		response.NotFound(w, "deployment not found")
		return
	}
	if rec.UserID != claims.UserID && !claims.IsAdmin {
		response.Forbidden(w, "not your deployment")
		return
	}

	h.killTunnel(sub)
	if rec.FilesPath != "" {
		os.RemoveAll(rec.FilesPath)
	}
	_ = os.Remove(h.deployLogPath(sub))

	_, err = h.DB.Pool.Exec(ctx, `DELETE FROM deployments WHERE id=$1`, rec.ID)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	response.Success(w, map[string]any{"deleted": true, "subdomain": sub})
}

// Logs handles GET /api/deploy/{subdomain}/logs — returns deploy info and file list.
func (h *DeployHandler) Logs(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	sub := r.PathValue("subdomain")
	if sub == "" {
		response.BadRequest(w, "subdomain required")
		return
	}

	rec, err := h.getDeployment(r.Context(), sub)
	if err != nil || rec == nil {
		response.NotFound(w, "deployment not found")
		return
	}
	if rec.UserID != claims.UserID && !claims.IsAdmin {
		response.Forbidden(w, "not your deployment")
		return
	}

	var files []string
	if rec.FilesPath != "" {
		filepath.Walk(rec.FilesPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(rec.FilesPath, path)
			files = append(files, rel)
			return nil
		})
	}

	h.mu.RLock()
	_, tunnelUp := h.tunnels[sub]
	h.mu.RUnlock()

	tunnelStatus := "down"
	if tunnelUp {
		tunnelStatus = "up"
	}

	logs := fmt.Sprintf("Deployment: %s\nURL: %s\nType: %s\nStatus: %s\nTunnel: %s\nSize: %d bytes\nCreated: %s\n\nFiles (%d):\n",
		sub, rec.URL(), rec.Type, rec.Status, tunnelStatus, rec.SizeBytes, rec.CreatedAt.Format(time.RFC3339), len(files))
	for _, f := range files {
		logs += "  " + f + "\n"
	}
	logs += "\nRecent session logs:\n"
	recentLogs, err := readTailFile(h.deployLogPath(sub), 64<<10)
	if err != nil {
		if os.IsNotExist(err) {
			logs += "  No deploy logs yet.\n"
		} else {
			logs += "  Failed to read deploy logs: " + err.Error() + "\n"
		}
	} else if strings.TrimSpace(recentLogs) == "" {
		logs += "  No deploy logs yet.\n"
	} else {
		logs += recentLogs
		if !strings.HasSuffix(logs, "\n") {
			logs += "\n"
		}
	}

	response.Success(w, map[string]any{"logs": logs})
}

// Get handles GET /api/deploy/{subdomain} — returns a single deployment.
func (h *DeployHandler) Get(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	sub := r.PathValue("subdomain")
	if sub == "" {
		response.BadRequest(w, "subdomain required")
		return
	}
	rec, err := h.getDeployment(r.Context(), sub)
	if err != nil || rec == nil {
		response.NotFound(w, "deployment not found")
		return
	}
	if rec.UserID != claims.UserID && !claims.IsAdmin {
		response.Forbidden(w, "not your deployment")
		return
	}
	h.mu.RLock()
	_, tunnelUp := h.tunnels[sub]
	h.mu.RUnlock()
	tunnelStatus := "down"
	if tunnelUp {
		tunnelStatus = "up"
	}
	response.Success(w, map[string]any{
		"id":               rec.ID,
		"url":              rec.URL(),
		"subdomain":        rec.Subdomain,
		"type":             rec.Type,
		"status":           rec.Status,
		"tunnel":           tunnelStatus,
		"size_bytes":       rec.SizeBytes,
		"expires_at":       rec.ExpiresAt,
		"created_at":       rec.CreatedAt,
		"redeploy_count":   rec.RedeployCount,
		"last_deployed_at": rec.LastDeployedAt,
	})
}

// Redeploy handles PUT /api/deploy/{subdomain} — replaces files for an existing deployment.
func (h *DeployHandler) Redeploy(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	sub := r.PathValue("subdomain")
	if sub == "" {
		response.BadRequest(w, "subdomain required")
		return
	}

	ctx := r.Context()
	rec, err := h.getDeployment(ctx, sub)
	if err != nil || rec == nil {
		response.NotFound(w, "deployment not found")
		return
	}
	if rec.UserID != claims.UserID && !claims.IsAdmin {
		response.Forbidden(w, "not your deployment")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, deployMaxBytes+1024)
	if err := r.ParseMultipartForm(deployMaxBytes); err != nil {
		response.BadRequest(w, "archive too large — max 50MB")
		return
	}

	// Allow updating the type on redeploy
	newType := strings.ToLower(r.FormValue("type"))
	if newType == "" {
		newType = rec.Type
	}
	if !validDeployTypes[newType] {
		response.BadRequest(w, "invalid type — must be one of: static, nextjs, nextjs-api, php, vue, react, react-vite")
		return
	}

	file, _, err := r.FormFile("archive")
	if err != nil {
		response.BadRequest(w, "missing archive file")
		return
	}
	defer file.Close()

	zipData, err := io.ReadAll(file)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	deployPath := rec.FilesPath
	if deployPath == "" {
		deployPath = filepath.Join(h.DeployDir, sub)
	}

	// Clear existing files and re-extract
	if err := os.RemoveAll(deployPath); err != nil {
		response.InternalError(w, err)
		return
	}
	if err := os.MkdirAll(deployPath, 0755); err != nil {
		response.InternalError(w, err)
		return
	}
	if err := extractZip(zipData, deployPath); err != nil {
		response.BadRequest(w, "invalid zip archive: "+err.Error())
		return
	}

	now := time.Now()
	newExpiry := now.Add(deployTTL) // reset TTL on redeploy
	_, err = h.DB.Pool.Exec(ctx,
		`UPDATE deployments
		 SET type=$1, size_bytes=$2, status='active', expires_at=$3,
		     redeploy_count = redeploy_count + 1, last_deployed_at=$4
		 WHERE id=$5`,
		newType, int64(len(zipData)), newExpiry, now, rec.ID,
	)
	if err != nil {
		response.InternalError(w, err)
		return
	}

	// Restart the tunnel with fresh files
	if err := h.startTunnel(sub, deployPath); err != nil {
		log.Printf("[deploy] redeploy tunnel restart error for %s: %v", sub, err)
	}

	response.Success(w, map[string]any{
		"redeployed": true,
		"subdomain":  sub,
		"url":        rec.URL(),
		"type":       newType,
		"size_bytes": int64(len(zipData)),
		"expires_at": newExpiry,
	})
}

// QuotaInfo handles GET /api/deploy/quota — returns user's storage quota and usage.
func (h *DeployHandler) QuotaInfo(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}
	_, used, total, err := h.checkQuota(r.Context(), claims.UserID, 0)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	maxDeploys := deployMaxPerPlan(claims.Plan)
	active, _ := h.countActiveDeployments(r.Context(), claims.UserID)
	response.Success(w, map[string]any{
		"used_bytes":         used,
		"quota_bytes":        total,
		"free_bytes":         total - used,
		"used_mb":            used / (1 << 20),
		"quota_mb":           total / (1 << 20),
		"plan":               claims.Plan,
		"max_deployments":    maxDeploys,
		"active_deployments": active,
	})
}

// ── SSH reverse tunnel ───────────────────────────────────────────────────────

// startTunnel starts a local file server and SSH reverse tunnel for subdomain.
func (h *DeployHandler) startTunnel(subdomain, filesPath string) error {
	if strings.TrimSpace(h.TunnelAddr) == "" {
		return fmt.Errorf("DEPLOY_TUNNEL_ADDR is required")
	}
	if strings.TrimSpace(h.TunnelSecret) == "" {
		return fmt.Errorf("TUNNEL_EDGE_SECRET is required for deployment tunnels")
	}
	if h.tunnels == nil {
		h.mu.Lock()
		h.tunnels = make(map[string]*activeTunnel)
		h.mu.Unlock()
	}

	// Kill any existing tunnel for this subdomain
	h.killTunnel(subdomain)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen local file server: %w", err)
	}
	localPort := ln.Addr().(*net.TCPAddr).Port
	if err := os.MkdirAll(h.deployLogsDir(), 0755); err != nil {
		ln.Close()
		return fmt.Errorf("create deploy log dir: %w", err)
	}
	logFile, err := os.OpenFile(h.deployLogPath(subdomain), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		ln.Close()
		return fmt.Errorf("open deploy log file: %w", err)
	}
	logWriter := &lockedWriter{w: logFile}
	_, _ = fmt.Fprintf(logWriter, "\n[%s] starting deploy tunnel for %s\n", time.Now().UTC().Format(time.RFC3339), subdomain)

	fs := &http.Server{
		Handler: http.FileServer(http.Dir(filesPath)),
	}

	ctx, cancel := context.WithCancel(context.Background())
	tunnelRef := &activeTunnel{cancel: cancel, fileServer: fs, logFile: logFile}
	readyCh := make(chan error, 1)

	h.mu.Lock()
	h.tunnels[subdomain] = tunnelRef
	h.mu.Unlock()

	go func() {
		defer ln.Close()
		if err := fs.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("[deploy] file server %s error: %v", subdomain, err)
		}
	}()

	go func() {
		defer func() {
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutCancel()
			fs.Shutdown(shutCtx)
			if logFile != nil {
				_ = logFile.Close()
			}

			h.mu.Lock()
			if t, ok := h.tunnels[subdomain]; ok && t == tunnelRef {
				delete(h.tunnels, subdomain)
			}
			h.mu.Unlock()
		}()

		backoff := time.Second
		notifyReady := readyCh
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			err := h.runSSHTunnel(ctx, subdomain, localPort, notifyReady, logWriter)
			notifyReady = nil
			if ctx.Err() != nil {
				return
			}
			_, _ = fmt.Fprintf(logWriter, "[%s] deploy tunnel disconnected: %v\n", time.Now().UTC().Format(time.RFC3339), err)
			log.Printf("[deploy] tunnel %s disconnected (%v), reconnecting in %s", subdomain, err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 60*time.Second {
				backoff *= 2
			}
		}
	}()

	select {
	case err := <-readyCh:
		if err != nil {
			h.killTunnel(subdomain)
			return err
		}
	case <-time.After(10 * time.Second):
		h.killTunnel(subdomain)
		return fmt.Errorf("timed out establishing deployment tunnel")
	}

	return nil
}

// killTunnel stops the file server + SSH tunnel for a subdomain.
func (h *DeployHandler) killTunnel(subdomain string) {
	h.mu.Lock()
	t, ok := h.tunnels[subdomain]
	if ok {
		delete(h.tunnels, subdomain)
	}
	h.mu.Unlock()

	if ok {
		t.cancel()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t.fileServer.Shutdown(shutCtx)
		if t.logFile != nil {
			_ = t.logFile.Close()
		}
	}
}

// runSSHTunnel opens one SSH connection and handles forwarded channels until ctx is done or error.
func (h *DeployHandler) runSSHTunnel(ctx context.Context, subdomain string, localPort int, ready chan<- error, logWriter io.Writer) error {
	sshCfg := &ssh.ClientConfig{
		User:            "tunnel",
		Auth:            []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         30 * time.Second,
	}

	dialer := &net.Dialer{}
	netConn, err := dialer.DialContext(ctx, "tcp", h.TunnelAddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	_, _ = fmt.Fprintf(logWriter, "[%s] dialing tunnel server %s\n", time.Now().UTC().Format(time.RFC3339), h.TunnelAddr)

	conn, chans, reqs, err := ssh.NewClientConn(netConn, h.TunnelAddr, sshCfg)
	if err != nil {
		netConn.Close()
		return fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	// Request reverse port forward on port 80
	payload := ssh.Marshal(tcpIPForwardReq{BindAddr: "", BindPort: 80})
	ok, _, err := client.SendRequest("tcpip-forward", true, payload)
	if err != nil {
		return fmt.Errorf("tcpip-forward: %w", err)
	}
	if !ok {
		return fmt.Errorf("tcpip-forward rejected by server")
	}

	// Handle incoming forwarded channels → proxy to local file server
	fwdChans := client.HandleChannelOpen("forwarded-tcpip")
	go func() {
		for nc := range fwdChans {
			var d forwardedTCPIPData
			if err := ssh.Unmarshal(nc.ExtraData(), &d); err != nil {
				nc.Reject(ssh.Prohibited, "bad payload")
				continue
			}
			ch, _, err := nc.Accept()
			if err != nil {
				continue
			}
			go deployProxyToLocal(ch, localPort)
		}
	}()

	// Open session and set subdomain env vars
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	defer stdin.Close()

	_ = sess.Setenv("MEKONG_DEPLOY_SUBDOMAIN", subdomain)
	_ = sess.Setenv("MEKONG_TUNNEL_EDGE_SECRET", h.TunnelSecret)
	_ = sess.Setenv("MEKONG_SKIP_WARNING", "1")
	_ = sess.Setenv("MEKONG_LOCAL_PORT", strconv.Itoa(localPort))

	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}
	if err := sess.RequestPty("xterm-256color", 40, 120, modes); err != nil {
		return fmt.Errorf("pty: %w", err)
	}
	if err := sess.Shell(); err != nil {
		if ready != nil {
			ready <- fmt.Errorf("shell: %w", err)
		}
		return fmt.Errorf("shell: %w", err)
	}

	log.Printf("[deploy] tunnel established: %s → 127.0.0.1:%d", subdomain, localPort)
	_, _ = fmt.Fprintf(logWriter, "[%s] tunnel established for %s on local port %d\n", time.Now().UTC().Format(time.RFC3339), subdomain, localPort)

	waitCh := make(chan error, 1)
	go func() { waitCh <- sess.Wait() }()

	startupTimer := time.NewTimer(1500 * time.Millisecond)
	defer startupTimer.Stop()

	select {
	case err := <-waitCh:
		if ready != nil {
			ready <- fmt.Errorf("deployment tunnel rejected: %w", err)
		}
		return err
	case <-startupTimer.C:
		if ready != nil {
			ready <- nil
		}
	case <-ctx.Done():
		if ready != nil {
			ready <- ctx.Err()
		}
		return nil
	}

	go func() { _, _ = io.Copy(logWriter, stdout) }()
	go func() { _, _ = io.Copy(logWriter, stderr) }()

	// Wait for context cancellation or session end
	select {
	case <-ctx.Done():
		return nil
	case err := <-waitCh:
		return err
	}
}

// deployProxyToLocal proxies an SSH channel to localhost:port.
func deployProxyToLocal(ch ssh.Channel, port int) {
	defer ch.Close()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(conn, ch)
		conn.(*net.TCPConn).CloseWrite() //nolint:errcheck
	}()
	go func() {
		defer wg.Done()
		io.Copy(ch, conn)
		ch.CloseWrite() //nolint:errcheck
	}()
	wg.Wait()
}

func (h *DeployHandler) deployLogsDir() string {
	return filepath.Join(h.DeployDir, ".deploy-logs")
}

func (h *DeployHandler) deployLogPath(subdomain string) string {
	return filepath.Join(h.deployLogsDir(), subdomain+".log")
}

func readTailFile(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}

	start := int64(0)
	if info.Size() > maxBytes {
		start = info.Size() - maxBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return "", err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	if start > 0 {
		if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
			data = data[idx+1:]
		}
	}
	return string(data), nil
}

// ── ZIP extraction ───────────────────────────────────────────────────────────

func extractZip(data []byte, dest string) error {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}

	for _, f := range r.File {
		name := filepath.Clean(f.Name)
		if strings.HasPrefix(name, "..") {
			continue
		}

		outPath := filepath.Join(dest, name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(outPath, 0755)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		out, err := os.Create(outPath)
		if err != nil {
			rc.Close()
			return err
		}

		_, err = io.Copy(out, rc)
		out.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// ── DB helpers ───────────────────────────────────────────────────────────────

func (h *DeployHandler) countActiveDeployments(ctx context.Context, userID string) (int, error) {
	var count int
	err := h.DB.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM deployments WHERE user_id=$1 AND status='active'`,
		userID,
	).Scan(&count)
	return count, err
}

func (h *DeployHandler) listDeployments(ctx context.Context, userID string) ([]deployRecord, error) {
	rows, err := h.DB.Pool.Query(ctx,
		`SELECT id, user_id, subdomain, domain, type, status, files_path, size_bytes,
		        created_at, expires_at, stopped_at, redeploy_count, last_deployed_at
		 FROM deployments WHERE user_id=$1 ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recs []deployRecord
	for rows.Next() {
		var r deployRecord
		if err := rows.Scan(&r.ID, &r.UserID, &r.Subdomain, &r.Domain, &r.Type,
			&r.Status, &r.FilesPath, &r.SizeBytes, &r.CreatedAt, &r.ExpiresAt,
			&r.StoppedAt, &r.RedeployCount, &r.LastDeployedAt); err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	return recs, rows.Err()
}

func (h *DeployHandler) getDeployment(ctx context.Context, subdomain string) (*deployRecord, error) {
	var r deployRecord
	err := h.DB.Pool.QueryRow(ctx,
		`SELECT id, user_id, subdomain, domain, type, status, files_path, size_bytes,
		        created_at, expires_at, stopped_at, redeploy_count, last_deployed_at
		 FROM deployments WHERE subdomain=$1`,
		subdomain,
	).Scan(&r.ID, &r.UserID, &r.Subdomain, &r.Domain, &r.Type,
		&r.Status, &r.FilesPath, &r.SizeBytes, &r.CreatedAt, &r.ExpiresAt,
		&r.StoppedAt, &r.RedeployCount, &r.LastDeployedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (h *DeployHandler) createDeployment(ctx context.Context, rec deployRecord) (*deployRecord, error) {
	err := h.DB.Pool.QueryRow(ctx,
		`INSERT INTO deployments (user_id, subdomain, domain, type, files_path, size_bytes, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, created_at`,
		rec.UserID, rec.Subdomain, rec.Domain, rec.Type, rec.FilesPath, rec.SizeBytes, rec.ExpiresAt,
	).Scan(&rec.ID, &rec.CreatedAt)
	return &rec, err
}

func (h *DeployHandler) stopDeployment(ctx context.Context, rec *deployRecord) error {
	now := time.Now()
	_, err := h.DB.Pool.Exec(ctx,
		`UPDATE deployments SET status='stopped', stopped_at=$1 WHERE id=$2`,
		now, rec.ID,
	)
	if err != nil {
		return err
	}
	h.killTunnel(rec.Subdomain)
	if rec.FilesPath != "" {
		os.RemoveAll(rec.FilesPath)
	}
	return nil
}

func (h *DeployHandler) stopUserDeployments(ctx context.Context, userID string) error {
	rows, err := h.DB.Pool.Query(ctx,
		`SELECT id, subdomain, files_path FROM deployments WHERE user_id=$1 AND status='active'`,
		userID,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var rec deployRecord
		if err := rows.Scan(&rec.ID, &rec.Subdomain, &rec.FilesPath); err != nil {
			continue
		}
		h.stopDeployment(ctx, &rec)
	}
	return rows.Err()
}

// stopOldestDeployment stops the oldest active deployment to free a slot.
func (h *DeployHandler) stopOldestDeployment(ctx context.Context, userID string) error {
	var rec deployRecord
	err := h.DB.Pool.QueryRow(ctx,
		`SELECT id, subdomain, files_path FROM deployments
		 WHERE user_id=$1 AND status='active'
		 ORDER BY created_at ASC LIMIT 1`,
		userID,
	).Scan(&rec.ID, &rec.Subdomain, &rec.FilesPath)
	if err != nil {
		return err
	}
	return h.stopDeployment(ctx, &rec)
}

// checkQuota returns (ok, usedBytes, quotaBytes, error).
// additionalBytes is the size of the new upload being considered (0 for info-only).
func (h *DeployHandler) checkQuota(ctx context.Context, userID string, additionalBytes int64) (bool, int64, int64, error) {
	var quotaBytes int64
	var usedBytes int64
	err := h.DB.Pool.QueryRow(ctx,
		`SELECT u.deploy_quota_bytes, COALESCE(SUM(d.size_bytes), 0)
		 FROM users u
		 LEFT JOIN deployments d ON d.user_id = u.id AND d.status = 'active'
		 WHERE u.id = $1
		 GROUP BY u.deploy_quota_bytes`,
		userID,
	).Scan(&quotaBytes, &usedBytes)
	if err != nil {
		return false, 0, 0, err
	}
	return usedBytes+additionalBytes <= quotaBytes, usedBytes, quotaBytes, nil
}

func fmtMB(b int64) string {
	if b < 1<<20 {
		return fmt.Sprintf("%d KB", b>>10)
	}
	return fmt.Sprintf("%d MB", b>>20)
}

// caddyAddRoute is a no-op stub kept for interface compatibility (Caddy not used).
func (h *DeployHandler) caddyAddRoute(subdomain, filesPath, deployType string) error {
	return nil
}

// caddyRemoveRoute is a no-op stub kept for interface compatibility (Caddy not used).
func (h *DeployHandler) caddyRemoveRoute(subdomain string) error {
	return nil
}

// marshal is a local alias so the handlers package doesn't need encoding/json at the top level.
var _ = json.Marshal
