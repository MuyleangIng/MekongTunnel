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
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/api/middleware"
	"github.com/MuyleangIng/MekongTunnel/internal/api/response"
	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/domain"
	"github.com/MuyleangIng/MekongTunnel/internal/notify"
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
	case "org", "enterprise", "team":
		return 10
	default:
		return 0 // free: no deployments
	}
}

// deployBaseQuotaBytes returns the plan's base storage quota in bytes.
// This is the floor for new users on that plan; purchased add-ons can raise it further.
func deployBaseQuotaBytes(plan string) int64 {
	switch plan {
	case "student":
		return 100 << 20 // 100 MB
	case "pro":
		return 512 << 20 // 512 MB
	case "org", "enterprise", "team":
		return 2 << 30 // 2 GB
	default:
		return 0 // free: no deploy storage
	}
}

// validDeployTypes is the set of accepted type values.
var validDeployTypes = map[string]bool{
	"static":            true,
	"nextjs":            true,
	"nextjs-api":        true,
	"nextjs-standalone": true,
	"php":               true,
	"vue":               true,
	"docs":              true,
	"react":             true,
	"react-vite":        true,
}

// DeployHandler handles /api/deploy endpoints.
type DeployHandler struct {
	DB           *db.DB
	DeployDir    string // local staging dir e.g. /opt/mekong/deployments
	Domain       string // e.g. proxy.mekongtunnel.dev
	TunnelAddr   string // tunnel server SSH address e.g. "34.158.38.176:22"
	TunnelSecret string // shared tunnel-edge secret used to claim deployment subdomains
	Notify       *notify.Service

	// internal tunnel registry (populated at runtime)
	mu      sync.RWMutex
	tunnels map[string]*activeTunnel // subdomain → running tunnel
}

// activeTunnel tracks a running file-server (or node process) + SSH reverse tunnel pair.
type activeTunnel struct {
	cancel     context.CancelFunc
	fileServer *http.Server  // set for static/nextjs/php types
	nodeProc   *exec.Cmd     // set for nextjs-standalone type
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

// ansiStripWriter strips ANSI escape sequences before passing bytes to the
// wrapped writer. Used so deploy log files stay human-readable plain text.
type ansiStripWriter struct{ w io.Writer }

// ansiEscapeRe matches ANSI CSI escape sequences (colours, cursor moves, etc.)
var ansiEscapeRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b[^[]`)

func (a *ansiStripWriter) Write(p []byte) (int, error) {
	clean := ansiEscapeRe.ReplaceAll(p, nil)
	_, err := a.w.Write(clean)
	return len(p), err // always report original len so callers don't think it's short
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
		`SELECT subdomain, files_path, type FROM deployments WHERE status='active' AND (expires_at IS NULL OR expires_at > now())`,
	)
	if err != nil {
		log.Printf("[deploy] init: failed to query active deployments: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var sub, filesPath, deployType string
		if err := rows.Scan(&sub, &filesPath, &deployType); err != nil {
			continue
		}
		if _, err := os.Stat(filesPath); err != nil {
			continue // files missing, skip
		}
		log.Printf("[deploy] restoring tunnel for %s (%s)", sub, deployType)
		if err := h.startTunnel(sub, filesPath, deployType); err != nil {
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
		response.BadRequest(w, "invalid type — must be one of: static, nextjs, nextjs-standalone, nextjs-api, php, vue, react, react-vite")
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
		// For a NEW deployment (no existing owned deployment at this subdomain),
		// check that the combined subdomain quota (reserved + deployments) is not exceeded.
		if existing == nil || existing.Status == "deleted" {
			var subLimitVal int
			_ = h.DB.Pool.QueryRow(ctx,
				`SELECT COALESCE((config->>'maxReservedSubdomains')::int, 0) FROM plan_configs WHERE plan_id=$1`,
				claims.Plan,
			).Scan(&subLimitVal)
			if !claims.IsAdmin && subLimitVal > 0 {
				var reservedCount, deployCount int
				_ = h.DB.Pool.QueryRow(ctx,
					`SELECT COUNT(*) FROM reserved_subdomains WHERE user_id=$1 AND team_id IS NULL`,
					claims.UserID,
				).Scan(&reservedCount)
				_ = h.DB.Pool.QueryRow(ctx,
					`SELECT COUNT(*) FROM deployments WHERE user_id=$1 AND status != 'deleted'`,
					claims.UserID,
				).Scan(&deployCount)
				if reservedCount+deployCount >= subLimitVal {
					response.Error(w, http.StatusPaymentRequired, fmt.Sprintf(
						"subdomain limit reached: your %s plan allows %d subdomain(s) total (reserved + deployments)",
						claims.Plan, subLimitVal,
					))
					return
				}
			}
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

	if err := h.startTunnel(sub, deployPath, deployType); err != nil {
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

	// Build structured lines for the dashboard to render with colour coding.
	type logLine struct {
		Kind string `json:"kind"` // "meta" | "req" | "info" | "warn" | "err"
		Text string `json:"text"`
	}

	var lines []logLine

	// Meta header
	lines = append(lines,
		logLine{"meta", fmt.Sprintf("subdomain  %s", sub)},
		logLine{"meta", fmt.Sprintf("url        %s", rec.URL())},
		logLine{"meta", fmt.Sprintf("type       %s", rec.Type)},
		logLine{"meta", fmt.Sprintf("status     %s  tunnel:%s", rec.Status, tunnelStatus)},
		logLine{"meta", fmt.Sprintf("size       %s", fmtMB(rec.SizeBytes))},
		logLine{"meta", fmt.Sprintf("created    %s", rec.CreatedAt.Format("2006-01-02 15:04 UTC"))},
	)

	// Session logs from file
	rawLogs, err := readTailFile(h.deployLogPath(sub), 64<<10)
	if err != nil || strings.TrimSpace(rawLogs) == "" {
		lines = append(lines, logLine{"info", "no session logs yet"})
	} else {
		for _, rawLine := range strings.Split(strings.TrimRight(rawLogs, "\n"), "\n") {
			line := strings.TrimRight(rawLine, "\r")
			if line == "" {
				continue
			}
			kind := classifyLogLine(line)
			lines = append(lines, logLine{kind, line})
		}
	}

	response.Success(w, map[string]any{"logs": rawLogs, "lines": lines})
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
		"id":             rec.ID,
		"url":            rec.URL(),
		"subdomain":      rec.Subdomain,
		"type":           rec.Type,
		"status":         rec.Status,
		"tunnel":         tunnelStatus,
		"size_bytes":     rec.SizeBytes,
		"expires_at":     rec.ExpiresAt,
		"created_at":     rec.CreatedAt,
		"redeploy_count": rec.RedeployCount,
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
	if err := h.startTunnel(sub, deployPath, newType); err != nil {
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
		"used_bytes":       used,
		"quota_bytes":      total,
		"free_bytes":       total - used,
		"used_mb":          used / (1 << 20),
		"quota_mb":         total / (1 << 20),
		"plan":             claims.Plan,
		"max_deployments":  maxDeploys,
		"active_deployments": active,
	})
}

// ── Admin deploy endpoints ───────────────────────────────────────────────────

// AdminListDeployments handles GET /api/admin/deployments — all users' deployments.
func (h *DeployHandler) AdminListDeployments(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	statusFilter := r.URL.Query().Get("status")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50
	offset := 0
	if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
		offset = v
	}

	where := `WHERE 1=1`
	args := []any{}
	idx := 1

	if search != "" {
		where += fmt.Sprintf(` AND (d.subdomain ILIKE $%d OR u.email ILIKE $%d OR u.name ILIKE $%d)`, idx, idx, idx)
		args = append(args, "%"+search+"%")
		idx++
	}
	if statusFilter != "" && statusFilter != "all" {
		where += fmt.Sprintf(` AND d.status = $%d`, idx)
		args = append(args, statusFilter)
		idx++
	}

	countArgs := make([]any, len(args))
	copy(countArgs, args)
	var total int
	_ = h.DB.Pool.QueryRow(r.Context(),
		`SELECT COUNT(*) FROM deployments d JOIN users u ON u.id = d.user_id `+where,
		countArgs...,
	).Scan(&total)

	limitOffsetArgs := append(args, limit, offset)
	rows, err := h.DB.Pool.Query(r.Context(), `
		SELECT d.id, d.user_id, u.name AS user_name, u.email AS user_email, u.plan AS user_plan,
		       d.subdomain, d.domain, d.type, d.status, d.size_bytes,
		       d.created_at, d.expires_at, d.stopped_at, d.redeploy_count, d.last_deployed_at
		FROM deployments d
		JOIN users u ON u.id = d.user_id
		`+where+fmt.Sprintf(` ORDER BY d.created_at DESC LIMIT $%d OFFSET $%d`, idx, idx+1),
		limitOffsetArgs...,
	)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	defer rows.Close()

	type adminDeploy struct {
		ID             string     `json:"id"`
		UserID         string     `json:"user_id"`
		UserName       string     `json:"user_name"`
		UserEmail      string     `json:"user_email"`
		UserPlan       string     `json:"user_plan"`
		Subdomain      string     `json:"subdomain"`
		Domain         string     `json:"domain"`
		Type           string     `json:"type"`
		Status         string     `json:"status"`
		SizeBytes      int64      `json:"size_bytes"`
		CreatedAt      time.Time  `json:"created_at"`
		ExpiresAt      *time.Time `json:"expires_at"`
		StoppedAt      *time.Time `json:"stopped_at"`
		RedeployCount  int        `json:"redeploy_count"`
		LastDeployedAt *time.Time `json:"last_deployed_at"`
		TunnelStatus   string     `json:"tunnel_status"`
		URL            string     `json:"url"`
	}

	var deployments []adminDeploy
	for rows.Next() {
		var d adminDeploy
		if err := rows.Scan(
			&d.ID, &d.UserID, &d.UserName, &d.UserEmail, &d.UserPlan,
			&d.Subdomain, &d.Domain, &d.Type, &d.Status, &d.SizeBytes,
			&d.CreatedAt, &d.ExpiresAt, &d.StoppedAt, &d.RedeployCount, &d.LastDeployedAt,
		); err != nil {
			continue
		}
		h.mu.RLock()
		_, tunnelUp := h.tunnels[d.Subdomain]
		h.mu.RUnlock()
		d.TunnelStatus = "down"
		if tunnelUp {
			d.TunnelStatus = "up"
		}
		d.URL = "https://" + d.Subdomain + "." + d.Domain
		deployments = append(deployments, d)
	}
	if deployments == nil {
		deployments = []adminDeploy{}
	}

	// Stats
	var statsActive, statsTotal int
	_ = h.DB.Pool.QueryRow(r.Context(), `SELECT COUNT(*) FROM deployments`).Scan(&statsTotal)
	_ = h.DB.Pool.QueryRow(r.Context(), `SELECT COUNT(*) FROM deployments WHERE status='active'`).Scan(&statsActive)

	response.Success(w, map[string]any{
		"deployments": deployments,
		"total":       total,
		"limit":       limit,
		"offset":      offset,
		"stats": map[string]any{
			"total":  statsTotal,
			"active": statsActive,
		},
	})
}

// AdminGetUserDeployments handles GET /api/admin/users/{id}/deployments.
func (h *DeployHandler) AdminGetUserDeployments(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		response.BadRequest(w, "user id required")
		return
	}

	recs, err := h.listDeployments(r.Context(), userID)
	if err != nil {
		response.InternalError(w, err)
		return
	}

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
	response.Success(w, map[string]any{"deployments": out})
}

// ── Quota request endpoints ──────────────────────────────────────────────────

// SubmitQuotaRequest handles POST /api/user/quota-request.
func (h *DeployHandler) SubmitQuotaRequest(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Type      string `json:"type"`      // deployments | storage | subdomains | tunnels
		Reason    string `json:"reason"`
		Requested int    `json:"requested"` // how many extra
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	validTypes := map[string]bool{"deployments": true, "storage": true, "subdomains": true, "tunnels": true, "extension": true}
	if !validTypes[body.Type] {
		response.BadRequest(w, "type must be deployments, storage, subdomains, tunnels, or extension")
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		response.BadRequest(w, "reason is required")
		return
	}
	if body.Requested <= 0 {
		body.Requested = 1
	}
	if body.Requested > 10 {
		body.Requested = 10
	}

	var id string
	var createdAt time.Time
	err := h.DB.Pool.QueryRow(r.Context(),
		`INSERT INTO quota_requests (user_id, type, reason, requested)
		 VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
		claims.UserID, body.Type, body.Reason, body.Requested,
	).Scan(&id, &createdAt)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	response.Created(w, map[string]any{"id": id, "created_at": createdAt, "status": "pending"})
}

// GetMyQuotaRequests handles GET /api/user/quota-requests — returns the caller's own requests.
func (h *DeployHandler) GetMyQuotaRequests(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	rows, err := h.DB.Pool.Query(r.Context(), `
		SELECT id, type, reason, requested, status, admin_note, reviewed_at, created_at
		FROM quota_requests
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT 10
	`, claims.UserID)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	defer rows.Close()

	type qr struct {
		ID         string     `json:"id"`
		Type       string     `json:"type"`
		Reason     string     `json:"reason"`
		Requested  int        `json:"requested"`
		Status     string     `json:"status"`
		AdminNote  *string    `json:"admin_note"`
		ReviewedAt *time.Time `json:"reviewed_at"`
		CreatedAt  time.Time  `json:"created_at"`
	}
	var list []qr
	for rows.Next() {
		var q qr
		if err := rows.Scan(&q.ID, &q.Type, &q.Reason, &q.Requested, &q.Status, &q.AdminNote, &q.ReviewedAt, &q.CreatedAt); err != nil {
			continue
		}
		list = append(list, q)
	}
	if list == nil {
		list = []qr{}
	}
	response.Success(w, map[string]any{"requests": list})
}

// AdminListQuotaRequests handles GET /api/admin/quota-requests.
func (h *DeployHandler) AdminListQuotaRequests(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")

	where := `WHERE 1=1`
	args := []any{}
	idx := 1
	if statusFilter != "" && statusFilter != "all" {
		where += fmt.Sprintf(` AND qr.status = $%d`, idx)
		args = append(args, statusFilter)
		idx++
	}

	rows, err := h.DB.Pool.Query(r.Context(), `
		SELECT qr.id, qr.user_id, u.name AS user_name, u.email AS user_email, u.plan AS user_plan,
		       qr.type, qr.reason, qr.requested, qr.status, qr.admin_note,
		       qr.reviewed_at, qr.created_at
		FROM quota_requests qr
		JOIN users u ON u.id = qr.user_id
		`+where+` ORDER BY qr.created_at DESC`,
		args...,
	)
	if err != nil {
		response.InternalError(w, err)
		return
	}
	defer rows.Close()

	type qrRow struct {
		ID         string     `json:"id"`
		UserID     string     `json:"user_id"`
		UserName   string     `json:"user_name"`
		UserEmail  string     `json:"user_email"`
		UserPlan   string     `json:"user_plan"`
		Type       string     `json:"type"`
		Reason     string     `json:"reason"`
		Requested  int        `json:"requested"`
		Status     string     `json:"status"`
		AdminNote  *string    `json:"admin_note"`
		ReviewedAt *time.Time `json:"reviewed_at"`
		CreatedAt  time.Time  `json:"created_at"`
	}
	var list []qrRow
	for rows.Next() {
		var q qrRow
		if err := rows.Scan(&q.ID, &q.UserID, &q.UserName, &q.UserEmail, &q.UserPlan,
			&q.Type, &q.Reason, &q.Requested, &q.Status, &q.AdminNote,
			&q.ReviewedAt, &q.CreatedAt); err != nil {
			continue
		}
		list = append(list, q)
	}
	if list == nil {
		list = []qrRow{}
	}
	response.Success(w, map[string]any{"requests": list})
}

// AdminReviewQuotaRequest handles PATCH /api/admin/quota-requests/{id} — approve or deny.
func (h *DeployHandler) AdminReviewQuotaRequest(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		response.BadRequest(w, "id required")
		return
	}
	claims := middleware.GetClaims(r)
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return
	}

	var body struct {
		Status          string `json:"status"`           // approved | denied
		AdminNote       string `json:"admin_note"`
		ExtensionMonths int    `json:"extension_months"` // for extension type: months to add (0 = use weeks or default)
		ExtensionWeeks  int    `json:"extension_weeks"`  // for extension type: weeks to add (used if months == 0)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.BadRequest(w, "invalid JSON body")
		return
	}
	if body.Status != "approved" && body.Status != "denied" {
		response.BadRequest(w, "status must be approved or denied")
		return
	}

	// Fetch request before updating so we can act on type/user_id
	var req struct {
		UserID    string
		ReqType   string
		Requested int
	}
	if err := h.DB.Pool.QueryRow(r.Context(),
		`SELECT user_id, type, requested FROM quota_requests WHERE id=$1`, id,
	).Scan(&req.UserID, &req.ReqType, &req.Requested); err != nil {
		response.NotFound(w, "quota request not found")
		return
	}

	now := time.Now()
	res, err := h.DB.Pool.Exec(r.Context(),
		`UPDATE quota_requests SET status=$1, admin_note=$2, reviewed_by=$3, reviewed_at=$4, updated_at=$4
		 WHERE id=$5`,
		body.Status, body.AdminNote, claims.UserID, now, id,
	)
	if err != nil || res.RowsAffected() == 0 {
		response.NotFound(w, "quota request not found")
		return
	}

	// If approved and type is "extension", extend plan_expires_at by admin-chosen duration.
	// Default: 6 months if neither months nor weeks specified.
	extDesc := ""
	if body.Status == "approved" && req.ReqType == "extension" {
		var currentExpiry *time.Time
		_ = h.DB.Pool.QueryRow(r.Context(),
			`SELECT plan_expires_at FROM users WHERE id=$1`, req.UserID,
		).Scan(&currentExpiry)

		base := now
		if currentExpiry != nil && currentExpiry.After(now) {
			base = *currentExpiry
		}

		var newExpiry time.Time
		switch {
		case body.ExtensionWeeks > 0:
			newExpiry = base.AddDate(0, 0, body.ExtensionWeeks*7)
			extDesc = fmt.Sprintf("%d week(s)", body.ExtensionWeeks)
		case body.ExtensionMonths > 0:
			newExpiry = base.AddDate(0, body.ExtensionMonths, 0)
			extDesc = fmt.Sprintf("%d month(s)", body.ExtensionMonths)
		default:
			newExpiry = base.AddDate(0, 6, 0) // default 6 months
			extDesc = "6 months"
		}

		if _, err := h.DB.Pool.Exec(r.Context(),
			`UPDATE users SET plan_expires_at=$1, updated_at=now() WHERE id=$2`,
			newExpiry, req.UserID,
		); err != nil {
			log.Printf("[deploy] failed to extend plan for user %s: %v", req.UserID, err)
		}
	}

	// Notify user of outcome
	if h.Notify != nil {
		notifType := "quota_request_denied"
		title := "Quota request denied"
		msg := "Your resource request was not approved."
		if body.Status == "approved" {
			notifType = "quota_request_approved"
			title = "Quota request approved"
			msg = "Your request for extra " + req.ReqType + " has been approved."
			if req.ReqType == "extension" {
				msg = "Your student plan has been extended by " + extDesc + "."
			}
		}
		if body.AdminNote != "" {
			msg += " Note: " + body.AdminNote
		}
		go h.Notify.Send(context.Background(), req.UserID, notifType, title, msg, "/dashboard/settings")
	}

	response.Success(w, map[string]any{"status": body.Status, "reviewed_at": now})
}

// ── SSH reverse tunnel ───────────────────────────────────────────────────────

// startTunnel starts a local file server (or node process) and SSH reverse tunnel for subdomain.
// deployType drives which backend is used: "nextjs-standalone" runs node server.js,
// all other types use http.FileServer.
func (h *DeployHandler) startTunnel(subdomain, filesPath, deployType string) error {
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

	// Grab a free local port. For the static file server we keep the listener open
	// and hand it directly to http.Server.Serve — no rebind race. For nextjs-standalone
	// we close it and pass PORT to node (node does its own bind).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen local port: %w", err)
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
	logWriter := &lockedWriter{w: &ansiStripWriter{w: logFile}}
	_, _ = fmt.Fprintf(logWriter, "\n[%s] starting deploy tunnel for %s (type=%s)\n", time.Now().UTC().Format(time.RFC3339), subdomain, deployType)

	ctx, cancel := context.WithCancel(context.Background())
	tunnelRef := &activeTunnel{cancel: cancel, logFile: logFile}
	readyCh := make(chan error, 1)

	h.mu.Lock()
	h.tunnels[subdomain] = tunnelRef
	h.mu.Unlock()

	if deployType == "nextjs-standalone" {
		// Release the port so node can bind it.
		ln.Close()

		nodeBin, err := resolveNodeBin()
		if err != nil {
			cancel()
			logFile.Close()
			return fmt.Errorf("node not found on server — install Node.js to run nextjs-standalone deployments: %w", err)
		}

		serverJS := filepath.Join(filesPath, "server.js")
		if _, err := os.Stat(serverJS); err != nil {
			cancel()
			logFile.Close()
			return fmt.Errorf("server.js not found in archive root — zip the .next/standalone/ directory")
		}

		cmd := exec.CommandContext(ctx, nodeBin, serverJS)
		cmd.Dir = filesPath
		cmd.Env = append(os.Environ(),
			fmt.Sprintf("PORT=%d", localPort),
			"HOSTNAME=127.0.0.1",
			"NODE_ENV=production",
		)
		cmd.Stdout = logWriter
		cmd.Stderr = logWriter
		tunnelRef.nodeProc = cmd
		if err := cmd.Start(); err != nil {
			cancel()
			logFile.Close()
			return fmt.Errorf("start node server: %w", err)
		}
		_, _ = fmt.Fprintf(logWriter, "[%s] node server started on port %d (pid %d)\n",
			time.Now().UTC().Format(time.RFC3339), localPort, cmd.Process.Pid)
		go func() {
			if err := cmd.Wait(); err != nil && ctx.Err() == nil {
				log.Printf("[deploy] node server %s exited: %v", subdomain, err)
			}
		}()
	} else {
		// Static / docs file server: keep ln open and hand it to http.Server.Serve.
		var handler http.Handler
		if deployType == "docs" {
			handler = markdownDeployServer(filesPath)
		} else {
			handler = http.FileServer(http.Dir(filesPath))
		}
		fs := &http.Server{Handler: handler}
		tunnelRef.fileServer = fs
		go func() {
			defer ln.Close()
			if err := fs.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("[deploy] file server %s error: %v", subdomain, err)
			}
		}()
	}

	go func() {
		defer func() {
			if tunnelRef.fileServer != nil {
				shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer shutCancel()
				tunnelRef.fileServer.Shutdown(shutCtx)
			}
			if tunnelRef.nodeProc != nil && tunnelRef.nodeProc.Process != nil {
				_ = tunnelRef.nodeProc.Process.Kill()
			}
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
		if t.fileServer != nil {
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutCancel()
			t.fileServer.Shutdown(shutCtx)
		}
		if t.nodeProc != nil && t.nodeProc.Process != nil {
			_ = t.nodeProc.Process.Kill()
		}
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
// The effective quota is MAX(stored deploy_quota_bytes, plan base quota) so that
// plan upgrades are reflected immediately without a DB write.
func (h *DeployHandler) checkQuota(ctx context.Context, userID string, additionalBytes int64) (bool, int64, int64, error) {
	var storedQuota int64
	var usedBytes int64
	var plan string
	err := h.DB.Pool.QueryRow(ctx,
		`SELECT u.deploy_quota_bytes, u.plan, COALESCE(SUM(d.size_bytes), 0)
		 FROM users u
		 LEFT JOIN deployments d ON d.user_id = u.id AND d.status = 'active'
		 WHERE u.id = $1
		 GROUP BY u.deploy_quota_bytes, u.plan`,
		userID,
	).Scan(&storedQuota, &plan, &usedBytes)
	if err != nil {
		return false, 0, 0, err
	}
	// Effective quota = whichever is higher: stored value or plan's base entitlement.
	// This means upgrading a plan instantly unlocks more storage.
	quotaBytes := storedQuota
	if base := deployBaseQuotaBytes(plan); base > quotaBytes {
		quotaBytes = base
	}
	return usedBytes+additionalBytes <= quotaBytes, usedBytes, quotaBytes, nil
}

// classifyLogLine assigns a kind tag to a raw log line for dashboard colour coding.
func classifyLogLine(line string) string {
	l := strings.TrimSpace(line)
	// HTTP request lines: "  GET  /path  200  12ms"
	for _, m := range []string{"GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD "} {
		if strings.Contains(l, m) {
			if strings.Contains(l, " 2") {
				return "req-ok"
			}
			if strings.Contains(l, " 4") || strings.Contains(l, " 5") {
				return "req-err"
			}
			return "req"
		}
	}
	// Internal event lines start with [timestamp]
	if strings.HasPrefix(l, "[") && strings.Contains(l, "] ") {
		if strings.Contains(l, "error") || strings.Contains(l, "failed") || strings.Contains(l, "exit") {
			return "err"
		}
		if strings.Contains(l, "warn") {
			return "warn"
		}
		return "info"
	}
	// Next.js startup lines
	if strings.Contains(l, "Ready in") || strings.Contains(l, "Starting...") || strings.Contains(l, "▲ Next.js") {
		return "info"
	}
	if strings.Contains(l, "error") || strings.Contains(l, "Error") {
		return "err"
	}
	return "info"
}

// resolveNodeBin finds the node binary. It first tries PATH, then falls back to
// common install locations on Linux/macOS servers.
func resolveNodeBin() (string, error) {
	if p, err := exec.LookPath("node"); err == nil {
		return p, nil
	}
	candidates := []string{
		"/usr/bin/node",
		"/usr/local/bin/node",
		"/opt/homebrew/bin/node",
		"/home/linuxbrew/.linuxbrew/bin/node",
		"/root/.nvm/versions/node/current/bin/node",
	}
	// Also try nvm-style paths under /root and /home
	for _, pattern := range []string{
		"/root/.nvm/versions/node/*/bin/node",
		"/home/*/.nvm/versions/node/*/bin/node",
	} {
		if matches, err := filepath.Glob(pattern); err == nil && len(matches) > 0 {
			candidates = append(candidates, matches...)
		}
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("node binary not found in PATH or common locations")
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
