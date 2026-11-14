// HTTP and HTTPS request handling for MekongTunnel.
// ServeHTTP is the main HTTPS reverse proxy: it validates the subdomain,
// enforces rate limits, shows a phishing-warning interstitial for browsers,
// and proxies requests (including WebSocket) to the client's local application
// via the SSH tunnel.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package proxy

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/domain"
	"github.com/MuyleangIng/MekongTunnel/internal/mdserve"
	"github.com/MuyleangIng/MekongTunnel/internal/tunnel"
)

// ServeHTTP implements http.Handler for all HTTPS requests.
//
// Request flow:
//  1. Set security headers on every response
//  2. Enforce request body size limit when configured
//  3. Extract and validate the subdomain from the Host header
//  4. Look up the active tunnel in the registry
//  5. Check per-tunnel rate limit when configured
//  6. Optionally show a phishing-warning page for browser requests
//  7. Handle WebSocket upgrade or reverse-proxy the request
//  8. Log request (method, path, status, latency) to the SSH terminal
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)

	// Reject oversized request bodies early to avoid memory pressure.
	if config.MaxRequestBodySize > 0 {
		if r.ContentLength > config.MaxRequestBodySize {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, config.MaxRequestBodySize)
	}

	host := stripPort(r.Host)

	// Root domain (for example proxy.mekongtunnel.dev): serve warning
	// interstitial when it's a tunnel warning flow (has redirect param or is a
	// POST confirmation), otherwise redirect to the main web app.
	if host == s.domain {
		if r.URL.Query().Get("redirect") != "" || r.Method == http.MethodPost {
			s.serveWarningPage(w, r)
			return
		}
		http.Redirect(w, r, "https://mekongtunnel.dev/", http.StatusTemporaryRedirect)
		return
	}

	customDomain := false
	sub := ""
	var tun *tunnel.Tunnel

	switch {
	case strings.HasSuffix(host, "."+s.domain):
		sub = strings.TrimSuffix(host, "."+s.domain)
		tun = s.GetTunnel(sub)
		if tun == nil {
			// Unknown subdomains still need basic shape validation so arbitrary host
			// probes do not fall through to a tunnel lookup path.
			if !domain.IsValid(sub) {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}

			// Check for static deployment — serve files if deploy directory exists.
			if s.DeployDir != "" {
				deployPath := filepath.Join(s.DeployDir, filepath.Clean("/"+sub))
				if info, err := os.Stat(deployPath); err == nil && info.IsDir() {
					mdserve.Handler(deployPath).ServeHTTP(w, r)
					return
				}
			}

			reserved, err := s.lookupReservedSubdomain(r.Context(), sub)
			if err != nil {
				log.Printf("Reserved subdomain lookup failed for %s: %v", sub, err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			if reserved {
				lastSeen, err := s.lookupTunnelLastSeen(r.Context(), sub)
				if err != nil {
					log.Printf("Tunnel last-seen lookup failed for %s: %v", sub, err)
				}
				s.serveTunnelOfflinePage(w, r, host, sub, false, lastSeen)
				return
			}
			s.serveTunnelNotFoundPage(w, r, host, "", false)
			return
		}
	default:
		targetSubdomain, found, err := s.lookupCustomDomainTarget(r.Context(), host)
		if err != nil {
			log.Printf("Custom domain lookup failed for %s: %v", host, err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !found {
			if wantsHTMLResponse(r) {
				s.serveTunnelNotFoundPage(w, r, host, "", true)
				return
			}
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		if targetSubdomain == "" {
			s.serveCustomDomainPendingPage(w, r, host)
			return
		}
		customDomain = true
		sub = targetSubdomain
		tun = s.GetTunnel(sub)
		if tun == nil {
			lastSeen, err := s.lookupTunnelLastSeen(r.Context(), sub)
			if err != nil {
				log.Printf("Tunnel last-seen lookup failed for %s: %v", sub, err)
			}
			s.serveTunnelOfflinePage(w, r, host, sub, true, lastSeen)
			return
		}
	}

	// Per-tunnel token-bucket rate limiting.
	if !tun.AllowRequest() {
		// Count violations; after RateLimitViolationsMax, kill the tunnel and block the SSH client IP.
		if tun.RecordRateLimitHit() {
			log.Printf("Tunnel %s killed due to rate limit abuse, blocking SSH client %s", sub, tun.ClientIP)
			s.BlockIP(tun.ClientIP)
			tun.CloseSSH()
		}
		w.Header().Set("Retry-After", "1")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	tun.Touch()
	s.IncrementRequests()

	// Show a phishing-warning interstitial for first-time browser visits.
	// The warning sets a cookie so the user only sees it once per day.
	// API clients and curl are not affected.
	if !customDomain &&
		isBrowserRequest(r) &&
		!tun.SkipWarning() &&
		r.Header.Get("mekongtunnel-skip-warning") == "" &&
		!hasWarningCookie(r, sub) {
		s.redirectToWarningPage(w, r, sub)
		return
	}

	if isWebSocketRequest(r) {
		s.handleWebSocket(w, r, tun, sub)
		return
	}

	// Standard HTTP reverse proxy with request/response timing.
	requestStart := time.Now()
	sw := &statusCaptureWriter{ResponseWriter: w}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			originalHost := r.Host
			// Rewrite the request to target the tunnel's internal TCP listener.
			req.URL.Scheme = "http"
			req.URL.Host = tun.Listener.Addr().String()
			req.Host = effectiveUpstreamHost(tun, originalHost)
			req.Header.Set("X-Forwarded-Host", originalHost)
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("X-Original-Host", originalHost)
		},
		Transport: tun.Transport(),
		ModifyResponse: func(resp *http.Response) error {
			// Reject responses that declare they are too large.
			if config.MaxResponseBodySize > 0 && resp.ContentLength > config.MaxResponseBodySize {
				return fmt.Errorf("response too large: %d bytes (max %d)", resp.ContentLength, config.MaxResponseBodySize)
			}
			// Wrap the body for chunked/unknown-length responses to enforce the limit.
			if config.MaxResponseBodySize > 0 {
				resp.Body = &limitedReadCloser{
					rc:    resp.Body,
					limit: config.MaxResponseBodySize,
				}
			}
			// Strip X-Frame-Options from upstream apps so they can be embedded
			// in the MekongTunnel dashboard deploy preview iframe. The upstream
			// app (e.g. a Next.js app) may set this header itself — we remove it
			// so our dashboard can iframe the tunnel subdomain.
			resp.Header.Del("X-Frame-Options")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error for %s: %v", sub, err)
			if strings.Contains(err.Error(), "response too large") {
				if wantsHTMLResponse(r) {
					s.serveUpstreamUnavailablePage(w, r, host, sub, tun, "The local app responded with more data than this tunnel allows.", "ERR_MEKONG_RESPONSE_TOO_LARGE")
					return
				}
				http.Error(w, "Response Too Large", http.StatusBadGateway)
				return
			}
			if wantsHTMLResponse(r) {
				s.serveUpstreamUnavailablePage(w, r, host, sub, tun, "Traffic reached MekongTunnel, but the local app behind this tunnel did not answer.", "ERR_MEKONG_UPSTREAM_UNREACHABLE")
				return
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(sw, r)
	tun.RecordTraffic(sw.bytesWritten)

	// Emit a log line to the SSH terminal for every proxied request.
	if logger := tun.Logger(); logger != nil {
		logger.LogRequest(r.Method, r.URL.Path, sw.status, time.Since(requestStart))
	}
}

// handleWebSocket handles WebSocket upgrade requests by hijacking the client connection,
// dialling the backend tunnel listener, forwarding the upgrade handshake, then copying
// data bidirectionally with configured transfer and idle limits.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request, tun *tunnel.Tunnel, sub string) {
	backendConn, err := net.DialTimeout("tcp", tun.Listener.Addr().String(), 10*time.Second)
	if err != nil {
		log.Printf("WebSocket backend dial error for %s: %v", sub, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer backendConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("WebSocket hijack not supported for %s", sub)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("WebSocket hijack error for %s: %v", sub, err)
		return
	}
	defer clientConn.Close()

	backendReq := r.Clone(r.Context())
	backendReq.Header = r.Header.Clone()
	backendReq.Host = effectiveUpstreamHost(tun, r.Host)
	backendReq.Header.Set("X-Forwarded-Host", r.Host)
	backendReq.Header.Set("X-Forwarded-Proto", "https")
	backendReq.Header.Set("X-Original-Host", r.Host)

	// Forward the original HTTP upgrade request to the backend.
	if err := backendReq.Write(backendConn); err != nil {
		log.Printf("WebSocket request write error for %s: %v", sub, err)
		return
	}

	logger := tun.Logger()
	wsPath := r.URL.Path
	wsStart := time.Now()
	if logger != nil {
		logger.LogWebSocketOpen(wsPath)
	}

	// Bidirectional copy with transfer and idle limits.
	var backendBytes, clientBytes int64
	done := make(chan struct{})
	go func() {
		backendBytes, _ = copyWithLimits(backendConn, clientConn, config.MaxWebSocketTransfer, config.WebSocketIdleTimeout)
		if tc, ok := backendConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer close(done)
		clientBytes, _ = copyWithLimits(clientConn, backendConn, config.MaxWebSocketTransfer, config.WebSocketIdleTimeout)
	}()
	<-done

	if logger != nil {
		logger.LogWebSocketClose(wsPath, time.Since(wsStart), backendBytes+clientBytes)
	}
	tun.RecordTraffic(backendBytes + clientBytes)
}

// copyWithLimits copies from src to dst enforcing a maximum byte transfer limit
// and a per-read idle timeout. The idle deadline is reset after each successful read.
// Returns the number of bytes written and the first error encountered.
func copyWithLimits(dst, src net.Conn, maxBytes int64, idleTimeout time.Duration) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, readErr := src.Read(buf)
		if n > 0 {
			written += int64(n)
			if maxBytes > 0 && written > maxBytes {
				return written, fmt.Errorf("transfer limit exceeded")
			}
			if _, writeErr := dst.Write(buf[:n]); writeErr != nil {
				return written, writeErr
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
}

func effectiveUpstreamHost(tun *tunnel.Tunnel, originalHost string) string {
	if tun == nil {
		return originalHost
	}
	if upstream := tun.UpstreamHost(); upstream != "" {
		return upstream
	}
	return originalHost
}

// setSecurityHeaders adds standard security headers to every proxy response.
// Note: X-Frame-Options is intentionally omitted here — the proxy forwards user
// apps which may legitimately need to be embedded in iframes (e.g. deploy previews
// in the MekongTunnel dashboard). Each user app controls its own framing policy.
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// isBrowserRequest returns true when the User-Agent looks like a web browser.
// Used to decide whether to show the phishing-warning interstitial.
func isBrowserRequest(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	browserKeywords := []string{"mozilla", "chrome", "safari", "firefox", "edge", "opera"}
	for _, kw := range browserKeywords {
		if strings.Contains(ua, kw) {
			return true
		}
	}
	return false
}

// hasWarningCookie returns true when the request contains the per-subdomain warning
// acknowledgement cookie, meaning the user has already seen the interstitial.
func hasWarningCookie(r *http.Request, sub string) bool {
	cookie, err := r.Cookie(config.WarningCookieName + "_" + sub)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte("1")) == 1
}

func wantsHTMLResponse(r *http.Request) bool {
	if isBrowserRequest(r) {
		return true
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml")
}

// serveWarningPage serves the phishing-warning interstitial HTML page on the root domain.
// It reads the redirect and subdomain from query parameters and sets a cookie on confirm.
func (s *Server) serveWarningPage(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	sub := r.URL.Query().Get("subdomain")

	if r.Method == http.MethodPost || r.URL.Query().Get("continue") == "1" {
		if redirect == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		s.confirmWarningPage(w, sub)
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}

	if redirect == "" {
		http.Redirect(w, r, "https://mekongtunnel.dev/", http.StatusTemporaryRedirect)
		return
	}

	s.renderHTMLPage(w, http.StatusOK, warningPageTemplate, tunnelWarningPageData{
		Redirect:        redirect,
		Subdomain:       sub,
		ContinueHref:    warningContinueHref(redirect, sub),
		DestinationHost: warningDestinationHost(redirect),
		DestinationPath: warningDestinationPath(redirect),
	}, "warning page unavailable")
}

func (s *Server) confirmWarningPage(w http.ResponseWriter, sub string) {
	subName := strings.TrimSuffix(sub, "."+s.domain)
	// Set cookie on the parent domain (with leading dot) so it is sent
	// to the subdomain tunnel on the next request.
	http.SetCookie(w, &http.Cookie{
		Name:   config.WarningCookieName + "_" + subName,
		Value:  "1",
		Path:   "/",
		Domain: "." + s.domain,
		MaxAge: config.WarningCookieMaxAge,
	})
}

func (s *Server) serveTunnelOfflinePage(w http.ResponseWriter, r *http.Request, publicHost, targetSub string, customDomain bool, lastSeen *time.Time) {
	command := ""
	developerTip := "Restart Mekong from the machine sharing this app and keep the tunnel process running."
	summary := "This tunnel is currently offline. The owner may have stopped it."
	if customDomain {
		if targetSub != "" {
			developerTip = fmt.Sprintf("Reconnect the reserved subdomain %q from the sharing machine, then refresh this page.", targetSub)
		} else {
			developerTip = fmt.Sprintf("Attach %s to a reserved subdomain with `mekong domain connect %s <reserved-subdomain>`, then start the tunnel again.", publicHost, publicHost)
			command = fmt.Sprintf("mekong domain connect %s <reserved-subdomain>", publicHost)
		}
	}
	if targetSub != "" {
		command = fmt.Sprintf("mekong <port> --subdomain %s", targetSub)
	}

	s.renderHTMLPage(w, http.StatusBadGateway, issuePageTemplate, tunnelIssuePageData{
		Accent:         template.CSS("#dd6b20"),
		AccentSoft:     template.CSS("rgba(221,107,32,0.16)"),
		StatusLine:     "502 · Tunnel offline",
		Code:           "ERR_MEKONG_TUNNEL_OFFLINE",
		Title:          "This tunnel is currently offline",
		Summary:        summary,
		PublicHost:     publicHost,
		ReservedSub:    targetSub,
		LastSeenLabel:  formatLastSeenLabel(lastSeen),
		VisitorTip:     "If someone shared this link with you, ask them to reopen the app or reconnect Mekong, then refresh this page.",
		DeveloperTip:   developerTip,
		Command:        command,
		PrimaryLabel:   "Refresh page",
		PrimaryHref:    currentRequestURL(r),
		SecondaryLabel: "Back to MekongTunnel",
		SecondaryHref:  "https://mekongtunnel.dev/",
	}, "tunnel offline")
}

func (s *Server) serveTunnelNotFoundPage(w http.ResponseWriter, r *http.Request, publicHost, targetSub string, customDomain bool) {
	developerTip := "Create or reconnect the expected reserved subdomain, then share the new link."
	command := ""
	if customDomain {
		developerTip = fmt.Sprintf("Point %s at an existing reserved subdomain with `mekong domain connect %s <reserved-subdomain>`, then verify DNS and reopen the tunnel.", publicHost, publicHost)
		command = fmt.Sprintf("mekong domain connect %s <reserved-subdomain>", publicHost)
	} else if targetSub != "" {
		developerTip = fmt.Sprintf("Reconnect the reserved subdomain %q from the sharing machine, or remove the old link if it is no longer used.", targetSub)
	}

	s.renderHTMLPage(w, http.StatusNotFound, issuePageTemplate, tunnelIssuePageData{
		Accent:         template.CSS("#2b6cb0"),
		AccentSoft:     template.CSS("rgba(43,108,176,0.14)"),
		StatusLine:     "404 · Tunnel not found",
		Code:           "ERR_MEKONG_TUNNEL_NOT_FOUND",
		Title:          "No tunnel found for this address",
		Summary:        "No tunnel found for this address. It may have been removed or never existed.",
		PublicHost:     publicHost,
		ReservedSub:    targetSub,
		VisitorTip:     "If someone shared this link with you, they may have removed it or copied the wrong address.",
		DeveloperTip:   developerTip,
		Command:        command,
		PrimaryLabel:   "Refresh page",
		PrimaryHref:    currentRequestURL(r),
		SecondaryLabel: "Open MekongTunnel",
		SecondaryHref:  "https://mekongtunnel.dev/",
	}, "tunnel not found")
}

func (s *Server) serveCustomDomainPendingPage(w http.ResponseWriter, r *http.Request, publicHost string) {
	s.renderHTMLPage(w, http.StatusNotFound, issuePageTemplate, tunnelIssuePageData{
		Accent:         template.CSS("#2b6cb0"),
		AccentSoft:     template.CSS("rgba(43,108,176,0.14)"),
		StatusLine:     "404 · Custom domain not ready",
		Code:           "ERR_MEKONG_DOMAIN_PENDING",
		Title:          "This custom domain is not connected yet",
		Summary:        "The request reached MekongTunnel, but this domain does not have a live tunnel target yet.",
		PublicHost:     publicHost,
		VisitorTip:     "If a developer shared this domain with you, they may still be setting it up. Give it a moment, then refresh the page.",
		DeveloperTip:   fmt.Sprintf("Point %s at a reserved subdomain with `mekong domain connect %s <reserved-subdomain>`, verify DNS, then keep the tunnel running.", publicHost, publicHost),
		Command:        fmt.Sprintf("mekong domain connect %s <reserved-subdomain>", publicHost),
		PrimaryLabel:   "Try again",
		PrimaryHref:    currentRequestURL(r),
		SecondaryLabel: "Open MekongTunnel",
		SecondaryHref:  "https://mekongtunnel.dev/",
	}, "custom domain pending")
}

func (s *Server) serveUpstreamUnavailablePage(w http.ResponseWriter, r *http.Request, publicHost, targetSub string, tun *tunnel.Tunnel, summary, code string) {
	showConnectionFlow := code == "ERR_MEKONG_UPSTREAM_UNREACHABLE"
	s.renderHTMLPage(w, http.StatusBadGateway, issuePageTemplate, tunnelIssuePageData{
		Accent:             template.CSS("#c53030"),
		AccentSoft:         template.CSS("rgba(197,48,48,0.14)"),
		StatusLine:         "502 · Upstream unreachable",
		Code:               code,
		Title:              "The tunnel is live, but the local app is not reachable",
		Summary:            summary,
		ShowConnectionFlow: showConnectionFlow,
		DashboardTitle:     "Tunnel Status",
		DashboardMessage:   "Tunnel is active, but the local service is not reachable",
		DashboardSubtext:   "Traffic reached MekongTunnel, but your local server did not respond.",
		PublicHost:         publicHost,
		ReservedSub:        targetSub,
		LastSeenLabel:      "",
		LocalTarget:        localTarget(tun),
		HostHeader:         upstreamHostLabel(tun),
		VisitorTip:         "Refresh the page in a few moments. If the app is still offline, contact the person who shared this link.",
		DeveloperTip:       upstreamUnavailableDeveloperTip(tun),
		Command:            suggestedMekongCommand(tun),
		PrimaryLabel:       "Reload page",
		PrimaryHref:        currentRequestURL(r),
		SecondaryLabel:     "Open MekongTunnel",
		SecondaryHref:      "https://mekongtunnel.dev/",
	}, "upstream unavailable")
}

func (s *Server) renderHTMLPage(w http.ResponseWriter, status int, tmpl *template.Template, data any, fallback string) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		log.Printf("render html page: %v", err)
		http.Error(w, fallback, status)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// redirectToWarningPage redirects the browser to the phishing-warning interstitial page
// on the root domain, passing the original URL and subdomain as query parameters.
func (s *Server) redirectToWarningPage(w http.ResponseWriter, r *http.Request, sub string) {
	originalURL := "https://" + r.Host + r.URL.RequestURI()
	fullSubdomain := sub + "." + s.domain
	warningURL := fmt.Sprintf("https://%s/?redirect=%s&subdomain=%s",
		s.domain,
		url.QueryEscape(originalURL),
		url.QueryEscape(fullSubdomain))
	http.Redirect(w, r, warningURL, http.StatusTemporaryRedirect)
}

// isWebSocketRequest returns true when the request carries WebSocket upgrade headers.
func isWebSocketRequest(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// stripPort removes the port suffix from a host string.
// Example: "example.com:443" → "example.com".
func stripPort(host string) string {
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		return host[:idx]
	}
	return host
}

// limitedReadCloser wraps an io.ReadCloser and returns an error once more than
// limit bytes have been read, preventing runaway response bodies.
type limitedReadCloser struct {
	rc    io.ReadCloser
	limit int64
	read  int64
}

func (l *limitedReadCloser) Read(p []byte) (n int, err error) {
	if l.limit <= 0 {
		return l.rc.Read(p)
	}
	if l.read >= l.limit {
		return 0, fmt.Errorf("response body too large (exceeded %d bytes)", l.limit)
	}
	remaining := l.limit - l.read
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err = l.rc.Read(p)
	l.read += int64(n)
	return n, err
}

func (l *limitedReadCloser) Close() error {
	return l.rc.Close()
}

// statusCaptureWriter wraps http.ResponseWriter to capture the HTTP status code
// written by the reverse proxy so it can be included in the request log line.
type statusCaptureWriter struct {
	http.ResponseWriter
	status       int
	wroteHeader  bool
	bytesWritten int64
}

func (w *statusCaptureWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCaptureWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.status = http.StatusOK
		w.wroteHeader = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// Unwrap returns the underlying ResponseWriter so that interface pass-throughs
// (e.g. http.Flusher, http.Hijacker) work correctly.
func (w *statusCaptureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

type tunnelWarningPageData struct {
	Redirect        string
	Subdomain       string
	ContinueHref    string
	DestinationHost string
	DestinationPath string
}

type tunnelIssuePageData struct {
	Accent             template.CSS
	AccentSoft         template.CSS
	StatusLine         string
	Code               string
	Title              string
	Summary            string
	ShowConnectionFlow bool
	DashboardTitle     string
	DashboardMessage   string
	DashboardSubtext   string
	PublicHost         string
	ReservedSub        string
	LastSeenLabel      string
	LocalTarget        string
	HostHeader         string
	VisitorTip         string
	DeveloperTip       string
	Command            string
	PrimaryLabel       string
	PrimaryHref        string
	SecondaryLabel     string
	SecondaryHref      string
}

func currentRequestURL(r *http.Request) string {
	if r == nil {
		return "/"
	}
	if uri := r.URL.RequestURI(); uri != "" {
		return uri
	}
	return "/"
}

func formatLastSeenLabel(lastSeen *time.Time) string {
	if lastSeen == nil || lastSeen.IsZero() {
		return ""
	}
	return lastSeen.UTC().Format("Jan 02, 2006 15:04 UTC")
}

func warningDestinationHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || strings.TrimSpace(u.Host) == "" {
		return raw
	}
	return u.Host
}

func warningDestinationPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	path := strings.TrimSpace(u.EscapedPath())
	if path == "" {
		path = "/"
	}
	if q := strings.TrimSpace(u.RawQuery); q != "" {
		path += "?" + q
	}
	return path
}

func warningContinueHref(redirect, sub string) string {
	return fmt.Sprintf("/?continue=1&redirect=%s&subdomain=%s", url.QueryEscape(redirect), url.QueryEscape(sub))
}

func (s *Server) lookupReservedSubdomain(ctx context.Context, sub string) (bool, error) {
	if s.tokenValidator == nil {
		return false, nil
	}
	return s.tokenValidator.ReservedSubdomainExists(ctx, sub)
}

func (s *Server) lookupTunnelLastSeen(ctx context.Context, sub string) (*time.Time, error) {
	if s.tokenValidator == nil {
		return nil, nil
	}
	return s.tokenValidator.GetTunnelLastSeen(ctx, sub)
}

func reportedLocalPort(tun *tunnel.Tunnel) (uint32, bool) {
	if tun == nil {
		return 0, false
	}
	port := tun.LocalPort()
	if port == 0 {
		return 0, false
	}
	return port, true
}

func localTarget(tun *tunnel.Tunnel) string {
	port, ok := reportedLocalPort(tun)
	if !ok {
		return ""
	}
	host := strings.TrimSpace(tun.BindAddr)
	switch host {
	case "", "0.0.0.0", "::":
		host = "localhost"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func upstreamHostLabel(tun *tunnel.Tunnel) string {
	if tun == nil {
		return ""
	}
	return tun.UpstreamHost()
}

func upstreamUnavailableDeveloperTip(tun *tunnel.Tunnel) string {
	if _, ok := reportedLocalPort(tun); ok {
		return "Make sure the local app is running and listening before sharing the tunnel. If you restarted the app, keep Mekong open and reload this page."
	}
	return "The tunnel is live, but this session did not report its local app port. Reconnect with the current mekong CLI, then reload this page. Raw ssh -R sessions cannot show the actual localhost port here."
}

func suggestedMekongCommand(tun *tunnel.Tunnel) string {
	if tun == nil {
		return ""
	}
	port := "<local-port>"
	if reported, ok := reportedLocalPort(tun); ok {
		port = strconv.FormatUint(uint64(reported), 10)
	}
	command := fmt.Sprintf("mekong %s", port)
	if sub := tun.GetRequestedSubdomain(); sub != "" {
		command += " --subdomain " + sub
	}
	if host := tun.UpstreamHost(); host != "" {
		command += " --upstream-host " + host
	}
	return command
}

// pageBaseCSS is the shared look for every page the tunnel edge renders
// (shared-tunnel notice, offline / not-found / status pages): MekongTunnel's
// glass card on a deep river-teal background, light/dark aware, phone friendly.
const pageBaseCSS = `
    :root {
      color-scheme: dark light;
      --bg: #061419; --bg-2: #040e12;
      --card: rgba(11, 31, 38, 0.62); --card-border: rgba(255, 255, 255, 0.10);
      --sunken: rgba(0, 0, 0, 0.24); --hairline: rgba(255, 255, 255, 0.09);
      --text: #e8eef0; --muted: #94aab0; --gold: #f5c451; --river: #2dd4bf;
      --danger: #f87171; --ok: #34d399;
      --shadow: 0 24px 80px rgba(0, 0, 0, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.07);
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f7f1e6; --bg-2: #efe4d2;
        --card: rgba(255, 253, 248, 0.78); --card-border: rgba(161, 95, 0, 0.16);
        --sunken: rgba(239, 228, 210, 0.55); --hairline: rgba(161, 95, 0, 0.14);
        --text: #201b16; --muted: #6a6f7d; --gold: #a15f00; --river: #0f766e;
        --danger: #b91c1c; --ok: #047857;
        --shadow: 0 24px 60px rgba(32, 27, 22, 0.12), inset 0 1px 0 rgba(255, 255, 255, 0.8);
      }
    }
    * { box-sizing: border-box; }
    html, body { margin: 0; }
    html { background: var(--bg-2); }
    body {
      min-height: 100vh;
      font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans Khmer", sans-serif;
      color: var(--text);
      background:
        radial-gradient(ellipse 80% 50% at 50% -10%, color-mix(in srgb, var(--river) 18%, transparent), transparent 60%),
        radial-gradient(ellipse 50% 40% at 95% 5%, color-mix(in srgb, var(--gold) 12%, transparent), transparent 60%),
        linear-gradient(180deg, var(--bg), var(--bg-2));
      background-repeat: no-repeat;
      display: flex; flex-direction: column; align-items: center;
      padding: 28px 16px 40px;
      -webkit-font-smoothing: antialiased;
    }
    a { color: inherit; }
    code, pre, .mono { font-family: ui-monospace, "SFMono-Regular", "JetBrains Mono", Menlo, Consolas, monospace; }
    .topbar { width: 100%; max-width: 640px; display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px; }
    .brand { display: inline-flex; align-items: center; gap: 10px; text-decoration: none; font-weight: 800; letter-spacing: 0.02em; }
    .brand-mark {
      width: 34px; height: 34px; border-radius: 11px; display: grid; place-items: center;
      background: linear-gradient(135deg, color-mix(in srgb, var(--river) 30%, transparent), color-mix(in srgb, var(--gold) 26%, transparent));
      border: 1px solid var(--card-border);
    }
    .brand-mark svg { width: 18px; height: 18px; color: var(--gold); }
    .brand-name span:first-child { background: linear-gradient(90deg, var(--gold), var(--river)); -webkit-background-clip: text; background-clip: text; color: transparent; }
    .topbar-link { font-size: 12px; color: var(--muted); text-decoration: none; }
    .topbar-link:hover { color: var(--text); }
    .card {
      position: relative; width: 100%; max-width: 640px; overflow: hidden;
      background: var(--card); border: 1px solid var(--card-border); border-radius: 24px;
      box-shadow: var(--shadow);
      -webkit-backdrop-filter: blur(20px) saturate(160%); backdrop-filter: blur(20px) saturate(160%);
      padding: 30px 28px;
    }
    .card::before {
      content: ""; position: absolute; inset: 0 0 auto 0; height: 1px;
      background: linear-gradient(90deg, transparent, var(--accent, var(--gold)), transparent);
    }
    .badge-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-bottom: 18px; }
    .pill {
      display: inline-flex; align-items: center; gap: 7px; border-radius: 999px; padding: 5px 11px;
      font-size: 11px; font-weight: 700; letter-spacing: 0.14em; text-transform: uppercase;
      color: var(--accent, var(--gold));
      background: color-mix(in srgb, var(--accent, var(--gold)) 12%, transparent);
      border: 1px solid color-mix(in srgb, var(--accent, var(--gold)) 30%, transparent);
    }
    .pill-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; box-shadow: 0 0 10px currentColor; }
    .chip { font-size: 11px; color: var(--muted); border: 1px solid var(--hairline); background: var(--sunken); border-radius: 8px; padding: 4px 8px; }
    .hero-icon {
      width: 52px; height: 52px; border-radius: 16px; display: grid; place-items: center; margin-bottom: 16px;
      color: var(--accent, var(--gold));
      background: color-mix(in srgb, var(--accent, var(--gold)) 12%, transparent);
      border: 1px solid color-mix(in srgb, var(--accent, var(--gold)) 30%, transparent);
    }
    .hero-icon svg { width: 26px; height: 26px; }
    h1 { margin: 0 0 10px; font-size: clamp(24px, 4.6vw, 32px); line-height: 1.15; letter-spacing: -0.02em; }
    .lead { margin: 0; color: var(--muted); font-size: 15px; line-height: 1.7; }
    .lead strong { color: var(--text); display: block; margin-bottom: 4px; }
    .panel { margin-top: 20px; border: 1px solid var(--hairline); background: var(--sunken); border-radius: 16px; padding: 14px 16px; }
    .label { font-size: 11px; font-weight: 700; letter-spacing: 0.16em; text-transform: uppercase; color: var(--muted); margin-bottom: 8px; }
    .btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 8px;
      border-radius: 14px; padding: 13px 20px; font-size: 15px; font-weight: 700; text-decoration: none;
      transition: transform .15s ease, filter .15s ease, background .15s ease;
    }
    .btn:active { transform: scale(0.98); }
    .btn-primary { color: #061419; background: linear-gradient(90deg, #f5c451, #fcd980); box-shadow: 0 8px 28px rgba(245, 196, 81, 0.28); }
    .btn-primary:hover { filter: brightness(1.06); }
    .btn-ghost { color: var(--text); border: 1px solid var(--card-border); background: var(--sunken); }
    .btn-ghost:hover { border-color: color-mix(in srgb, var(--river) 45%, transparent); }
    .footnote { margin: 18px 0 0; font-size: 12px; color: var(--muted); text-align: center; }
    details.dev { margin-top: 18px; border: 1px dashed color-mix(in srgb, var(--river) 35%, transparent); border-radius: 16px; background: color-mix(in srgb, var(--river) 6%, transparent); }
    details.dev summary { cursor: pointer; list-style: none; padding: 13px 16px; font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 10px; }
    details.dev summary::-webkit-details-marker { display: none; }
    details.dev summary .chev { margin-left: auto; transition: transform .2s ease; color: var(--muted); }
    details.dev[open] summary .chev { transform: rotate(90deg); }
    details.dev .dev-body { padding: 0 16px 14px; font-size: 13px; color: var(--muted); line-height: 1.6; }
    .snippet { margin: 8px 0 12px; display: block; padding: 10px 12px; border-radius: 10px; background: var(--sunken); border: 1px solid var(--hairline); color: var(--river); font-size: 12.5px; overflow-x: auto; white-space: pre; }
    .snippet .p { color: var(--gold); user-select: none; }
    .site-foot { margin-top: 22px; font-size: 12px; color: var(--muted); }
    .site-foot a { color: var(--gold); text-decoration: none; }
    @media (max-width: 520px) {
      body { padding: 18px 12px 32px; }
      .card { padding: 24px 18px; border-radius: 20px; }
      .btn { width: 100%; }
    }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; } }
`

const pageBrandSVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 15c2.5 0 2.5-2 5-2s2.5 2 5 2 2.5-2 5-2 2.5 2 5 2"/><path d="M2 19c2.5 0 2.5-2 5-2s2.5 2 5 2 2.5-2 5-2 2.5 2 5 2"/><path d="M12 3 7 9h10z"/></svg>`

var warningPageTemplate = template.Must(template.New("warning-page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex">
  <title>MekongTunnel | Shared tunnel notice</title>
  <style>` + pageBaseCSS + `
    .dest { display: flex; align-items: center; gap: 12px; }
    .dest-icon { flex: none; width: 38px; height: 38px; border-radius: 12px; display: grid; place-items: center; background: color-mix(in srgb, var(--river) 14%, transparent); color: var(--river); }
    .dest-icon svg { width: 20px; height: 20px; }
    .dest-host { font-weight: 700; font-size: 16px; word-break: break-all; }
    .dest-url { display: block; margin-top: 2px; font-size: 12px; color: var(--muted); word-break: break-all; }
    .cta-wrap { margin-top: 22px; display: flex; flex-direction: column; gap: 10px; }
    .cta { width: 100%; }
    .cta-inner { display: inline-flex; align-items: center; gap: 10px; }
    .cta-spinner { display: none; width: 16px; height: 16px; border-radius: 50%; border: 2px solid rgba(6, 20, 25, 0.25); border-top-color: #061419; animation: spin .7s linear infinite; }
    .cta.is-loading { pointer-events: none; filter: saturate(0.8); }
    .cta.is-loading .cta-spinner { display: inline-block; }
    .cta.is-loading .cta-arrow { display: none; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .cancel-note { margin: 0; text-align: center; font-size: 12.5px; color: var(--muted); }
    .notice-title { margin-top: 24px; font-size: 13px; font-weight: 700; }
    .notice { list-style: none; margin: 10px 0 0; padding: 0; display: grid; gap: 8px; }
    .notice li { display: flex; gap: 10px; align-items: flex-start; font-size: 14px; color: var(--muted); line-height: 1.55; }
    .notice svg { flex: none; width: 18px; height: 18px; margin-top: 2px; color: var(--gold); }
  </style>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="https://mekongtunnel.dev/"><span class="brand-mark">` + pageBrandSVG + `</span><span class="brand-name"><span>Mekong</span><span>Tunnel</span></span></a>
    <a class="topbar-link" href="https://docs.mekongtunnel.dev/" rel="noopener">What is this?</a>
  </header>

  <main class="card" style="--accent: var(--gold)">
    <div class="badge-row">
      <span class="pill"><span class="pill-dot"></span><span class="kicker">Shared tunnel notice</span></span>
      {{if .Subdomain}}<span class="chip mono">{{.Subdomain}}</span>{{end}}
    </div>

    <div class="hero-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4.5 6v5.5c0 4.5 3.2 8.4 7.5 9.5 4.3-1.1 7.5-5 7.5-9.5V6z"/><path d="M12 8v4.5"/><path d="M12 16h.01"/></svg>
    </div>
    <h1>You are about to open a shared tunnel.</h1>
    <p class="lead">This URL points to an app running on someone's own computer, shared through MekongTunnel. Continue only if you trust the person who sent you this link.</p>

    <div class="panel">
      <div class="label">Destination</div>
      <div class="dest">
        <div class="dest-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a14 14 0 0 1 0 18"/><path d="M12 3a14 14 0 0 0 0 18"/></svg></div>
        <div>
          <div class="dest-host mono">{{if .DestinationHost}}{{.DestinationHost}}{{else}}{{.Redirect}}{{end}}</div>
          <code class="dest-url">{{.Redirect}}</code>
        </div>
      </div>
    </div>

    <div class="cta-wrap">
      <a class="btn btn-primary cta" href="{{.ContinueHref}}" data-destination="{{.Redirect}}" data-loading-label="Opening site...">
        <span class="cta-inner">
          <span class="cta-spinner" aria-hidden="true"></span>
          <span class="cta-label">Continue to site</span>
          <span class="cta-arrow" aria-hidden="true">&rarr;</span>
        </span>
      </a>
      <p class="cancel-note">Don't trust this link? Just close this tab.</p>
    </div>

    <div class="notice-title">Before you continue</div>
    <ul class="notice">
      <li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></svg><span>This app is controlled by the person who shared the tunnel link, not by MekongTunnel.</span></li>
      <li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/></svg><span>The page behind this URL may change, restart, or go offline at any time.</span></li>
      <li><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg><span>Don't enter passwords, payment details, or private data unless you trust the sender.</span></li>
    </ul>

    <details class="dev">
      <summary><span aria-hidden="true">&#9881;&#65039;</span> Is this your tunnel? Skip this page <span class="chev" aria-hidden="true">&rsaquo;</span></summary>
      <div class="dev-body">
        Start the tunnel with the skip flag so visitors go straight to your app:
        <code class="snippet"><span class="p">$ </span>mekong 3000 --skip-browser-warning</code>
        Calling it from code, a webhook or a script? Send this header (non-browser clients like <code>curl</code> never see this page):
        <code class="snippet">mekongtunnel-skip-warning: 1</code>
        Visitors who click <strong>Continue</strong> won't see this notice again for this tunnel for 24 hours.
      </div>
    </details>
  </main>

  <p class="site-foot">Secured by <a href="https://mekongtunnel.dev/">MekongTunnel</a> &middot; open-source tunnels from Cambodia</p>

  <script>
    document.addEventListener("click", function (event) {
      var link = event.target.closest("[data-loading-label]");
      if (!link) return;
      if (link.classList.contains("is-loading")) {
        event.preventDefault();
        return;
      }
      link.classList.add("is-loading");
      var label = link.querySelector(".cta-label");
      if (label) {
        label.textContent = link.getAttribute("data-loading-label") || "Opening site...";
      }
    });
  </script>
</body>
</html>`))

var issuePageTemplate = template.Must(template.New("issue-page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex">
  <title>MekongTunnel | {{.Title}}</title>
  <style>` + pageBaseCSS + `
    .code { font-size: 11px; color: var(--muted); }
    .flow { margin-top: 22px; padding: 20px 14px 16px; border: 1px solid var(--hairline); background: var(--sunken); border-radius: 18px; }
    .flow-grid { position: relative; display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 6px; }
    .flow-line { position: absolute; top: 23px; left: 12.5%; right: 12.5%; height: 2px; border-radius: 2px; background: color-mix(in srgb, var(--danger) 35%, transparent); }
    .flow-line-active { display: block; height: 100%; width: 66.6%; border-radius: 2px; background: linear-gradient(90deg, var(--river), var(--ok)); box-shadow: 0 0 12px color-mix(in srgb, var(--river) 60%, transparent); transition: width .5s ease; }
    .flow-node { position: relative; display: flex; flex-direction: column; align-items: center; text-align: center; gap: 8px; }
    .flow-icon {
      position: relative; z-index: 1; width: 48px; height: 48px; border-radius: 15px; display: grid; place-items: center;
      background: var(--card); border: 1px solid var(--card-border);
    }
    .flow-icon svg { width: 22px; height: 22px; }
    .flow-node.active .flow-icon { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 45%, transparent); box-shadow: 0 0 22px -6px var(--ok); }
    .flow-node.failed .flow-icon { color: var(--danger); border-color: color-mix(in srgb, var(--danger) 50%, transparent); animation: pulse 1.6s ease-in-out infinite; }
    @keyframes pulse { 50% { box-shadow: 0 0 0 6px color-mix(in srgb, var(--danger) 14%, transparent); } }
    .flow-indicator { height: 14px; display: grid; place-items: center; }
    .flow-dot { width: 14px; height: 14px; border-radius: 50%; display: grid; place-items: center; font-size: 10px; line-height: 1; color: #fff; }
    .flow-node.active .flow-dot { background: var(--ok); }
    .flow-node.failed .flow-dot { background: var(--danger); }
    .flow-label { font-size: 12px; font-weight: 600; color: var(--muted); }
    .flow-node.failed .flow-label { color: var(--danger); }
    .retry-note { margin: 14px 0 0; display: flex; align-items: center; gap: 10px; font-size: 13px; color: var(--muted); }
    .retry-dot { flex: none; width: 8px; height: 8px; border-radius: 50%; background: var(--gold); animation: blink 1.2s ease-in-out infinite; }
    .retry-note.is-ready .retry-dot { background: var(--ok); animation: none; }
    @keyframes blink { 50% { opacity: .25; } }
    .facts dl { margin: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px 18px; }
    .facts dt { font-size: 11px; color: var(--muted); }
    .facts dd { margin: 2px 0 0; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13px; word-break: break-all; }
    .actions { margin-top: 20px; display: flex; flex-wrap: wrap; gap: 10px; }
    .help { margin-top: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; }
    .help-block { border: 1px solid var(--hairline); border-radius: 16px; padding: 14px 16px; background: var(--sunken); }
    .help-block h2 { margin: 0 0 6px; font-size: 13px; }
    .help-block p { margin: 0; font-size: 13px; line-height: 1.6; color: var(--muted); }
    .help-block pre { margin: 10px 0 0; padding: 10px 12px; border-radius: 10px; background: var(--bg-2); border: 1px solid var(--hairline); color: var(--river); font-size: 12.5px; overflow-x: auto; }
    @media (max-width: 420px) {
      .flow { padding: 16px 8px 14px; }
      .flow-icon { width: 40px; height: 40px; border-radius: 12px; }
      .flow-line { top: 19px; }
      .flow-label { font-size: 10.5px; }
    }
  </style>
</head>
<body>
  <header class="topbar">
    <a class="brand" href="https://mekongtunnel.dev/"><span class="brand-mark">` + pageBrandSVG + `</span><span class="brand-name"><span>Mekong</span><span>Tunnel</span></span></a>
    <a class="topbar-link" href="https://docs.mekongtunnel.dev/" rel="noopener">Docs</a>
  </header>

  <main class="card" style="--accent: {{.Accent}}">
    <div class="badge-row">
      <span class="pill status"><span class="pill-dot"></span>{{.StatusLine}}</span>
      <span class="chip mono code">{{.Code}}</span>
    </div>

    {{if .ShowConnectionFlow}}
    <h1>{{.DashboardTitle}}</h1>
    <p class="lead summary"><strong data-retry-title>{{.DashboardMessage}}</strong><span data-retry-text>{{.DashboardSubtext}}</span></p>
    <div class="flow" aria-label="Tunnel connection status">
      <div class="flow-grid">
        <div class="flow-line" aria-hidden="true">
          <span class="flow-line-active" data-flow-active></span>
        </div>
        <div class="flow-node active">
          <div class="flow-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle><path d="M3 12h18"></path><path d="M12 3a14 14 0 0 1 0 18"></path><path d="M12 3a14 14 0 0 0 0 18"></path></svg>
          </div>
          <div class="flow-indicator"><span class="flow-dot"></span></div>
          <div class="flow-label">Internet</div>
        </div>
        <div class="flow-node active">
          <div class="flow-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="7" rx="2"></rect><rect x="3" y="13" width="18" height="7" rx="2"></rect><path d="M7 7.5h.01"></path><path d="M7 16.5h.01"></path></svg>
          </div>
          <div class="flow-indicator"><span class="flow-dot"></span></div>
          <div class="flow-label">Mekong Edge</div>
        </div>
        <div class="flow-node active">
          <div class="flow-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"></rect><path d="m8 10 3 2.5L8 15"></path><path d="M13 15h4"></path></svg>
          </div>
          <div class="flow-indicator"><span class="flow-dot"></span></div>
          <div class="flow-label">Mekong Agent</div>
        </div>
        <div class="flow-node failed" data-local-node>
          <div class="flow-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m8 9-4 3 4 3"></path><path d="m16 9 4 3-4 3"></path><path d="m13.5 6-3 12"></path></svg>
          </div>
          <div class="flow-indicator"><span class="flow-dot"><span class="flow-cross">&times;</span></span></div>
          <div class="flow-label">Local Service</div>
        </div>
      </div>
      <p class="retry-note" data-retry-note><span class="retry-dot" aria-hidden="true"></span><span data-retry-status>Checking again every 2 seconds. This page will open your app automatically when localhost responds.</span></p>
    </div>
    {{else}}
    <div class="hero-icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M2 15c2.5 0 2.5-2 5-2s2.5 2 5 2 2.5-2 5-2 2.5 2 5 2"></path><path d="M12 3v7"></path><path d="m9 7 3 3 3-3"></path><path d="M2 19c2.5 0 2.5-2 5-2s2.5 2 5 2 2.5-2 5-2 2.5 2 5 2"></path></svg>
    </div>
    <h1>{{.Title}}</h1>
    <p class="lead summary">{{.Summary}}</p>
    {{end}}

    <div class="panel facts">
      <div class="label">Connection details</div>
      <dl>
        <div><dt>Public host</dt><dd>{{.PublicHost}}</dd></div>
        {{if .ReservedSub}}<div><dt>Reserved subdomain target</dt><dd>{{.ReservedSub}}</dd></div>{{end}}
        {{if .LastSeenLabel}}<div><dt>Last seen</dt><dd>{{.LastSeenLabel}}</dd></div>{{end}}
        {{if .LocalTarget}}<div><dt>Expected local app</dt><dd>{{.LocalTarget}}</dd></div>{{end}}
        {{if .HostHeader}}<div><dt>Host header override</dt><dd>{{.HostHeader}}</dd></div>{{end}}
      </dl>
    </div>

    <div class="actions">
      <a class="btn btn-primary primary" href="{{.PrimaryHref}}">{{.PrimaryLabel}}</a>
      <a class="btn btn-ghost secondary" href="{{.SecondaryHref}}">{{.SecondaryLabel}}</a>
    </div>

    <div class="help">
      <div class="help-block">
        <h2>If you are visiting this page</h2>
        <p>{{.VisitorTip}}</p>
      </div>
      <div class="help-block">
        <h2>If you are sharing this page</h2>
        <p>{{.DeveloperTip}}</p>
        {{if .Command}}<pre>{{.Command}}</pre>{{end}}
      </div>
    </div>
  </main>

  <p class="site-foot">Powered by <a href="https://mekongtunnel.dev/">MekongTunnel</a> &middot; open-source tunnels from Cambodia</p>
  {{if .ShowConnectionFlow}}
  <script>
    (function () {
      if (!window.fetch) return;
      var localNode = document.querySelector("[data-local-node]");
      var activeLine = document.querySelector("[data-flow-active]");
      var retryNote = document.querySelector("[data-retry-note]");
      var retryStatus = document.querySelector("[data-retry-status]");
      var retryTitle = document.querySelector("[data-retry-title]");
      var retryText = document.querySelector("[data-retry-text]");
      var currentURL = window.location.href;
      var polling = false;
      var recovered = false;

      var setStatus = function (text) {
        if (retryStatus) retryStatus.textContent = text;
      };

      var markRecovered = function () {
        if (recovered) return;
        recovered = true;
        if (localNode) {
          localNode.classList.remove("failed");
          localNode.classList.add("active");
        }
        if (activeLine) {
          activeLine.style.width = "100%";
        }
        if (retryNote) {
          retryNote.classList.add("is-ready");
        }
        if (retryTitle) {
          retryTitle.textContent = "Tunnel is active and the local service responded";
        }
        if (retryText) {
          retryText.textContent = "Opening the shared site now.";
        }
        setStatus("Local service responded. Opening site...");
      };

      var probe = function () {
        if (polling || recovered) return;
        polling = true;
        var url = new URL(currentURL);
        url.searchParams.set("_mekong_probe", String(Date.now()));
        fetch(url.toString(), {
          method: "GET",
          credentials: "same-origin",
          cache: "no-store",
          headers: {
            "Accept": "text/html",
            "X-Mekong-Probe": "1"
          }
        }).then(function (response) {
          if (response.status !== 502 && response.status !== 503 && response.status !== 504) {
            markRecovered();
            window.setTimeout(function () {
              window.location.reload();
            }, 260);
            return;
          }
          setStatus("Still waiting for localhost to respond. Checking again...");
        }).catch(function () {
          setStatus("Still waiting for localhost to respond. Checking again...");
        }).finally(function () {
          polling = false;
        });
      };

      window.setTimeout(probe, 1200);
      window.setInterval(probe, 2000);
    })();
  </script>
  {{end}}
</body>
</html>`))

// HTTPRedirectHandler returns an http.Handler that permanently redirects
// all HTTP requests to their HTTPS equivalent (301 Moved Permanently).
// Only requests for our domain or its subdomains are accepted; others get 400.
func (s *Server) HTTPRedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := stripPort(r.Host)
		if !strings.HasSuffix(host, "."+s.domain) && host != s.domain {
			_, found, err := s.lookupCustomDomainTarget(r.Context(), host)
			if err != nil {
				log.Printf("Custom domain redirect lookup failed for %s: %v", host, err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			if !found {
				http.Error(w, "Bad Request", http.StatusBadRequest)
				return
			}
		}
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}
