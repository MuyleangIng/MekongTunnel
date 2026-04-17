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

var warningPageTemplate = template.Must(template.New("warning-page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MekongTunnel | Shared tunnel notice</title>
  <style>
    :root {
      --bg: #f6f2eb;
      --panel: #ffffff;
      --ink: #171615;
      --muted: #6d655c;
      --line: rgba(23, 22, 21, 0.12);
      --accent: #0f766e;
      --accent-soft: rgba(15, 118, 110, 0.08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, var(--accent-soft), transparent 32%),
        linear-gradient(180deg, #faf8f4 0%, var(--bg) 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .shell {
      width: min(680px, 100%);
      border: 1px solid var(--line);
      border-radius: 22px;
      background: var(--panel);
      box-shadow: 0 18px 40px rgba(28, 24, 19, 0.08);
    }
    .content {
      padding: 28px;
    }
    .brand {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.03em;
    }
    .kicker {
      margin: 8px 0 0;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1em;
    }
    h1 {
      margin: 18px 0 14px;
      font-family: Georgia, "Times New Roman", serif;
      font-size: clamp(32px, 6vw, 52px);
      line-height: 1.02;
      letter-spacing: -0.05em;
    }
    .copy,
    .cancel-note,
    .footnote {
      margin: 0;
      color: var(--muted);
      line-height: 1.7;
    }
    .copy {
      font-size: 16px;
      max-width: 38rem;
    }
    .destination {
      margin-top: 20px;
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px;
      background: #fcfcfb;
    }
    .label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--muted);
      margin-bottom: 8px;
      font-weight: 700;
    }
    code {
      display: block;
      font-family: "SFMono-Regular", "JetBrains Mono", monospace;
      font-size: clamp(13px, 3.8vw, 15px);
      line-height: 1.7;
      word-break: break-word;
      overflow-wrap: anywhere;
      color: #0f172a;
    }
    .cta-wrap {
      margin-top: 22px;
    }
    .cta {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 100%;
      text-decoration: none;
      border-radius: 16px;
      padding: 17px 22px;
      background: linear-gradient(135deg, var(--accent) 0%, #155e75 100%);
      color: white;
      box-shadow: 0 12px 24px rgba(15,118,110,0.18);
      transition: transform 120ms ease, opacity 120ms ease, box-shadow 120ms ease;
    }
    .cta:hover {
      transform: translateY(-1px);
      opacity: 0.94;
    }
    .cta.is-loading {
      pointer-events: none;
      opacity: 0.96;
      box-shadow: 0 18px 36px rgba(15,118,110,0.22);
    }
    .cta-inner {
      display: inline-flex;
      align-items: center;
      gap: 12px;
    }
    .cta-spinner {
      width: 18px;
      height: 18px;
      border-radius: 999px;
      border: 2px solid rgba(255,255,255,0.34);
      border-top-color: #ffffff;
      display: none;
      animation: mekong-spin 0.8s linear infinite;
    }
    .cta.is-loading .cta-spinner {
      display: inline-flex;
    }
    .cta-label {
      font-size: clamp(18px, 4vw, 22px);
      font-weight: 800;
      line-height: 1.1;
      letter-spacing: -0.03em;
    }
    .cancel-note {
      margin-top: 16px;
      font-size: 14px;
    }
    .notice {
      margin: 18px 0 0;
      padding-left: 18px;
      font-size: 14px;
      color: var(--muted);
      line-height: 1.65;
    }
    .notice-title {
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: #3f3a34;
      margin: 18px 0 8px;
    }
    .notice li + li {
      margin-top: 8px;
    }
    .footnote {
      margin-top: 14px;
      font-size: 13px;
    }
    @keyframes mekong-spin {
      to { transform: rotate(360deg); }
    }
    @media (max-width: 640px) {
      body {
        padding: 10px;
        align-items: stretch;
      }
      .shell {
        width: 100%;
        border-radius: 20px;
      }
      .content {
        padding: 20px 16px 18px;
      }
      h1 {
        font-size: clamp(28px, 12vw, 44px);
      }
      .copy {
        font-size: 15px;
      }
      .destination {
        margin-top: 18px;
        padding: 14px;
        border-radius: 16px;
      }
      .cta {
        padding: 16px 18px;
        border-radius: 16px;
      }
      .cta-label {
        font-size: clamp(16px, 6.8vw, 21px);
      }
      .notice {
        margin-top: 16px;
      }
    }
    @media (max-width: 380px) {
      .brand {
        font-size: 20px;
      }
      h1 {
        font-size: 26px;
      }
      .cta-label {
        font-size: 15px;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="content">
      <p class="brand">MekongTunnel</p>
      <p class="kicker">Shared tunnel notice</p>
      <h1>You are about to open a shared tunnel.</h1>
      <p class="copy">This URL points to an app being exposed from a developer machine through MekongTunnel. Continue only if you trust the person who shared it with you.</p>
      <div class="destination">
        <div class="label">Destination</div>
        <code>{{.Redirect}}</code>
      </div>
      <div class="cta-wrap">
        <a class="cta" href="{{.ContinueHref}}" data-destination="{{.Redirect}}" data-loading-label="Opening site...">
          <span class="cta-inner">
            <span class="cta-spinner" aria-hidden="true"></span>
            <span class="cta-label">Continue to site</span>
          </span>
        </a>
      </div>
      <p class="cancel-note">If you do not trust this link, close this tab instead of continuing.</p>
      <div class="notice-title">Before you continue</div>
      <ul class="notice">
        <li>This app is controlled by the person who shared the tunnel link.</li>
        <li>The page behind this URL may change, restart, or go offline at any time.</li>
        <li>Do not enter passwords, payment details, or private data unless you trust the sender.</li>
      </ul>
      <p class="footnote">You will not see this warning again for this tunnel for the next 24 hours.</p>
    </div>
  </div>
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
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MekongTunnel | {{.Title}}</title>
  <style>
    :root {
      --bg: #f6f2eb;
      --panel: #ffffff;
      --ink: #161514;
      --muted: #6a6258;
      --line: rgba(22, 21, 20, 0.12);
      --accent: {{.Accent}};
      --accent-soft: {{.AccentSoft}};
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Avenir Next", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, var(--accent-soft), transparent 32%),
        linear-gradient(180deg, #faf8f4 0%, var(--bg) 100%);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .shell {
      width: min(760px, 100%);
      border: 1px solid var(--line);
      border-radius: 22px;
      background: var(--panel);
      box-shadow: 0 18px 40px rgba(28, 24, 19, 0.08);
    }
    .brand {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.03em;
    }
    .status {
      margin: 8px 0 0;
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.1em;
    }
    .content {
      padding: 28px;
    }
    .code {
      display: inline-flex;
      align-items: center;
      margin-top: 20px;
      padding: 6px 10px;
      border-radius: 999px;
      background: rgba(22,21,20,0.05);
      color: var(--accent);
      font-size: 11px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.12em;
    }
    h1 {
      margin: 18px 0 14px;
      font-family: Georgia, "Times New Roman", serif;
      font-size: clamp(32px, 6vw, 50px);
      line-height: 1.02;
      letter-spacing: -0.05em;
    }
    .summary {
      margin: 0;
      color: var(--muted);
      font-size: 16px;
      line-height: 1.75;
      max-width: 42rem;
      overflow-wrap: anywhere;
    }
    .summary strong {
      display: block;
      color: var(--ink);
      font-weight: 800;
      margin-bottom: 4px;
      overflow-wrap: anywhere;
    }
    .flow {
      margin-top: 22px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: #fcfcfb;
      padding: 18px 16px 16px;
      overflow: hidden;
    }
    .flow-grid {
      position: relative;
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 10px;
    }
    .flow-line {
      position: absolute;
      top: 63px;
      left: 12.5%;
      right: 12.5%;
      height: 4px;
      border-radius: 999px;
      background: #d1d5db;
      overflow: hidden;
    }
    .flow-line-active {
      display: block;
      width: 66.666%;
      height: 100%;
      border-radius: inherit;
      background: linear-gradient(90deg, #22c55e 0%, #86efac 50%, #22c55e 100%);
      background-size: 200% 100%;
      transition: width 220ms ease;
      animation: mekong-flow-shift 2.8s linear infinite;
    }
    .flow-node {
      position: relative;
      z-index: 1;
      display: grid;
      justify-items: center;
      gap: 8px;
      min-width: 0;
      text-align: center;
    }
    .flow-icon {
      width: 46px;
      height: 46px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: #ffffff;
      display: grid;
      place-items: center;
      color: #9ca3af;
    }
    .flow-icon svg {
      width: 22px;
      height: 22px;
      display: block;
    }
    .flow-node.active .flow-icon {
      color: #22c55e;
      border-color: rgba(34, 197, 94, 0.24);
      box-shadow: inset 0 0 0 1px rgba(34, 197, 94, 0.06);
    }
    .flow-node.failed .flow-icon {
      color: #9ca3af;
    }
    .flow-indicator {
      width: 100%;
      height: 18px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .flow-dot {
      width: 14px;
      height: 14px;
      border-radius: 999px;
      border: 3px solid #fcfcfb;
      background: #9ca3af;
      box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.28);
    }
    .flow-node.active .flow-dot {
      background: #22c55e;
      animation: mekong-pulse 1.8s ease-out infinite;
    }
    .flow-node.active .flow-cross {
      display: none;
    }
    .flow-node.failed .flow-dot {
      width: 22px;
      height: 22px;
      border: 2px solid #ef4444;
      background: #ffffff;
      color: #ef4444;
      display: grid;
      place-items: center;
      box-shadow: 0 0 0 4px #fcfcfb;
      animation: mekong-error-pulse 1.8s ease-in-out infinite;
    }
    .flow-cross {
      font-size: 14px;
      line-height: 1;
      font-weight: 800;
      transform: translateY(-1px);
    }
    .flow-label {
      color: #3f3a34;
      font-size: 13px;
      font-weight: 700;
      line-height: 1.35;
      overflow-wrap: anywhere;
    }
    .flow-node.failed .flow-label {
      color: #6b7280;
    }
    .retry-note {
      margin: 14px 0 0;
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--muted);
      font-size: 13px;
      line-height: 1.6;
      overflow-wrap: anywhere;
    }
    .retry-note.is-ready {
      color: #166534;
    }
    .retry-dot {
      width: 9px;
      height: 9px;
      border-radius: 999px;
      background: #22c55e;
      flex: 0 0 auto;
      animation: mekong-retry-blink 1.6s ease-in-out infinite;
    }
    .retry-note.is-ready .retry-dot {
      animation: none;
      box-shadow: 0 0 0 6px rgba(34, 197, 94, 0.12);
    }
    .facts {
      margin-top: 22px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: #fcfcfb;
      padding: 16px;
    }
    .label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--muted);
      font-weight: 700;
      margin-bottom: 10px;
    }
    .facts dl {
      margin: 0;
      display: grid;
      gap: 12px;
    }
    .facts div {
      display: grid;
      gap: 4px;
    }
    dt {
      color: var(--muted);
      font-size: 13px;
      font-weight: 600;
    }
    dd {
      margin: 0;
      color: var(--ink);
      font-family: "SFMono-Regular", "JetBrains Mono", monospace;
      font-size: 14px;
      line-height: 1.55;
      word-break: break-word;
      overflow-wrap: anywhere;
    }
    .actions {
      display: flex;
      flex-wrap: wrap;
      gap: 14px;
      margin-top: 24px;
    }
    .actions a {
      text-decoration: none;
      border-radius: 14px;
      padding: 14px 18px;
      font-weight: 700;
      text-align: center;
      overflow-wrap: anywhere;
      transition: transform 120ms ease, opacity 120ms ease;
    }
    .actions a:hover { transform: translateY(-1px); opacity: 0.92; }
    .primary {
      background: linear-gradient(135deg, var(--accent) 0%, #1f2937 100%);
      color: white;
      box-shadow: 0 14px 32px rgba(16, 24, 40, 0.18);
    }
    .secondary {
      border: 1px solid var(--line);
      color: var(--ink);
      background: #ffffff;
    }
    .help {
      margin-top: 24px;
      padding-top: 20px;
      border-top: 1px solid var(--line);
      display: grid;
      gap: 20px;
    }
    .help-block h2 {
      margin: 0 0 10px;
      font-size: 15px;
      letter-spacing: -0.02em;
    }
    .help-block p {
      margin: 0;
      color: var(--muted);
      line-height: 1.7;
      overflow-wrap: anywhere;
    }
    pre {
      margin: 14px 0 0;
      border-radius: 12px;
      background: #151515;
      color: #f8fafc;
      padding: 14px 16px;
      overflow-x: auto;
      font-family: "SFMono-Regular", "JetBrains Mono", monospace;
      font-size: 13px;
      line-height: 1.6;
    }
    @keyframes mekong-flow-shift {
      0% { background-position: 200% 0; }
      100% { background-position: 0 0; }
    }
    @keyframes mekong-pulse {
      0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.34); }
      70% { box-shadow: 0 0 0 12px rgba(34, 197, 94, 0); }
      100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
    }
    @keyframes mekong-error-pulse {
      0%, 100% { transform: scale(1); box-shadow: 0 0 0 4px #fcfcfb, 0 0 0 0 rgba(239, 68, 68, 0.24); }
      50% { transform: scale(1.06); box-shadow: 0 0 0 4px #fcfcfb, 0 0 0 10px rgba(239, 68, 68, 0); }
    }
    @keyframes mekong-retry-blink {
      0%, 100% { opacity: 0.45; transform: scale(0.92); }
      50% { opacity: 1; transform: scale(1); }
    }
    @media (max-width: 720px) {
      body {
        padding: 10px;
        align-items: stretch;
      }
      .shell {
        width: 100%;
        border-radius: 20px;
      }
      .content {
        padding: 20px 16px 18px;
      }
      h1 {
        font-size: clamp(28px, 11vw, 42px);
      }
      .summary {
        font-size: 15px;
      }
      .flow {
        padding: 16px 10px 14px;
      }
      .flow-grid {
        gap: 6px;
      }
      .flow-line {
        top: 57px;
      }
      .flow-icon {
        width: 40px;
        height: 40px;
        border-radius: 12px;
      }
      .flow-icon svg {
        width: 19px;
        height: 19px;
      }
      .flow-label {
        font-size: 11px;
      }
      .flow-node.failed .flow-dot {
        width: 20px;
        height: 20px;
      }
      .facts {
        padding: 14px;
        border-radius: 16px;
      }
      .actions a {
        width: 100%;
        text-align: center;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="content">
      <p class="brand">MekongTunnel</p>
      <p class="status">{{.StatusLine}}</p>
      <div class="code">{{.Code}}</div>
      {{if .ShowConnectionFlow}}
      <h1>{{.DashboardTitle}}</h1>
      <div class="summary"><strong data-retry-title>{{.DashboardMessage}}</strong><span data-retry-text>{{.DashboardSubtext}}</span></div>
      <div class="flow" aria-label="Tunnel connection status">
        <div class="flow-grid">
          <div class="flow-line" aria-hidden="true">
            <span class="flow-line-active" data-flow-active></span>
          </div>
          <div class="flow-node active">
            <div class="flow-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="9"></circle>
                <path d="M3 12h18"></path>
                <path d="M12 3a14 14 0 0 1 0 18"></path>
                <path d="M12 3a14 14 0 0 0 0 18"></path>
              </svg>
            </div>
            <div class="flow-indicator"><span class="flow-dot"></span></div>
            <div class="flow-label">Internet</div>
          </div>
          <div class="flow-node active">
            <div class="flow-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M6.5 18h10a4 4 0 0 0 .7-7.94A5.5 5.5 0 0 0 6.2 9.7 3.8 3.8 0 0 0 6.5 18Z"></path>
                <path d="M9 12h.01"></path>
                <path d="M12 12h.01"></path>
                <path d="M15 12h.01"></path>
              </svg>
            </div>
            <div class="flow-indicator"><span class="flow-dot"></span></div>
            <div class="flow-label">Mekong Edge</div>
          </div>
          <div class="flow-node active">
            <div class="flow-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="4" width="18" height="16" rx="2"></rect>
                <path d="m8 10 3 2.5L8 15"></path>
                <path d="M13 15h4"></path>
              </svg>
            </div>
            <div class="flow-indicator"><span class="flow-dot"></span></div>
            <div class="flow-label">Mekong Agent</div>
          </div>
          <div class="flow-node failed" data-local-node>
            <div class="flow-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <rect x="4" y="4" width="16" height="6" rx="1.5"></rect>
                <rect x="4" y="14" width="16" height="6" rx="1.5"></rect>
                <path d="M8 7h.01"></path>
                <path d="M8 17h.01"></path>
              </svg>
            </div>
            <div class="flow-indicator"><span class="flow-dot"><span class="flow-cross">×</span></span></div>
            <div class="flow-label">Local Service</div>
          </div>
        </div>
      </div>
      <p class="retry-note" data-retry-note><span class="retry-dot" aria-hidden="true"></span><span data-retry-status>Checking again every 2 seconds. This page will open your app automatically when localhost responds.</span></p>
      {{else}}
      <h1>{{.Title}}</h1>
      <div class="summary">{{.Summary}}</div>
      {{end}}
      <div class="facts">
        <div class="label">Connection details</div>
        <dl>
          <div>
            <dt>Public host</dt>
            <dd>{{.PublicHost}}</dd>
          </div>
          {{if .ReservedSub}}
          <div>
            <dt>Reserved subdomain target</dt>
            <dd>{{.ReservedSub}}</dd>
          </div>
          {{end}}
          {{if .LastSeenLabel}}
          <div>
            <dt>Last seen</dt>
            <dd>{{.LastSeenLabel}}</dd>
          </div>
          {{end}}
          {{if .LocalTarget}}
          <div>
            <dt>Expected local app</dt>
            <dd>{{.LocalTarget}}</dd>
          </div>
          {{end}}
          {{if .HostHeader}}
          <div>
            <dt>Host header override</dt>
            <dd>{{.HostHeader}}</dd>
          </div>
          {{end}}
        </dl>
      </div>
      <div class="actions">
        <a class="primary" href="{{.PrimaryHref}}">{{.PrimaryLabel}}</a>
        <a class="secondary" href="{{.SecondaryHref}}">{{.SecondaryLabel}}</a>
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
    </div>
  </div>
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
