// HTTP and HTTPS request handling for MekongTunnel.
// ServeHTTP is the main HTTPS reverse proxy: it validates the subdomain,
// enforces rate limits, shows a phishing-warning interstitial for browsers,
// and proxies requests (including WebSocket) to the client's local application
// via the SSH tunnel.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package proxy

import (
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"muyleanging.com/mekongtunnel/internal/config"
	"muyleanging.com/mekongtunnel/internal/domain"
	"muyleanging.com/mekongtunnel/internal/tunnel"
)

// ServeHTTP implements http.Handler for all HTTPS requests.
//
// Request flow:
//  1. Set security headers on every response
//  2. Enforce request body size limit (128 MB)
//  3. Extract and validate the subdomain from the Host header
//  4. Look up the active tunnel in the registry
//  5. Check per-tunnel rate limit (10 req/s, burst 20)
//  6. Optionally show a phishing-warning page for browser requests
//  7. Handle WebSocket upgrade or reverse-proxy the request
//  8. Log request (method, path, status, latency) to the SSH terminal
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)

	// Reject oversized request bodies early to avoid memory pressure.
	if r.ContentLength > config.MaxRequestBodySize {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, config.MaxRequestBodySize)

	host := stripPort(r.Host)

	// Only accept requests for subdomains of our configured domain.
	if !strings.HasSuffix(host, "."+s.domain) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sub := strings.TrimSuffix(host, "."+s.domain)

	// Validate subdomain against the whitelist to prevent injection attacks.
	if !domain.IsValid(sub) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	tun := s.GetTunnel(sub)
	if tun == nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
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
	if isBrowserRequest(r) &&
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
			// Rewrite the request to target the tunnel's internal TCP listener.
			req.URL.Scheme = "http"
			req.URL.Host = tun.Listener.Addr().String()
			req.Host = r.Host
		},
		Transport: tun.Transport(),
		ModifyResponse: func(resp *http.Response) error {
			// Reject responses that declare they are too large.
			if resp.ContentLength > config.MaxResponseBodySize {
				return fmt.Errorf("response too large: %d bytes (max %d)", resp.ContentLength, config.MaxResponseBodySize)
			}
			// Wrap the body for chunked/unknown-length responses to enforce the limit.
			resp.Body = &limitedReadCloser{
				rc:    resp.Body,
				limit: config.MaxResponseBodySize,
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error for %s: %v", sub, err)
			if strings.Contains(err.Error(), "response too large") {
				http.Error(w, "Response Too Large", http.StatusBadGateway)
				return
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(sw, r)

	// Emit a log line to the SSH terminal for every proxied request.
	if logger := tun.Logger(); logger != nil {
		logger.LogRequest(r.Method, r.URL.Path, sw.status, time.Since(requestStart))
	}
}

// handleWebSocket handles WebSocket upgrade requests by hijacking the client connection,
// dialling the backend tunnel listener, forwarding the upgrade handshake, then copying
// data bidirectionally with a per-direction 1 GB limit and 2-hour idle timeout.
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

	// Forward the original HTTP upgrade request to the backend.
	if err := r.Write(backendConn); err != nil {
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
			if written > maxBytes {
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

// setSecurityHeaders adds standard security headers to every response.
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
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

// redirectToWarningPage redirects the browser to the phishing-warning interstitial page
// on the root domain, passing the original URL and subdomain as query parameters.
func (s *Server) redirectToWarningPage(w http.ResponseWriter, r *http.Request, sub string) {
	originalURL := "https://" + r.Host + r.URL.RequestURI()
	fullSubdomain := sub + "." + s.domain
	warningURL := fmt.Sprintf("https://%s/#/warning?redirect=%s&subdomain=%s",
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
	status      int
	wroteHeader bool
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
	return w.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter so that interface pass-throughs
// (e.g. http.Flusher, http.Hijacker) work correctly.
func (w *statusCaptureWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// HTTPRedirectHandler returns an http.Handler that permanently redirects
// all HTTP requests to their HTTPS equivalent (301 Moved Permanently).
// Only requests for our domain or its subdomains are accepted; others get 400.
func (s *Server) HTTPRedirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := stripPort(r.Host)
		if !strings.HasSuffix(host, "."+s.domain) && host != s.domain {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}
