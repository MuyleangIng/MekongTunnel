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

	// Serve the warning interstitial page for requests to the root domain.
	if host == s.domain {
		s.serveWarningPage(w, r)
		return
	}

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

// serveWarningPage serves the phishing-warning interstitial HTML page on the root domain.
// It reads the redirect and subdomain from query parameters and sets a cookie on confirm.
func (s *Server) serveWarningPage(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	sub := r.URL.Query().Get("subdomain")

	if r.Method == http.MethodPost {
		if redirect == "" {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		subName := strings.TrimSuffix(sub, "."+s.domain)
		http.SetCookie(w, &http.Cookie{
			Name:   config.WarningCookieName + "_" + subName,
			Value:  "1",
			Path:   "/",
			Domain: sub,
			MaxAge: config.WarningCookieMaxAge,
		})
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}

	if redirect == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!DOCTYPE html><html><body style="font-family:sans-serif;text-align:center;padding:60px">
<h1>MekongTunnel</h1><p>No tunnel specified.</p></body></html>`)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MekongTunnel — Security Warning</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f0f0f; color: #e0e0e0; display: flex;
         align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
  .card { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 12px;
          max-width: 520px; width: 100%%; padding: 40px; text-align: center; }
  .logo { color: #00bcd4; font-size: 22px; font-weight: 700; letter-spacing: 1px; margin-bottom: 8px; }
  .author { color: #888; font-size: 13px; margin-bottom: 32px; }
  .icon { font-size: 48px; margin-bottom: 16px; }
  h1 { font-size: 20px; color: #f5a623; margin-bottom: 12px; }
  p { color: #aaa; font-size: 14px; line-height: 1.6; margin-bottom: 10px; }
  .url { background: #111; border: 1px solid #333; border-radius: 6px;
         padding: 10px 16px; font-family: monospace; font-size: 13px;
         color: #7c9fd4; word-break: break-all; margin: 20px 0; }
  .btn { display: inline-block; background: #00bcd4; color: #000; font-weight: 600;
         font-size: 15px; padding: 12px 32px; border-radius: 8px; border: none;
         cursor: pointer; text-decoration: none; margin-top: 8px; width: 100%%; }
  .btn:hover { background: #00acc1; }
  .dismiss { color: #555; font-size: 12px; margin-top: 16px; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">MekongTunnel</div>
  <div class="author">by Ing Muyleang · Founder of KhmerStack</div>
  <div class="icon">⚠️</div>
  <h1>You are leaving a secure site</h1>
  <p>This link points to a tunnel hosted by a third party. MekongTunnel is not responsible for its content.</p>
  <div class="url">%s</div>
  <p>Only proceed if you trust the person who shared this link.</p>
  <form method="POST" action="/?redirect=%s&subdomain=%s">
    <button class="btn" type="submit">I understand, take me there</button>
  </form>
  <p class="dismiss">This warning will not show again for 24 hours.</p>
</div>
</body>
</html>`, redirect, url.QueryEscape(redirect), url.QueryEscape(sub))
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
