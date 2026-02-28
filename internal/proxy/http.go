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

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/domain"
	"github.com/MuyleangIng/MekongTunnel/internal/tunnel"
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

	// Root domain (mekongtunnel.dev): serve warning interstitial when it's a
	// tunnel warning flow (has redirect param or is a POST confirmation),
	// otherwise redirect to the Vercel landing page.
	if host == s.domain {
		if r.URL.Query().Get("redirect") != "" || r.Method == http.MethodPost {
			s.serveWarningPage(w, r)
			return
		}
		http.Redirect(w, r, "https://mekongtunnel-dev.vercel.app/", http.StatusTemporaryRedirect)
		return
	}

	// Only accept requests for subdomains of our configured domain.
	if !strings.HasSuffix(host, "."+s.domain) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	sub := strings.TrimSuffix(host, "."+s.domain)

	// Accept both auto-generated (adjective-noun-hex) and custom subdomains.
	if !domain.IsValid(sub) && !domain.IsValidCustom(sub) {
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
	tun.IncrementRequestCount()

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
		// Set cookie on the parent domain (with leading dot) so it is sent
		// to the subdomain tunnel on the next request.
		http.SetCookie(w, &http.Cookie{
			Name:   config.WarningCookieName + "_" + subName,
			Value:  "1",
			Path:   "/",
			Domain: "." + s.domain,
			MaxAge: config.WarningCookieMaxAge,
		})
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}

	if redirect == "" {
		http.Redirect(w, r, "https://mekongtunnel-dev.vercel.app/", http.StatusTemporaryRedirect)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="km">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MekongTunnel — ការព្រមាន</title>
<link href="https://fonts.googleapis.com/css2?family=Hanuman:wght@400;700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', sans-serif;
    background: #0d0d1a;
    background-image: radial-gradient(ellipse at top, #1a1035 0%%, #0d0d1a 70%%);
    color: #e0e0e0;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 20px;
  }
  .card {
    background: linear-gradient(145deg, #16162a, #1e1e38);
    border: 1px solid #FFD70033;
    border-radius: 16px;
    max-width: 540px;
    width: 100%%;
    padding: 44px 40px;
    text-align: center;
    box-shadow: 0 0 60px #FFD70015, 0 20px 40px #00000060;
  }
  .top-border {
    height: 3px;
    background: linear-gradient(90deg, #cc0001, #FFD700, #cc0001);
    border-radius: 3px 3px 0 0;
    margin: -44px -40px 36px;
    border-top-left-radius: 16px;
    border-top-right-radius: 16px;
  }
  .logo {
    font-family: 'Inter', sans-serif;
    color: #FFD700;
    font-size: 20px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 4px;
  }
  .author {
    color: #888;
    font-size: 12px;
    margin-bottom: 32px;
    letter-spacing: 0.5px;
  }
  .author span { color: #FFD70099; }
  .shield {
    width: 64px;
    height: 64px;
    background: linear-gradient(135deg, #cc000122, #FFD70022);
    border: 2px solid #cc000155;
    border-radius: 50%%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 28px;
    margin: 0 auto 20px;
  }
  .km-title {
    font-family: 'Hanuman', serif;
    font-size: 22px;
    color: #FFD700;
    margin-bottom: 8px;
    line-height: 1.5;
  }
  .en-subtitle {
    font-size: 13px;
    color: #cc4444;
    font-weight: 600;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-bottom: 20px;
  }
  .km-desc {
    font-family: 'Hanuman', serif;
    color: #aaa;
    font-size: 15px;
    line-height: 1.8;
    margin-bottom: 8px;
  }
  .en-desc {
    color: #666;
    font-size: 12px;
    line-height: 1.6;
    margin-bottom: 20px;
  }
  .url-box {
    background: #0a0a16;
    border: 1px solid #FFD70033;
    border-radius: 8px;
    padding: 12px 16px;
    font-family: monospace;
    font-size: 13px;
    color: #7c9fd4;
    word-break: break-all;
    margin: 20px 0;
    text-align: left;
  }
  .url-label {
    font-size: 10px;
    color: #FFD70077;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 4px;
  }
  .divider {
    border: none;
    border-top: 1px solid #ffffff11;
    margin: 20px 0;
  }
  .btn {
    display: block;
    width: 100%%;
    background: linear-gradient(135deg, #cc0001, #8b0000);
    color: #fff;
    font-family: 'Hanuman', serif;
    font-weight: 700;
    font-size: 17px;
    padding: 14px 32px;
    border-radius: 10px;
    border: none;
    cursor: pointer;
    margin-top: 8px;
    letter-spacing: 0.5px;
    transition: opacity 0.2s;
    line-height: 1.6;
  }
  .btn:hover { opacity: 0.88; }
  .btn-sub {
    font-family: 'Inter', sans-serif;
    font-size: 11px;
    font-weight: 400;
    opacity: 0.7;
    display: block;
    margin-top: 2px;
  }
  .dismiss {
    font-family: 'Hanuman', serif;
    color: #444;
    font-size: 13px;
    margin-top: 20px;
    line-height: 1.6;
  }
</style>
</head>
<body>
<div class="card">
  <div class="top-border"></div>
  <div class="logo">MekongTunnel</div>
  <div class="author">បង្កើតដោយ <span>អុឹង មួយលៀង (Ing Muyleang)</span> · KhmerStack</div>

  <div class="shield">🛡️</div>

  <div class="km-title">ការព្រមានសុវត្ថិភាព</div>
  <div class="en-subtitle">Security Notice</div>

  <div class="km-desc">
    អ្នកកំពុងចូលទៅកាន់ផ្លូវទំនាក់ទំនងរបស់ភាគីទីបី។<br>
    MekongTunnel មិនទទួលខុសត្រូវចំពោះមាតិការបស់ខ្លឹមសារនោះទេ។
  </div>
  <div class="en-desc">
    You are about to visit a third-party tunnel.<br>
    MekongTunnel is not responsible for its content.
  </div>

  <div class="url-box">
    <div class="url-label">គោលដៅ · Destination</div>
    %s
  </div>

  <div class="km-desc" style="font-size:14px;color:#888">
    សូមបន្តតែប្រសិនបើអ្នកទុកចិត្តអ្នកដែលបានចែករំលែកតំណភ្ជាប់នេះ។
  </div>

  <hr class="divider">

  <form method="POST" action="/?redirect=%s&subdomain=%s">
    <button class="btn" type="submit">
      ខ្ញុំយល់ព្រម បន្តទៅមុខ
      <span class="btn-sub">I understand, take me there</span>
    </button>
  </form>

  <p class="dismiss">ការព្រមាននេះនឹងមិនបង្ហាញម្តងទៀតក្នុងរយៈពេល ២៤ ម៉ោង។</p>
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
