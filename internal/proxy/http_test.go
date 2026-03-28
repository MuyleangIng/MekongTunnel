// Tests for HTTP handling in the proxy package.
//
// Author: Ing Muyleang (អុឹង មួយលៀង) — Ing_Muyleang
package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/config"
	"github.com/MuyleangIng/MekongTunnel/internal/tunnel"
)

type stubTokenValidator struct {
	customTargets map[string]string
	reservedSubs  map[string]bool
	lastSeen      map[string]time.Time
}

func (s stubTokenValidator) ValidateToken(context.Context, string) (string, error) {
	return "", nil
}

func (s stubTokenValidator) GetFirstReservedSubdomain(context.Context, string) (string, error) {
	return "", nil
}

func (s stubTokenValidator) GetReservedSubdomainForUser(context.Context, string, string) (string, error) {
	return "", nil
}

func (s stubTokenValidator) LookupVerifiedCustomDomainTarget(_ context.Context, host string) (string, bool, error) {
	target, ok := s.customTargets[host]
	return target, ok, nil
}

func (s stubTokenValidator) ReservedSubdomainExists(_ context.Context, subdomain string) (bool, error) {
	return s.reservedSubs[subdomain], nil
}

func (s stubTokenValidator) GetTunnelLastSeen(_ context.Context, subdomain string) (*time.Time, error) {
	if ts, ok := s.lastSeen[subdomain]; ok {
		return &ts, nil
	}
	return nil, nil
}

func TestStripPort(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"with port", "example.com:443", "example.com"},
		{"without port", "example.com", "example.com"},
		{"ipv4 with port", "127.0.0.1:8080", "127.0.0.1"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripPort(tt.input); got != tt.want {
				t.Errorf("stripPort(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsBrowserRequest(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      bool
	}{
		{"chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0", true},
		{"firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0", true},
		{"curl", "curl/7.68.0", false},
		{"go http", "Go-http-client/1.1", false},
		{"empty", "", false},
		{"safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			r.Header.Set("User-Agent", tt.userAgent)
			if got := isBrowserRequest(r); got != tt.want {
				t.Errorf("isBrowserRequest(%q) = %v, want %v", tt.userAgent, got, tt.want)
			}
		})
	}
}

func TestIsWebSocketRequest(t *testing.T) {
	tests := []struct {
		name       string
		upgrade    string
		connection string
		want       bool
	}{
		{"valid websocket", "websocket", "Upgrade", true},
		{"case insensitive", "WebSocket", "upgrade", true},
		{"missing upgrade header", "", "Upgrade", false},
		{"missing connection header", "websocket", "", false},
		{"wrong upgrade value", "http/2", "Upgrade", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			if tt.upgrade != "" {
				r.Header.Set("Upgrade", tt.upgrade)
			}
			if tt.connection != "" {
				r.Header.Set("Connection", tt.connection)
			}
			if got := isWebSocketRequest(r); got != tt.want {
				t.Errorf("isWebSocketRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasWarningCookie(t *testing.T) {
	sub := "test-sub-12345678"
	cookieName := config.WarningCookieName + "_" + sub

	tests := []struct {
		name   string
		cookie *http.Cookie
		want   bool
	}{
		{"no cookie", nil, false},
		{"valid cookie", &http.Cookie{Name: cookieName, Value: "1"}, true},
		{"wrong value", &http.Cookie{Name: cookieName, Value: "0"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{}}
			if tt.cookie != nil {
				r.AddCookie(tt.cookie)
			}
			if got := hasWarningCookie(r, sub); got != tt.want {
				t.Errorf("hasWarningCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetSecurityHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	setSecurityHeaders(w)

	expected := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-Xss-Protection":       "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	for header, want := range expected {
		if got := w.Header().Get(header); got != want {
			t.Errorf("header %q = %q, want %q", header, got, want)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"2 hours", 2 * time.Hour, "2h"},
		{"1 hour", 1 * time.Hour, "1h"},
		{"90 minutes", 90 * time.Minute, "1h"},
		{"45 minutes", 45 * time.Minute, "45m"},
		{"10 minutes", 10 * time.Minute, "10m"},
		{"3 hours", 3 * time.Hour, "3h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDuration(tt.d); got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestLimitedReadCloser(t *testing.T) {
	t.Run("within limit", func(t *testing.T) {
		data := "hello world"
		rc := io.NopCloser(strings.NewReader(data))
		lrc := &limitedReadCloser{rc: rc, limit: 100}

		buf, err := io.ReadAll(lrc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(buf) != data {
			t.Errorf("got %q, want %q", string(buf), data)
		}
	})

	t.Run("exceeds limit", func(t *testing.T) {
		data := "hello world"
		rc := io.NopCloser(strings.NewReader(data))
		lrc := &limitedReadCloser{rc: rc, limit: 5}

		buf := make([]byte, 20)
		n, err := lrc.Read(buf)
		if err != nil {
			t.Fatalf("first read error: %v", err)
		}
		if n != 5 {
			t.Errorf("first read got %d bytes, want 5", n)
		}

		_, err = lrc.Read(buf)
		if err == nil {
			t.Error("expected error after exceeding limit")
		}
	})

	t.Run("close", func(t *testing.T) {
		rc := io.NopCloser(strings.NewReader("test"))
		lrc := &limitedReadCloser{rc: rc, limit: 100}
		if err := lrc.Close(); err != nil {
			t.Errorf("Close() error: %v", err)
		}
	})
}

func TestCopyWithLimits(t *testing.T) {
	t.Run("normal copy", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		data := []byte("hello world")
		go func() {
			server.Write(data)
			server.Close()
		}()

		dst, dstWriter := net.Pipe()
		defer dst.Close()
		defer dstWriter.Close()

		received := make(chan []byte, 1)
		go func() {
			buf, _ := io.ReadAll(dst)
			received <- buf
		}()

		n, err := copyWithLimits(dstWriter, client, 1024, 5*time.Second)
		dstWriter.Close()

		if err != nil {
			t.Fatalf("copyWithLimits error: %v", err)
		}
		if n != int64(len(data)) {
			t.Errorf("copyWithLimits returned %d bytes, want %d", n, len(data))
		}

		got := <-received
		if string(got) != string(data) {
			t.Errorf("got %q, want %q", string(got), string(data))
		}
	})

	t.Run("transfer limit exceeded", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		go func() {
			buf := make([]byte, 100)
			for i := 0; i < 100; i++ {
				server.Write(buf)
			}
			server.Close()
		}()

		dst, dstWriter := net.Pipe()
		defer dst.Close()
		defer dstWriter.Close()

		go io.Copy(io.Discard, dst)

		_, err := copyWithLimits(dstWriter, client, 500, 5*time.Second)
		if err == nil || !strings.Contains(err.Error(), "transfer limit exceeded") {
			t.Errorf("expected transfer limit exceeded error, got: %v", err)
		}
	})

	t.Run("idle timeout", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		dst, dstWriter := net.Pipe()
		defer dst.Close()
		defer dstWriter.Close()

		go io.Copy(io.Discard, dst)

		_, err := copyWithLimits(dstWriter, client, 1024, 50*time.Millisecond)
		if err == nil {
			t.Error("expected timeout error, got nil")
		}
	})
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(
		t.TempDir()+"/host_key",
		config.DefaultDomain,
		config.DefaultMaxTunnelsPerIP,
		config.DefaultMaxTotalTunnels,
		config.DefaultMaxConnectionsPerMin,
	)
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	t.Cleanup(func() { s.Stop() })
	return s
}

func TestHTTPRedirectHandler(t *testing.T) {
	s := newTestServer(t)
	handler := s.HTTPRedirectHandler()

	tests := []struct {
		name       string
		host       string
		path       string
		wantCode   int
		wantTarget string
	}{
		{
			"subdomain redirect",
			"test-sub-12345678." + config.DefaultDomain,
			"/foo",
			http.StatusMovedPermanently,
			"https://test-sub-12345678." + config.DefaultDomain + "/foo",
		},
		{
			"bare domain redirect",
			config.DefaultDomain,
			"/",
			http.StatusMovedPermanently,
			"https://" + config.DefaultDomain + "/",
		},
		{
			"bad domain rejected",
			"evil.com",
			"/",
			http.StatusBadRequest,
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://"+tt.host+tt.path, nil)
			r.Host = tt.host
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			if w.Code != tt.wantCode {
				t.Errorf("status = %d, want %d", w.Code, tt.wantCode)
			}
			if tt.wantTarget != "" {
				loc := w.Header().Get("Location")
				if loc != tt.wantTarget {
					t.Errorf("Location = %q, want %q", loc, tt.wantTarget)
				}
			}
		})
	}
}

func TestStatusCaptureWriter(t *testing.T) {
	t.Run("captures explicit status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		sw := &statusCaptureWriter{ResponseWriter: rec}
		sw.WriteHeader(http.StatusNotFound)

		if sw.status != http.StatusNotFound {
			t.Errorf("status = %d, want %d", sw.status, http.StatusNotFound)
		}
	})

	t.Run("defaults to 200 on Write", func(t *testing.T) {
		rec := httptest.NewRecorder()
		sw := &statusCaptureWriter{ResponseWriter: rec}
		sw.Write([]byte("hello"))

		if sw.status != http.StatusOK {
			t.Errorf("status = %d, want %d", sw.status, http.StatusOK)
		}
	})

	t.Run("first WriteHeader wins", func(t *testing.T) {
		rec := httptest.NewRecorder()
		sw := &statusCaptureWriter{ResponseWriter: rec}
		sw.WriteHeader(http.StatusCreated)
		sw.WriteHeader(http.StatusNotFound)

		if sw.status != http.StatusCreated {
			t.Errorf("status = %d, want %d (first call should win)", sw.status, http.StatusCreated)
		}
	})

	t.Run("Unwrap returns inner writer", func(t *testing.T) {
		rec := httptest.NewRecorder()
		sw := &statusCaptureWriter{ResponseWriter: rec}

		if sw.Unwrap() != rec {
			t.Error("Unwrap() should return the underlying ResponseWriter")
		}
	})
}

func TestRedirectToWarningPage(t *testing.T) {
	s := newTestServer(t)
	sub := "happy-tiger-abcdef01"
	host := "happy-tiger-abcdef01." + config.DefaultDomain
	r := httptest.NewRequest("GET", "https://"+host+"/path?q=1", nil)
	r.Host = host
	w := httptest.NewRecorder()

	s.redirectToWarningPage(w, r, sub)

	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want %d", w.Code, http.StatusTemporaryRedirect)
	}

	loc := w.Header().Get("Location")
	wantPrefix := "https://" + config.DefaultDomain + "/?"
	if !strings.HasPrefix(loc, wantPrefix) {
		t.Errorf("Location = %q, want prefix %q", loc, wantPrefix)
	}
	if !strings.Contains(loc, "redirect="+url.QueryEscape("https://"+host+"/path?q=1")) {
		t.Errorf("Location missing redirect param: %q", loc)
	}
	if !strings.Contains(loc, "subdomain="+url.QueryEscape(host)) {
		t.Errorf("Location missing subdomain param: %q", loc)
	}
}

func TestServeWarningPageRendersSharedTunnelNotice(t *testing.T) {
	s := newTestServer(t)
	r := httptest.NewRequest("GET", "https://"+config.DefaultDomain+"/?redirect=https%3A%2F%2Fmyapp."+config.DefaultDomain+"%2F&subdomain=myapp."+config.DefaultDomain, nil)
	r.Host = config.DefaultDomain
	w := httptest.NewRecorder()

	s.serveWarningPage(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if !strings.Contains(body, "You are about to open a shared tunnel.") {
		t.Fatalf("warning page body missing shared-tunnel title: %q", body)
	}
	if !strings.Contains(body, "Continue to site") {
		t.Fatalf("warning page body missing simplified CTA label: %q", body)
	}
	if strings.Contains(body, "Back to MekongTunnel") {
		t.Fatalf("warning page body still contains confusing back link: %q", body)
	}
	if strings.Contains(body, "<form") {
		t.Fatalf("warning page should use an anchor CTA instead of a form: %q", body)
	}
	wantHref := strings.ReplaceAll(warningContinueHref("https://myapp."+config.DefaultDomain+"/", "myapp."+config.DefaultDomain), "&", "&amp;")
	if !strings.Contains(body, `href="`+wantHref+`"`) {
		t.Fatalf("warning page CTA should use the one-click continue redirect: %q", body)
	}
	if !strings.Contains(body, `data-destination="https://myapp.`+config.DefaultDomain+`/"`) {
		t.Fatalf("warning page CTA missing destination marker: %q", body)
	}
	if strings.Contains(body, `data-warning-confirm=`) {
		t.Fatalf("warning page should not use background confirm fetch anymore: %q", body)
	}
	if !strings.Contains(body, `data-loading-label="Opening site..."`) {
		t.Fatalf("warning page CTA missing loading label: %q", body)
	}
	if !strings.Contains(body, "cta-spinner") {
		t.Fatalf("warning page CTA missing loading spinner markup: %q", body)
	}
	if strings.Contains(body, "https%253A%252F%252F") {
		t.Fatalf("warning page CTA still double-encodes redirect target: %q", body)
	}
	if !strings.Contains(body, "Before you continue") {
		t.Fatalf("warning page missing safety notice section: %q", body)
	}
	if strings.Contains(body, "cta-meta") {
		t.Fatalf("warning page should not render the old CTA meta text: %q", body)
	}
}

func TestServeWarningPageContinueLinkSetsCookieAndRedirects(t *testing.T) {
	s := newTestServer(t)
	redirect := "https://myapp." + config.DefaultDomain + "/"
	sub := "myapp." + config.DefaultDomain
	r := httptest.NewRequest("GET", "https://"+config.DefaultDomain+"/?continue=1&redirect="+url.QueryEscape(redirect)+"&subdomain="+url.QueryEscape(sub), nil)
	r.Host = config.DefaultDomain
	w := httptest.NewRecorder()

	s.serveWarningPage(w, r)

	if w.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusSeeOther)
	}
	if loc := w.Header().Get("Location"); loc != redirect {
		t.Fatalf("Location = %q, want %q", loc, redirect)
	}
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected warning cookie to be set")
	}
	found := false
	for _, c := range cookies {
		if c.Name == config.WarningCookieName+"_myapp" {
			found = true
			if strings.TrimPrefix(c.Domain, ".") != config.DefaultDomain {
				t.Fatalf("cookie domain = %q, want %q", c.Domain, config.DefaultDomain)
			}
			if c.MaxAge != config.WarningCookieMaxAge {
				t.Fatalf("cookie MaxAge = %d, want %d", c.MaxAge, config.WarningCookieMaxAge)
			}
		}
	}
	if !found {
		t.Fatalf("warning cookie %q was not set", config.WarningCookieName+"_myapp")
	}
}

func TestServeHTTPShowsOfflinePageForMissingTunnelInBrowser(t *testing.T) {
	s := newTestServer(t)

	sub := "happy-tiger-a1b2c3d4"
	s.tokenValidator = stubTokenValidator{
		reservedSubs: map[string]bool{sub: true},
	}
	r := httptest.NewRequest("GET", "https://"+sub+"."+config.DefaultDomain+"/", nil)
	r.Host = sub + "." + config.DefaultDomain
	r.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
	if got := w.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", got)
	}
	body := w.Body.String()
	if !strings.Contains(body, "ERR_MEKONG_TUNNEL_OFFLINE") {
		t.Fatalf("body missing offline code: %q", body)
	}
	if !strings.Contains(body, "This tunnel is currently offline") {
		t.Fatalf("body missing offline title: %q", body)
	}
}

func TestServeHTTPShowsNotFoundPageForUnknownSubdomainInBrowser(t *testing.T) {
	s := newTestServer(t)

	sub := "happy-tiger-a1b2c3d4"
	r := httptest.NewRequest("GET", "https://"+sub+"."+config.DefaultDomain+"/", nil)
	r.Host = sub + "." + config.DefaultDomain
	r.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	body := w.Body.String()
	if !strings.Contains(body, "ERR_MEKONG_TUNNEL_NOT_FOUND") {
		t.Fatalf("body missing not-found code: %q", body)
	}
	if !strings.Contains(body, "No tunnel found for this address") {
		t.Fatalf("body missing not-found title: %q", body)
	}
}

func TestServeHTTPShowsUpstreamUnavailablePage(t *testing.T) {
	s := newTestServer(t)
	s.tokenValidator = stubTokenValidator{
		customTargets: map[string]string{
			"app.example.com": "myapp",
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tun := tunnel.New("myapp", listener, "localhost", 3000, "127.0.0.1", time.Hour)
	tun.SetLocalPort(3000)
	s.mu.Lock()
	s.tunnels["myapp"] = tun
	s.mu.Unlock()
	_ = listener.Close()

	r := httptest.NewRequest("GET", "https://app.example.com/", nil)
	r.Host = "app.example.com"
	r.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
	body := w.Body.String()
	if !strings.Contains(body, "ERR_MEKONG_UPSTREAM_UNREACHABLE") {
		t.Fatalf("body missing upstream code: %q", body)
	}
	if !strings.Contains(body, "Tunnel Status") {
		t.Fatalf("body missing tunnel status dashboard title: %q", body)
	}
	if !strings.Contains(body, "Tunnel is active, but the local service is not reachable") {
		t.Fatalf("body missing tunnel status main message: %q", body)
	}
	for _, label := range []string{"Internet", "Mekong Edge", "Mekong Agent", "Local Service"} {
		if !strings.Contains(body, label) {
			t.Fatalf("body missing connection flow label %q: %q", label, body)
		}
	}
	if !strings.Contains(body, "Checking again every 2 seconds") {
		t.Fatalf("body missing retry note: %q", body)
	}
	if !strings.Contains(body, "flow-line-active") {
		t.Fatalf("body missing animated active flow segment: %q", body)
	}
	if !strings.Contains(body, `data-local-node`) {
		t.Fatalf("body missing local node marker for recovery state: %q", body)
	}
	if !strings.Contains(body, `flow-node failed`) {
		t.Fatalf("body missing failed local service state: %q", body)
	}
	if !strings.Contains(body, "window.location.reload()") {
		t.Fatalf("body missing auto-reload recovery script: %q", body)
	}
	if !strings.Contains(body, "localhost:3000") {
		t.Fatalf("body missing local target: %q", body)
	}
}

func TestServeHTTPShowsClientLocalPortInsteadOfRemoteBindPort(t *testing.T) {
	s := newTestServer(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tun := tunnel.New("myapp", listener, "localhost", 80, "127.0.0.1", time.Hour)
	tun.SetLocalPort(3000)
	s.mu.Lock()
	s.tunnels["myapp"] = tun
	s.mu.Unlock()
	_ = listener.Close()

	r := httptest.NewRequest("GET", "https://myapp."+config.DefaultDomain+"/", nil)
	r.Host = "myapp." + config.DefaultDomain
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("mekongtunnel-skip-warning", "1")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
	body := w.Body.String()
	if !strings.Contains(body, "localhost:3000") {
		t.Fatalf("body missing client local port target: %q", body)
	}
	if strings.Contains(body, "localhost:80") {
		t.Fatalf("body still shows remote bind port instead of client local port: %q", body)
	}
}

func TestServeHTTPDoesNotGuessClientLocalPortFromRemoteBindPort(t *testing.T) {
	s := newTestServer(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tun := tunnel.New("myapp", listener, "localhost", 80, "127.0.0.1", time.Hour)
	s.mu.Lock()
	s.tunnels["myapp"] = tun
	s.mu.Unlock()
	_ = listener.Close()

	r := httptest.NewRequest("GET", "https://myapp."+config.DefaultDomain+"/", nil)
	r.Host = "myapp." + config.DefaultDomain
	r.Header.Set("User-Agent", "Mozilla/5.0")
	r.Header.Set("mekongtunnel-skip-warning", "1")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadGateway)
	}
	body := w.Body.String()
	if strings.Contains(body, "localhost:80") {
		t.Fatalf("body guessed the remote bind port as the client local app: %q", body)
	}
	if strings.Contains(body, "Expected local app") {
		t.Fatalf("body should omit expected local app when the client did not report one: %q", body)
	}
	if !strings.Contains(body, "mekong &lt;local-port&gt;") {
		t.Fatalf("body missing placeholder reconnect command: %q", body)
	}
	if !strings.Contains(body, "did not report its local app port") {
		t.Fatalf("body missing missing-port explanation: %q", body)
	}
}

func TestServeHTTPAllowsActiveReservedSubdomain(t *testing.T) {
	s := newTestServer(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "reserved ok")
	})}
	go func() { _ = backend.Serve(listener) }()
	t.Cleanup(func() { _ = backend.Close() })

	tun := tunnel.New("myapp", listener, "localhost", 8080, "127.0.0.1", time.Hour)
	s.mu.Lock()
	s.tunnels["myapp"] = tun
	s.mu.Unlock()

	r := httptest.NewRequest("GET", "https://myapp."+config.DefaultDomain+"/", nil)
	r.Host = "myapp." + config.DefaultDomain
	r.Header.Set("User-Agent", "curl/8.0.0")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if body := w.Body.String(); body != "reserved ok" {
		t.Fatalf("body = %q, want %q", body, "reserved ok")
	}
}

func TestServeHTTPRoutesVerifiedCustomDomain(t *testing.T) {
	s := newTestServer(t)
	s.tokenValidator = stubTokenValidator{
		customTargets: map[string]string{
			"app.example.com": "myapp",
		},
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "custom ok")
	})}
	go func() { _ = backend.Serve(listener) }()
	t.Cleanup(func() { _ = backend.Close() })

	tun := tunnel.New("myapp", listener, "localhost", 8080, "127.0.0.1", time.Hour)
	s.mu.Lock()
	s.tunnels["myapp"] = tun
	s.mu.Unlock()

	r := httptest.NewRequest("GET", "https://app.example.com/", nil)
	r.Host = "app.example.com"
	r.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if body := w.Body.String(); body != "custom ok" {
		t.Fatalf("body = %q, want %q", body, "custom ok")
	}
}

func TestServeHTTPUsesUpstreamHostOverride(t *testing.T) {
	s := newTestServer(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Host; got != "myapp.test" {
			t.Fatalf("backend Host = %q, want %q", got, "myapp.test")
		}
		if got := r.Header.Get("X-Forwarded-Host"); got != "myapp."+config.DefaultDomain {
			t.Fatalf("X-Forwarded-Host = %q, want %q", got, "myapp."+config.DefaultDomain)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "host override ok")
	})}
	go func() { _ = backend.Serve(listener) }()
	t.Cleanup(func() { _ = backend.Close() })

	tun := tunnel.New("myapp", listener, "localhost", 8080, "127.0.0.1", time.Hour)
	tun.SetUpstreamHost("myapp.test")
	s.mu.Lock()
	s.tunnels["myapp"] = tun
	s.mu.Unlock()

	r := httptest.NewRequest("GET", "https://myapp."+config.DefaultDomain+"/", nil)
	r.Host = "myapp." + config.DefaultDomain
	r.Header.Set("User-Agent", "curl/8.0.0")
	w := httptest.NewRecorder()

	s.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if body := w.Body.String(); body != "host override ok" {
		t.Fatalf("body = %q, want %q", body, "host override ok")
	}
}

func TestHTTPRedirectHandlerAllowsVerifiedCustomDomain(t *testing.T) {
	s := newTestServer(t)
	s.tokenValidator = stubTokenValidator{
		customTargets: map[string]string{
			"app.example.com": "myapp",
		},
	}

	r := httptest.NewRequest("GET", "http://app.example.com/docs", nil)
	r.Host = "app.example.com"
	w := httptest.NewRecorder()

	s.HTTPRedirectHandler().ServeHTTP(w, r)

	if w.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusMovedPermanently)
	}
	if got := w.Header().Get("Location"); got != "https://app.example.com/docs" {
		t.Fatalf("Location = %q, want %q", got, "https://app.example.com/docs")
	}
}
