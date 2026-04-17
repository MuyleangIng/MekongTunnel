package main

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNormalizeRequestedSubdomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "lowercase", input: "myapp", want: "myapp"},
		{name: "trim and lower", input: "  My-App-1 ", want: "my-app-1"},
		{name: "empty ok", input: "   ", want: ""},
		{name: "reject spaces", input: "my app", wantErr: true},
		{name: "reject symbols", input: "my$app", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeRequestedSubdomain(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeRequestedSubdomain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("normalizeRequestedSubdomain() = %q, want %q", got, tt.want)
			}
		})
	}
}

type stubConn struct{}

func (stubConn) Read([]byte) (int, error)         { return 0, nil }
func (stubConn) Write([]byte) (int, error)        { return 0, nil }
func (stubConn) Close() error                     { return nil }
func (stubConn) LocalAddr() net.Addr              { return nil }
func (stubConn) RemoteAddr() net.Addr             { return nil }
func (stubConn) SetDeadline(time.Time) error      { return nil }
func (stubConn) SetReadDeadline(time.Time) error  { return nil }
func (stubConn) SetWriteDeadline(time.Time) error { return nil }

func TestEnsureLocalPortReady(t *testing.T) {
	oldDial := localDial
	t.Cleanup(func() { localDial = oldDial })
	localDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return stubConn{}, nil
	}

	if err := ensureLocalPortReady(3000); err != nil {
		t.Fatalf("ensureLocalPortReady() error = %v", err)
	}
}

func TestEnsureLocalPortReadyFailsForClosedPort(t *testing.T) {
	oldDial := localDial
	t.Cleanup(func() { localDial = oldDial })
	localDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	if err := ensureLocalPortReady(3000); err == nil {
		t.Fatal("ensureLocalPortReady() should fail for a closed port")
	}
}

func TestFindReservedSubdomain(t *testing.T) {
	list := []reservedSubdomain{
		{ID: "1", Subdomain: "first-app"},
		{ID: "2", Subdomain: "myapp"},
	}

	got, ok := findReservedSubdomain(list, " MyApp ")
	if !ok {
		t.Fatal("findReservedSubdomain() should find normalized match")
	}
	if got.ID != "2" {
		t.Fatalf("findReservedSubdomain() id = %q, want %q", got.ID, "2")
	}
}

func TestRunDeleteCommand(t *testing.T) {
	oldBase := authAPIBase
	t.Cleanup(func() { authAPIBase = oldBase })
	oldDo := apiDo
	t.Cleanup(func() { apiDo = oldDo })
	t.Setenv("MEKONG_TOKEN", "mkt_test")
	authAPIBase = "https://api.angkorsearch.dev"

	deleted := false
	apiDo = func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer mkt_test" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer mkt_test")
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/cli/subdomains":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"subdomains":[{"id":"sub_123","subdomain":"myapp","created_at":"2026-03-25T00:00:00Z"}],"count":1,"limit":1}}`)),
				Header:     make(http.Header),
			}, nil
		case r.Method == http.MethodDelete && r.URL.Path == "/api/cli/subdomains/sub_123":
			deleted = true
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	}

	if err := runDeleteCommand([]string{"myapp", "--yes"}); err != nil {
		t.Fatalf("runDeleteCommand() error = %v", err)
	}
	if !deleted {
		t.Fatal("delete endpoint was not called")
	}
}

func TestRunDeleteCommandNotFound(t *testing.T) {
	oldBase := authAPIBase
	t.Cleanup(func() { authAPIBase = oldBase })
	oldDo := apiDo
	t.Cleanup(func() { apiDo = oldDo })
	t.Setenv("MEKONG_TOKEN", "mkt_test")
	authAPIBase = "https://api.angkorsearch.dev"

	apiDo = func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/cli/subdomains" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"subdomains":[],"count":0,"limit":1}}`)),
				Header:     make(http.Header),
			}, nil
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		return nil, nil
	}

	if err := runDeleteCommand([]string{"myapp", "--yes"}); err == nil {
		t.Fatal("runDeleteCommand() should fail when the subdomain is missing")
	}
}

func TestRunSubdomainCommandReservesFromBareName(t *testing.T) {
	oldBase := authAPIBase
	t.Cleanup(func() { authAPIBase = oldBase })
	oldDo := apiDo
	t.Cleanup(func() { apiDo = oldDo })
	t.Setenv("MEKONG_TOKEN", "mkt_test")
	authAPIBase = "https://api.angkorsearch.dev"

	created := false
	apiDo = func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer mkt_test" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer mkt_test")
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/cli/subdomains" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		created = true
		return &http.Response{
			StatusCode: http.StatusCreated,
			Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"id":"sub_123","subdomain":"myapp","created_at":"2026-03-25T00:00:00Z"}}`)),
			Header:     make(http.Header),
		}, nil
	}

	if err := runSubdomainCommand([]string{"myapp"}); err != nil {
		t.Fatalf("runSubdomainCommand() error = %v", err)
	}
	if !created {
		t.Fatal("reserve endpoint was not called")
	}
}

func TestRunSubdomainCommandDeletesWithVerb(t *testing.T) {
	oldBase := authAPIBase
	t.Cleanup(func() { authAPIBase = oldBase })
	oldDo := apiDo
	t.Cleanup(func() { apiDo = oldDo })
	t.Setenv("MEKONG_TOKEN", "mkt_test")
	authAPIBase = "https://api.angkorsearch.dev"

	var calls []string
	apiDo = func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/cli/subdomains":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"subdomains":[{"id":"sub_123","subdomain":"myapp","created_at":"2026-03-25T00:00:00Z"}],"count":1,"limit":1}}`)),
				Header:     make(http.Header),
			}, nil
		case r.Method == http.MethodDelete && r.URL.Path == "/api/cli/subdomains/sub_123":
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	}

	if err := runSubdomainCommand([]string{"delete", "myapp", "--yes"}); err != nil {
		t.Fatalf("runSubdomainCommand() error = %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("call count = %d, want %d (%v)", len(calls), 2, calls)
	}
}
