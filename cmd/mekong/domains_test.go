package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNormalizeCustomDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "plain", input: "app.example.com", want: "app.example.com"},
		{name: "trim and lower", input: "  HTTPS://App.Example.com/  ", want: "app.example.com"},
		{name: "reject empty", input: "  ", wantErr: true},
		{name: "reject no dot", input: "localhost", wantErr: true},
		{name: "reject empty label", input: "ttt..mekongtunnel.dev", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeCustomDomain(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeCustomDomain() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("normalizeCustomDomain() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindCustomDomain(t *testing.T) {
	list := []customDomainRecord{
		{ID: "1", Domain: "first.example.com"},
		{ID: "2", Domain: "app.example.com"},
	}

	got, ok := findCustomDomain(list, " HTTPS://App.Example.com/ ")
	if !ok {
		t.Fatal("findCustomDomain() should find normalized match")
	}
	if got.ID != "2" {
		t.Fatalf("findCustomDomain() id = %q, want %q", got.ID, "2")
	}
}

func TestRunDomainAddCommand(t *testing.T) {
	oldBase := authAPIBase
	t.Cleanup(func() { authAPIBase = oldBase })
	oldDo := apiDo
	t.Cleanup(func() { apiDo = oldDo })
	t.Setenv("MEKONG_TOKEN", "mkt_test")
	authAPIBase = "https://api.angkorsearch.dev"

	apiDo = func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer mkt_test" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer mkt_test")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/cli/domains":
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"id":"dom_123","domain":"app.example.com","status":"pending","verification_token":"abc123","created_at":"2026-03-25T00:00:00Z","cname_target":"proxy.angkorsearch.dev","txt_name":"_mekongtunnel-verify.app.example.com","txt_value":"mekong-verify=abc123"}}`)),
				Header:     make(http.Header),
			}, nil
		case r.Method == http.MethodPost && r.URL.Path == "/api/cli/domains/dom_123/verify":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"verified":false,"status":"failed","cname_ok":false,"txt_ok":false,"address_ok":false,"cname_target":"proxy.angkorsearch.dev","txt_name":"_mekongtunnel-verify.app.example.com","txt_value":"mekong-verify=abc123","https_ok":false,"ready":false,"readiness_status":"pending_dns","message":"DNS verification failed."}}`)),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	}

	if err := runDomainAddCommand([]string{"app.example.com"}); err != nil {
		t.Fatalf("runDomainAddCommand() error = %v", err)
	}
}

func TestRunDomainTargetCommand(t *testing.T) {
	oldBase := authAPIBase
	t.Cleanup(func() { authAPIBase = oldBase })
	oldDo := apiDo
	t.Cleanup(func() { apiDo = oldDo })
	t.Setenv("MEKONG_TOKEN", "mkt_test")
	authAPIBase = "https://api.angkorsearch.dev"

	apiDo = func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != "Bearer mkt_test" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer mkt_test")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/cli/domains":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":[{"id":"dom_123","domain":"app.example.com","status":"verified","verification_token":"abc123","created_at":"2026-03-25T00:00:00Z","cname_target":"proxy.angkorsearch.dev","txt_name":"_mekongtunnel-verify.app.example.com","txt_value":"mekong-verify=abc123"}]}`)),
				Header:     make(http.Header),
			}, nil
		case r.Method == http.MethodPatch && r.URL.Path == "/api/cli/domains/dom_123/target":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"ok":true}}`)),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	}

	if err := runDomainTargetCommand([]string{"app.example.com", "myapp"}); err != nil {
		t.Fatalf("runDomainTargetCommand() error = %v", err)
	}
}

func TestRunDomainConnectCommand(t *testing.T) {
	oldBase := authAPIBase
	t.Cleanup(func() { authAPIBase = oldBase })
	oldDo := apiDo
	t.Cleanup(func() { apiDo = oldDo })
	t.Setenv("MEKONG_TOKEN", "mkt_test")
	authAPIBase = "https://api.angkorsearch.dev"

	var calls []string
	verifyCalls := 0
	apiDo = func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if got := r.Header.Get("Authorization"); got != "Bearer mkt_test" {
			t.Fatalf("Authorization = %q, want %q", got, "Bearer mkt_test")
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/cli/domains":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":[]}`)),
				Header:     make(http.Header),
			}, nil
		case r.Method == http.MethodPost && r.URL.Path == "/api/cli/domains":
			return &http.Response{
				StatusCode: http.StatusCreated,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"id":"dom_123","domain":"app.example.com","status":"pending","verification_token":"abc123","created_at":"2026-03-25T00:00:00Z","cname_target":"proxy.angkorsearch.dev","txt_name":"_mekongtunnel-verify.app.example.com","txt_value":"mekong-verify=abc123"}}`)),
				Header:     make(http.Header),
			}, nil
		case r.Method == http.MethodPatch && r.URL.Path == "/api/cli/domains/dom_123/target":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"ok":true}}`)),
				Header:     make(http.Header),
			}, nil
		case r.Method == http.MethodPost && r.URL.Path == "/api/cli/domains/dom_123/verify":
			verifyCalls++
			if verifyCalls == 1 {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"verified":false,"status":"failed","cname_ok":false,"txt_ok":false,"address_ok":false,"cname_target":"proxy.angkorsearch.dev","txt_name":"_mekongtunnel-verify.app.example.com","txt_value":"mekong-verify=abc123","https_ok":false,"ready":false,"readiness_status":"pending_dns","message":"DNS verification failed."}}`)),
					Header:     make(http.Header),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":{"verified":true,"status":"verified","cname_ok":true,"txt_ok":false,"address_ok":false,"cname_target":"proxy.angkorsearch.dev","txt_name":"_mekongtunnel-verify.app.example.com","txt_value":"mekong-verify=abc123","https_ok":true,"ready":true,"readiness_status":"ready","message":"Domain verified via CNAME record and HTTPS is ready."}}`)),
				Header:     make(http.Header),
			}, nil
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			return nil, nil
		}
	}

	if err := runDomainConnectCommand([]string{"app.example.com", "myapp"}); err != nil {
		t.Fatalf("runDomainConnectCommand() error = %v", err)
	}

	if len(calls) != 5 {
		t.Fatalf("call count = %d, want %d (%v)", len(calls), 5, calls)
	}
}

func TestDoctorTXTCheckSkipsWhenCNAMEAlreadyValid(t *testing.T) {
	record := customDomainRecord{
		Domain:      "app.example.com",
		CNAMETarget: "proxy.angkorsearch.dev",
		TXTName:     "_mekongtunnel-verify.app.example.com",
		TXTValue:    "mekong-verify=abc123",
	}

	got := doctorTXTCheck(true, record, nil, errors.New("lookup failed"))
	if !got.skipped {
		t.Fatalf("doctorTXTCheck() skipped = %v, want true", got.skipped)
	}
	if got.ok {
		t.Fatalf("doctorTXTCheck() ok = %v, want false", got.ok)
	}
	if !strings.Contains(got.detail, "optional") {
		t.Fatalf("doctorTXTCheck() detail = %q, want optional guidance", got.detail)
	}
}

func TestDoctorTXTCheckFailsWhenCNAMEMissingAndTXTMissing(t *testing.T) {
	record := customDomainRecord{
		Domain:      "app.example.com",
		CNAMETarget: "proxy.angkorsearch.dev",
		TXTName:     "_mekongtunnel-verify.app.example.com",
		TXTValue:    "mekong-verify=abc123",
	}

	got := doctorTXTCheck(false, record, nil, errors.New("no such host"))
	if got.skipped {
		t.Fatalf("doctorTXTCheck() skipped = %v, want false", got.skipped)
	}
	if got.ok {
		t.Fatalf("doctorTXTCheck() ok = %v, want false", got.ok)
	}
	if got.detail != "no such host" {
		t.Fatalf("doctorTXTCheck() detail = %q, want %q", got.detail, "no such host")
	}
}

func TestDoctorTXTCheckSkipsWhenAddressAlreadyValid(t *testing.T) {
	record := customDomainRecord{
		Domain:      "app.example.com",
		CNAMETarget: "proxy.angkorsearch.dev",
		TXTName:     "_mekongtunnel-verify.app.example.com",
		TXTValue:    "mekong-verify=abc123",
	}

	got := doctorTXTCheck(true, record, nil, errors.New("lookup failed"))
	if !got.skipped {
		t.Fatalf("doctorTXTCheck() skipped = %v, want true", got.skipped)
	}
	if !strings.Contains(got.detail, "optional") {
		t.Fatalf("doctorTXTCheck() detail = %q, want optional guidance", got.detail)
	}
}

func TestDoctorCNAMECheckSkipsApexDomains(t *testing.T) {
	got, ok := doctorCNAMECheck(customDomainRecord{
		Domain:      "example.com",
		CNAMETarget: "proxy.angkorsearch.dev",
	}, "", errors.New("no such host"))

	if ok {
		t.Fatalf("doctorCNAMECheck() ok = %v, want false", ok)
	}
	if !got.skipped {
		t.Fatalf("doctorCNAMECheck() skipped = %v, want true", got.skipped)
	}
	if !strings.Contains(got.detail, "root domains") {
		t.Fatalf("doctorCNAMECheck() detail = %q, want root-domain guidance", got.detail)
	}
}

func TestRunDomainDeleteCommandShowsCleanupNotes(t *testing.T) {
	oldBase := authAPIBase
	t.Cleanup(func() { authAPIBase = oldBase })
	oldDo := apiDo
	t.Cleanup(func() { apiDo = oldDo })
	t.Setenv("MEKONG_TOKEN", "mkt_test")
	authAPIBase = "https://api.angkorsearch.dev"

	apiDo = func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/cli/domains":
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"ok":true,"data":[{"id":"dom_123","domain":"app.example.com","status":"verified","verification_token":"abc123","target_subdomain":"myapp","created_at":"2026-03-25T00:00:00Z","cname_target":"proxy.angkorsearch.dev","txt_name":"_mekongtunnel-verify.app.example.com","txt_value":"mekong-verify=abc123"}]}`)),
				Header:     make(http.Header),
			}, nil
		case r.Method == http.MethodDelete && r.URL.Path == "/api/cli/domains/dom_123":
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

	out := captureStdout(t, func() {
		if err := runDomainDeleteCommand([]string{"app.example.com", "--yes"}); err != nil {
			t.Fatalf("runDomainDeleteCommand() error = %v", err)
		}
	})

	if !strings.Contains(out, "not changed at your DNS provider") {
		t.Fatalf("output = %q, want DNS cleanup note", out)
	}
	if !strings.Contains(out, "shared or existing certificate may still validate") {
		t.Fatalf("output = %q, want HTTPS cleanup note", out)
	}
}
