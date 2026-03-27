package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadProjectConfigFromDirMissing(t *testing.T) {
	cfg, err := loadProjectConfigFromDir(t.TempDir())
	if err != nil {
		t.Fatalf("loadProjectConfigFromDir() error = %v", err)
	}
	if cfg != nil {
		t.Fatalf("loadProjectConfigFromDir() = %#v, want nil", cfg)
	}
}

func TestNormalizeUpstreamHost(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "plain host", input: "myapp.test", want: "myapp.test"},
		{name: "trim scheme", input: " https://MyApp.test/ ", want: "myapp.test"},
		{name: "empty", input: "   ", want: ""},
		{name: "reject path", input: "myapp.test/admin", wantErr: true},
		{name: "reject port", input: "myapp.test:80", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeUpstreamHost(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeUpstreamHost() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("normalizeUpstreamHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectProjectLaravel(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "artisan"), []byte("#!/usr/bin/env php\n"), 0644); err != nil {
		t.Fatalf("write artisan: %v", err)
	}

	oldDial := localDial
	t.Cleanup(func() { localDial = oldDial })
	localDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, os.ErrNotExist
	}

	project, err := detectProject(dir)
	if err != nil {
		t.Fatalf("detectProject() error = %v", err)
	}
	if project.Stack != "laravel" {
		t.Fatalf("stack = %q, want %q", project.Stack, "laravel")
	}
	if project.Port != 8000 {
		t.Fatalf("port = %d, want %d", project.Port, 8000)
	}
	if !strings.Contains(project.Start, "php artisan serve") {
		t.Fatalf("start = %q, want php artisan serve", project.Start)
	}
}

func TestResolvePortsUsesProjectConfig(t *testing.T) {
	ports, err := resolvePorts(0, nil, &projectConfig{Port: 8080})
	if err != nil {
		t.Fatalf("resolvePorts() error = %v", err)
	}
	if len(ports) != 1 || ports[0] != 8080 {
		t.Fatalf("ports = %#v, want [8080]", ports)
	}
}

func TestRunInitCommandWritesProjectConfig(t *testing.T) {
	dir := t.TempDir()
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer func() { _ = os.Chdir(oldWD) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "artisan"), []byte("#!/usr/bin/env php\n"), 0644); err != nil {
		t.Fatalf("write artisan: %v", err)
	}

	oldDial := localDial
	t.Cleanup(func() { localDial = oldDial })
	localDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		return nil, os.ErrNotExist
	}

	if err := runInitCommand([]string{"--upstream-host", "myapp.test"}); err != nil {
		t.Fatalf("runInitCommand() error = %v", err)
	}

	cfg, err := loadProjectConfigFromDir(dir)
	if err != nil {
		t.Fatalf("loadProjectConfigFromDir() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("expected config file to be written")
	}
	if cfg.Port != 8000 {
		t.Fatalf("cfg.Port = %d, want %d", cfg.Port, 8000)
	}
	if cfg.UpstreamHost != "myapp.test" {
		t.Fatalf("cfg.UpstreamHost = %q, want %q", cfg.UpstreamHost, "myapp.test")
	}
}
