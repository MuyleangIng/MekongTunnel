package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLogsArgs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantFollow bool
		wantPort   int
		wantErr    bool
	}{
		{name: "no args", args: nil},
		{name: "follow short", args: []string{"-f"}, wantFollow: true},
		{name: "follow long", args: []string{"--follow"}, wantFollow: true},
		{name: "port only", args: []string{"3000"}, wantPort: 3000},
		{name: "follow then port", args: []string{"-f", "3000"}, wantFollow: true, wantPort: 3000},
		{name: "port then follow", args: []string{"3000", "-f"}, wantFollow: true, wantPort: 3000},
		{name: "invalid flag", args: []string{"--bad"}, wantErr: true},
		{name: "invalid port", args: []string{"abc"}, wantErr: true},
		{name: "too many args", args: []string{"3000", "4000"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFollow, gotPort, err := parseLogsArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseLogsArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if gotFollow != tt.wantFollow {
				t.Fatalf("parseLogsArgs() follow = %v, want %v", gotFollow, tt.wantFollow)
			}
			if gotPort != tt.wantPort {
				t.Fatalf("parseLogsArgs() port = %d, want %d", gotPort, tt.wantPort)
			}
		})
	}
}

func TestLogLineMatchesPort(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		portFilter int
		want       bool
	}{
		{name: "no filter", line: "plain line", portFilter: 0, want: true},
		{name: "prefixed match", line: "[:3000] connected", portFilter: 3000, want: true},
		{name: "prefixed mismatch", line: "[:4000] connected", portFilter: 3000, want: false},
		{name: "ansi prefixed match", line: "\x1b[38;5;245m  ↺  [:3000] Reconnecting\x1b[0m", portFilter: 3000, want: true},
		{name: "global line", line: "Tunnel is live!", portFilter: 3000, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := logLineMatchesPort(tt.line, tt.portFilter); got != tt.want {
				t.Fatalf("logLineMatchesPort() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractServerErrorMessage(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{
			name:   "plain error line",
			output: "\r\n  ERROR: rate limit exceeded: max 3 tunnels per IP\r\n\r\n",
			want:   "rate limit exceeded: max 3 tunnels per IP",
		},
		{
			name:   "ansi wrapped error line",
			output: "\x1b[1;31m  ERROR: IP 127.0.0.1 is temporarily blocked. Try again in 15m\x1b[0m\n",
			want:   "IP 127.0.0.1 is temporarily blocked. Try again in 15m",
		},
		{
			name:   "no error line",
			output: "welcome\n",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractServerErrorMessage(tt.output); got != tt.want {
				t.Fatalf("extractServerErrorMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseStopArgs(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantPort int
		wantAll  bool
		wantErr  bool
	}{
		{name: "no args", args: nil},
		{name: "specific port", args: []string{"5500"}, wantPort: 5500},
		{name: "all", args: []string{"--all"}, wantAll: true},
		{name: "bad flag", args: []string{"--bad"}, wantErr: true},
		{name: "bad port", args: []string{"abc"}, wantErr: true},
		{name: "mixed port and all", args: []string{"5500", "--all"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPort, gotAll, err := parseStopArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseStopArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if gotPort != tt.wantPort {
				t.Fatalf("parseStopArgs() port = %d, want %d", gotPort, tt.wantPort)
			}
			if gotAll != tt.wantAll {
				t.Fatalf("parseStopArgs() all = %v, want %v", gotAll, tt.wantAll)
			}
		})
	}
}

func TestPruneLogFile(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	logDir := filepath.Join(tmpHome, ".mekong")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	path := filepath.Join(logDir, "mekong.log")
	content := "global line\n[:3000] first line\n[:4000] keep me\n[:3000] second line\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if err := pruneLogFile(3000, false); err != nil {
		t.Fatalf("pruneLogFile() error = %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	want := "global line\n[:4000] keep me\n"
	if string(got) != want {
		t.Fatalf("pruneLogFile() = %q, want %q", string(got), want)
	}
}

func TestRunStopStaleCleansPortLogs(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	logDir := filepath.Join(tmpHome, ".mekong")
	tunnelDir := filepath.Join(logDir, "tunnels")
	if err := os.MkdirAll(tunnelDir, 0755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}

	logPath := filepath.Join(logDir, "mekong.log")
	if err := os.WriteFile(logPath, []byte("[:3000] old line\n[:4000] keep line\n"), 0644); err != nil {
		t.Fatalf("WriteFile(log) error = %v", err)
	}

	state := []byte("{\n  \"pid\": 999999,\n  \"url\": \"https://example.test\",\n  \"local_port\": 3000,\n  \"started_at\": \"2026-03-13T00:00:00Z\",\n  \"expires_at\": \"2026-03-20T00:00:00Z\"\n}\n")
	if err := os.WriteFile(filepath.Join(tunnelDir, "3000.json"), state, 0600); err != nil {
		t.Fatalf("WriteFile(state) error = %v", err)
	}

	if err := runStop(3000, false); err != nil {
		t.Fatalf("runStop() error = %v", err)
	}

	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != "[:4000] keep line\n" {
		t.Fatalf("runStop() log = %q, want %q", string(got), "[:4000] keep line\n")
	}
}
