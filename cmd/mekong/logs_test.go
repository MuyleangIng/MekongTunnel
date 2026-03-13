package main

import "testing"

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
