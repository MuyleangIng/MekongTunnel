package main

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestParseReleaseChecksum(t *testing.T) {
	data := strings.NewReader("" +
		"aaa111  mekong-darwin-amd64\n" +
		"bbb222  mekong-darwin-arm64\n" +
		"ccc333  mekong-linux-amd64\n")

	got, err := parseReleaseChecksum(data, "mekong-darwin-arm64")
	if err != nil {
		t.Fatalf("parseReleaseChecksum() error = %v", err)
	}
	if got != "bbb222" {
		t.Fatalf("parseReleaseChecksum() = %q, want %q", got, "bbb222")
	}
}

func TestParseReleaseChecksum_MissingAsset(t *testing.T) {
	_, err := parseReleaseChecksum(strings.NewReader("aaa111  mekong-darwin-amd64\n"), "mekong-linux-amd64")
	if err == nil {
		t.Fatal("parseReleaseChecksum() should fail for missing asset")
	}
}

func TestShouldRetryUpdateDownload(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "timeout", err: &net.DNSError{IsTimeout: true}, want: true},
		{name: "tls mac", err: errors.New("local error: tls: bad record MAC"), want: true},
		{name: "checksum mismatch", err: errors.New("checksum mismatch: got aaa, want bbb"), want: true},
		{name: "http 404", err: errors.New("HTTP 404"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldRetryUpdateDownload(tt.err); got != tt.want {
				t.Fatalf("shouldRetryUpdateDownload() = %v, want %v", got, tt.want)
			}
		})
	}
}
