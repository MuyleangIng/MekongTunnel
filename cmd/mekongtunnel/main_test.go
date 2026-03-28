package main

import "testing"

func TestDeriveAPIBaseURL(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   string
	}{
		{name: "proxy domain", domain: "proxy.angkorsearch.dev", want: "https://api.angkorsearch.dev"},
		{name: "plain host", domain: "example.com", want: "https://api.example.com"},
		{name: "api host stays api", domain: "api.example.com", want: "https://api.example.com"},
		{name: "empty", domain: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deriveAPIBaseURL(tt.domain); got != tt.want {
				t.Fatalf("deriveAPIBaseURL(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}
