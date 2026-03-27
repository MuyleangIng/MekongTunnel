package main

import "testing"

func TestResolveTunnelSessionToken(t *testing.T) {
	tests := []struct {
		name               string
		apiToken           string
		requestedSubdomain string
		want               string
	}{
		{
			name:               "no reserved subdomain keeps random tunnel",
			apiToken:           "mkt_saved",
			requestedSubdomain: "",
			want:               "",
		},
		{
			name:               "reserved subdomain forwards token",
			apiToken:           "mkt_saved",
			requestedSubdomain: "myapp",
			want:               "mkt_saved",
		},
		{
			name:               "trims token and subdomain",
			apiToken:           "  mkt_saved  ",
			requestedSubdomain: " myapp ",
			want:               "mkt_saved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveTunnelSessionToken(tt.apiToken, tt.requestedSubdomain)
			if got != tt.want {
				t.Fatalf("resolveTunnelSessionToken() = %q, want %q", got, tt.want)
			}
		})
	}
}
