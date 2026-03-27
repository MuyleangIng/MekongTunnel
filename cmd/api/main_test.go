package main

import "testing"

func TestNormalizePlan(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "free", in: "free", want: "free"},
		{name: "student", in: "student", want: "student"},
		{name: "pro", in: "PRO", want: "pro"},
		{name: "org default", in: "", want: "org"},
		{name: "unknown defaults to org", in: "enterprise", want: "org"},
	}

	for _, tt := range tests {
		if got := normalizePlan(tt.in); got != tt.want {
			t.Fatalf("%s: got %q want %q", tt.name, got, tt.want)
		}
	}
}
