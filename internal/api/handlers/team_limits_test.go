package handlers

import "testing"

func TestPlanSubdomainLimit(t *testing.T) {
	tests := []struct {
		plan string
		want int
	}{
		{plan: "student", want: 1},
		{plan: "pro", want: 3},
		{plan: "org", want: -1},
		{plan: "free", want: 0},
	}

	for _, tt := range tests {
		if got := planSubdomainLimit(tt.plan); got != tt.want {
			t.Fatalf("planSubdomainLimit(%q) = %d, want %d", tt.plan, got, tt.want)
		}
	}
}

func TestTeamRouteLimit(t *testing.T) {
	tests := []struct {
		plan string
		want int
	}{
		{plan: "student", want: 3},
		{plan: "pro", want: 10},
		{plan: "org", want: -1},
		{plan: "free", want: 0},
	}

	for _, tt := range tests {
		if got := teamRouteLimit(tt.plan); got != tt.want {
			t.Fatalf("teamRouteLimit(%q) = %d, want %d", tt.plan, got, tt.want)
		}
	}
}
