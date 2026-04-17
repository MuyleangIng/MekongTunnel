package expiry

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  time.Duration
	}{
		{name: "bare hours", input: "48", want: 48 * time.Hour},
		{name: "hours suffix", input: "48h", want: 48 * time.Hour},
		{name: "days short", input: "2d", want: 48 * time.Hour},
		{name: "days long", input: "2day", want: 48 * time.Hour},
		{name: "days plural", input: "2days", want: 48 * time.Hour},
		{name: "7 days", input: "7d", want: 7 * 24 * time.Hour},
		{name: "weeks short", input: "1w", want: 7 * 24 * time.Hour},
		{name: "weeks long", input: "1week", want: 7 * 24 * time.Hour},
		{name: "2 weeks", input: "2w", want: 14 * 24 * time.Hour},
		{name: "1 day", input: "1d", want: 24 * time.Hour},
		{name: "1mo", input: "1mo", want: 30 * 24 * time.Hour},
		{name: "1m shorthand for month", input: "1m", want: 30 * 24 * time.Hour},
		{name: "minutes 30m go fallback", input: "30m", want: 30 * time.Minute},
		{name: "minutes min suffix", input: "30min", want: 30 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("Parse(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []string{"", "0", "-1h", "banana", "week", "1mdadasd", "abc123"}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := Parse(input); err == nil {
				t.Fatalf("Parse(%q) should fail", input)
			}
		})
	}
}

func TestValidateDeployExpiry(t *testing.T) {
	ok := []time.Duration{30 * time.Minute, time.Hour, 7 * 24 * time.Hour, MaxDeploy}
	for _, d := range ok {
		if err := ValidateDeployExpiry(d); err != nil {
			t.Fatalf("ValidateDeployExpiry(%v) should pass: %v", d, err)
		}
	}
	bad := []time.Duration{0, time.Minute, 29 * time.Minute, MaxDeploy + time.Hour}
	for _, d := range bad {
		if err := ValidateDeployExpiry(d); err == nil {
			t.Fatalf("ValidateDeployExpiry(%v) should fail", d)
		}
	}
}

func TestFormat(t *testing.T) {
	tests := []struct {
		input time.Duration
		want  string
	}{
		{input: 7 * 24 * time.Hour, want: "1w"},
		{input: 48 * time.Hour, want: "2d"},
		{input: 6 * time.Hour, want: "6h"},
		{input: 45 * time.Minute, want: "45m"},
	}

	for _, tt := range tests {
		if got := Format(tt.input); got != tt.want {
			t.Fatalf("Format(%v) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
