package expiry

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const EnvName = "MEKONG_EXPIRE"

const monthDuration = 30 * 24 * time.Hour

// Deploy bounds: minimum 30 minutes, maximum 1 year.
const (
	MinDeploy = 30 * time.Minute
	MaxDeploy = 365 * 24 * time.Hour
)

// ValidateDeployExpiry checks that d is within the allowed deploy range.
func ValidateDeployExpiry(d time.Duration) error {
	if d < MinDeploy {
		return fmt.Errorf("too short — minimum is 30 minutes (got %s)\n  Examples: 1h  24h  7d  2w  1mo", Format(d))
	}
	if d > MaxDeploy {
		return fmt.Errorf("too long — maximum is 1 year (got %s)\n  Examples: 7d  1mo  6mo  1year", Format(d))
	}
	return nil
}

var unitSuffixes = []struct {
	suffix string
	unit   time.Duration
}{
	{suffix: "months", unit: monthDuration},
	{suffix: "month", unit: monthDuration},
	{suffix: "mo", unit: monthDuration},
	{suffix: "weeks", unit: 7 * 24 * time.Hour},
	{suffix: "week", unit: 7 * 24 * time.Hour},
	{suffix: "wks", unit: 7 * 24 * time.Hour},
	{suffix: "wk", unit: 7 * 24 * time.Hour},
	{suffix: "w", unit: 7 * 24 * time.Hour},
	{suffix: "days", unit: 24 * time.Hour},
	{suffix: "day", unit: 24 * time.Hour},
	{suffix: "d", unit: 24 * time.Hour},
	{suffix: "hours", unit: time.Hour},
	{suffix: "hour", unit: time.Hour},
	{suffix: "minutes", unit: time.Minute},
	{suffix: "minute", unit: time.Minute},
	{suffix: "min", unit: time.Minute},
}

// Parse converts user input like "48", "48h", "2d", or "1week" into a duration.
func Parse(value string) (time.Duration, error) {
	original := strings.TrimSpace(value)
	if original == "" {
		return 0, fmt.Errorf("expiry cannot be empty")
	}

	normalized := strings.ToLower(original)

	// "1m" is a shorthand for "1mo" (1 month); bare "Nm" falls through to time.ParseDuration as minutes.
	if normalized == "1m" {
		return monthDuration, nil
	}

	if hours, err := strconv.ParseFloat(normalized, 64); err == nil {
		if hours <= 0 {
			return 0, fmt.Errorf("expiry must be greater than zero")
		}
		return time.Duration(hours * float64(time.Hour)), nil
	}

	for _, suffix := range unitSuffixes {
		if !strings.HasSuffix(normalized, suffix.suffix) {
			continue
		}
		number := strings.TrimSpace(strings.TrimSuffix(normalized, suffix.suffix))
		if number == "" {
			return 0, fmt.Errorf("missing value before %q", suffix.suffix)
		}
		n, err := strconv.ParseFloat(number, 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid expiry %q", original)
		}
		return time.Duration(n * float64(suffix.unit)), nil
	}

	d, err := time.ParseDuration(normalized)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid expiry %q (use 1d, 1w, 1mo — or 48h, 2d, 2w)", original)
	}
	return d, nil
}

// Format returns a compact human-friendly representation like "1mo", "1w", "2d", or "48h".
func Format(d time.Duration) string {
	switch {
	case d%monthDuration == 0:
		return fmt.Sprintf("%dmo", d/monthDuration)
	case d%(7*24*time.Hour) == 0:
		return fmt.Sprintf("%dw", d/(7*24*time.Hour))
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return d.String()
	}
}
