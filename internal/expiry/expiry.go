package expiry

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const EnvName = "MEKONG_EXPIRE"

var unitSuffixes = []struct {
	suffix string
	unit   time.Duration
}{
	{suffix: "weeks", unit: 7 * 24 * time.Hour},
	{suffix: "week", unit: 7 * 24 * time.Hour},
	{suffix: "wks", unit: 7 * 24 * time.Hour},
	{suffix: "wk", unit: 7 * 24 * time.Hour},
	{suffix: "w", unit: 7 * 24 * time.Hour},
	{suffix: "days", unit: 24 * time.Hour},
	{suffix: "day", unit: 24 * time.Hour},
	{suffix: "d", unit: 24 * time.Hour},
}

// Parse converts user input like "48", "48h", "2d", or "1week" into a duration.
func Parse(value string) (time.Duration, error) {
	original := strings.TrimSpace(value)
	if original == "" {
		return 0, fmt.Errorf("expiry cannot be empty")
	}

	normalized := strings.ToLower(original)

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
		return 0, fmt.Errorf("invalid expiry %q (use 30m, 48h, 2d, 2day, or 1w)", original)
	}
	return d, nil
}

// Format returns a compact human-friendly representation like "1w", "2d", or "48h".
func Format(d time.Duration) string {
	switch {
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
