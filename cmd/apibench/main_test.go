package main

import (
	"testing"
	"time"
)

func TestPercentile(t *testing.T) {
	samples := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		30 * time.Millisecond,
		40 * time.Millisecond,
		50 * time.Millisecond,
	}

	if got := percentile(samples, 50); got != 30*time.Millisecond {
		t.Fatalf("p50 = %s, want 30ms", got)
	}
	if got := percentile(samples, 95); got != 40*time.Millisecond {
		t.Fatalf("p95 = %s, want 40ms", got)
	}
}
