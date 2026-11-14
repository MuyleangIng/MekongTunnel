package handlers

import (
	"strings"
	"testing"
)

func TestValidateSubdomainName(t *testing.T) {
	ok := []string{"myapp", "abc", "my-app-2", strings.Repeat("a", 63)}
	bad := []string{"", "ab", strings.Repeat("x", 64), strings.Repeat("x", 200), "-app", "app-", "my_app", "My.App"}
	for _, n := range ok {
		if msg := validateSubdomainName(n); msg != "" {
			t.Errorf("%q should be valid, got %q", n, msg)
		}
	}
	for _, n := range bad {
		if validateSubdomainName(n) == "" {
			t.Errorf("%q should be rejected", n)
		}
	}
}
