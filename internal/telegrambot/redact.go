package telegrambot

import "regexp"

type redactRule struct {
	re          *regexp.Regexp
	replacement string
}

// redactRules strip likely secrets from log lines before sending to Telegram.
var redactRules = []redactRule{
	{regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)\S+`), `${1}` + redactedLabel},
	{regexp.MustCompile(`(?i)(mkt_[A-Za-z0-9_\-]+)`), redactedLabel},
	{regexp.MustCompile(`(?i)(password\s*[=:]\s*)\S+`), `${1}` + redactedLabel},
	{regexp.MustCompile(`(?i)(secret\s*[=:]\s*)\S+`), `${1}` + redactedLabel},
	{regexp.MustCompile(`(?i)(token\s*[=:]\s*)\S+`), `${1}` + redactedLabel},
	{regexp.MustCompile(`(?i)(api[_-]?key\s*[=:]\s*)\S+`), `${1}` + redactedLabel},
	{regexp.MustCompile(`(?i)Set-Cookie:[^\r\n]+`), redactedLabel},
	{regexp.MustCompile(`(?i)Cookie:[^\r\n]+`), redactedLabel},
	// provider-specific
	{regexp.MustCompile(`(?i)(gh[pousr]_[A-Za-z0-9]+)`), redactedLabel}, // GitHub tokens
	{regexp.MustCompile(`(?i)(sk_live_[A-Za-z0-9]+)`), redactedLabel},   // Stripe live key
	{regexp.MustCompile(`(?i)(re_[A-Za-z0-9]+)`), redactedLabel},        // Resend key
	{regexp.MustCompile(`(?i)(smtp[_-]?pass\s*[=:]\s*)\S+`), `${1}` + redactedLabel},
}

const redactedLabel = "[REDACTED]"

// Redact replaces known secret patterns with [REDACTED].
func Redact(line string) string {
	for _, rule := range redactRules {
		line = rule.re.ReplaceAllString(line, rule.replacement)
	}
	return line
}

// RedactLines applies Redact to each line.
func RedactLines(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = Redact(l)
	}
	return out
}
