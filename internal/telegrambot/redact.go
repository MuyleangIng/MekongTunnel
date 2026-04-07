package telegrambot

import "regexp"

// redactPatterns strips likely secrets from log lines before sending to Telegram.
var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(Authorization:\s*Bearer\s+)\S+`),
	regexp.MustCompile(`(?i)(mkt_[A-Za-z0-9_\-]+)`),
	regexp.MustCompile(`(?i)(password\s*[=:]\s*)\S+`),
	regexp.MustCompile(`(?i)(secret\s*[=:]\s*)\S+`),
	regexp.MustCompile(`(?i)(token\s*[=:]\s*)\S+`),
	regexp.MustCompile(`(?i)(api[_-]?key\s*[=:]\s*)\S+`),
	regexp.MustCompile(`(?i)(Set-Cookie:[^\r\n]+)`),
	regexp.MustCompile(`(?i)(Cookie:[^\r\n]+)`),
	// provider-specific
	regexp.MustCompile(`(?i)(gh[pousr]_[A-Za-z0-9]+)`),          // GitHub tokens
	regexp.MustCompile(`(?i)(sk_live_[A-Za-z0-9]+)`),             // Stripe live key
	regexp.MustCompile(`(?i)(re_[A-Za-z0-9]+)`),                  // Resend key
	regexp.MustCompile(`(?i)(smtp[_-]?pass\s*[=:]\s*)\S+`),
}

const redactedLabel = "[REDACTED]"

// Redact replaces known secret patterns with [REDACTED].
func Redact(line string) string {
	for _, re := range redactPatterns {
		if re.NumSubexp() > 0 {
			line = re.ReplaceAllString(line, "${1}"+redactedLabel)
		} else {
			line = re.ReplaceAllString(line, redactedLabel)
		}
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
