package telegrambot

import (
	"fmt"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

const maxMessageLen = 4000 // Telegram limit is 4096; leave headroom

// FormatUser formats a user's account summary.
func FormatUser(u *models.User) string {
	verified := "✓ verified"
	if !u.EmailVerified {
		verified = "⚠ not verified"
	}
	return fmt.Sprintf(
		"*Your Mekong Account*\n\nEmail: %s (%s)\nPlan: %s\nAccount: %s",
		escMD(u.Email), verified,
		strings.ToUpper(u.Plan),
		strings.ToUpper(u.AccountType),
	)
}

// FormatTunnels formats a slice of tunnel records.
func FormatTunnels(tunnels []*models.Tunnel) string {
	if len(tunnels) == 0 {
		return "No active tunnels found."
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("*Active Tunnels* (%d)\n\n", len(tunnels)))
	for _, t := range tunnels {
		status := "🟢"
		if t.Status != "active" {
			status = "🔴"
		}
		b.WriteString(fmt.Sprintf("%s `%s`\nPort: %d | Requests: %d\n\n",
			status, escMD(t.Subdomain), t.LocalPort, t.TotalRequests))
	}
	return truncate(b.String())
}

// FormatSubdomains formats reserved subdomain records.
func FormatSubdomains(subs []*models.ReservedSubdomain) string {
	if len(subs) == 0 {
		return "No reserved subdomains found."
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("*Reserved Subdomains* (%d)\n\n", len(subs)))
	for _, s := range subs {
		b.WriteString(fmt.Sprintf("• `%s`\n", escMD(s.Subdomain)))
	}
	return truncate(b.String())
}

// FormatDomains formats custom domain records.
func FormatDomains(domains []*models.CustomDomain) string {
	if len(domains) == 0 {
		return "No custom domains found."
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("*Custom Domains* (%d)\n\n", len(domains)))
	for _, d := range domains {
		icon := domainStatusIcon(d.Status)
		b.WriteString(fmt.Sprintf("%s `%s` — %s\n", icon, escMD(d.Domain), d.Status))
	}
	return truncate(b.String())
}

// FormatDomain formats one custom domain in detail.
func FormatDomain(d *models.CustomDomain) string {
	icon := domainStatusIcon(d.Status)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("*Domain: %s*\n\n", escMD(d.Domain)))
	b.WriteString(fmt.Sprintf("Status: %s %s\n", icon, d.Status))
	if d.TargetSubdomain != nil && *d.TargetSubdomain != "" {
		b.WriteString(fmt.Sprintf("Target: `%s`\n", escMD(*d.TargetSubdomain)))
	}
	if d.VerifiedAt != nil {
		b.WriteString(fmt.Sprintf("Verified: %s\n", d.VerifiedAt.Format(time.RFC1123)))
	}
	b.WriteString(fmt.Sprintf("Added: %s\n", d.CreatedAt.Format(time.RFC1123)))
	return b.String()
}

// FormatLogs formats recent log lines for Telegram.
func FormatLogs(lines []string, label string) string {
	redacted := RedactLines(lines)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("*Recent logs: %s*\n\n```\n", escMD(label)))
	for _, l := range redacted {
		b.WriteString(l + "\n")
	}
	b.WriteString("```")
	return truncate(b.String())
}

// FormatLogsPlain formats recent log lines without Markdown parsing.
func FormatLogsPlain(lines []string, label string) string {
	redacted := RedactLines(lines)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Recent logs: %s\n\n", label))
	for _, l := range redacted {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return strings.TrimRight(truncate(b.String()), "\n")
}

func domainStatusIcon(status string) string {
	switch status {
	case "verified", "active":
		return "✅"
	case "pending":
		return "⏳"
	case "failed":
		return "❌"
	default:
		return "❓"
	}
}

// escMD escapes Markdown special chars for Telegram Markdown mode.
func escMD(s string) string {
	r := strings.NewReplacer(
		"_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]",
		"`", "\\`",
	)
	return r.Replace(s)
}

func truncate(s string) string {
	if len(s) <= maxMessageLen {
		return s
	}
	return s[:maxMessageLen] + "\n…(truncated)"
}
