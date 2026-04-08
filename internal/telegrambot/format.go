package telegrambot

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

const maxMessageLen = 4000 // Telegram limit is 4096; leave headroom

const shortTimeLayout = "02 Jan 2006 15:04 MST"

func FormatStartIntro(firstName string) string {
	name := strings.TrimSpace(firstName)
	if name == "" {
		name = "there"
	}
	return fmt.Sprintf(
		"Hi %s!\n\nLink your Mekong account to check active tunnels, recent logs, reserved subdomains, and domain status.\n\nUse /link to begin.",
		name,
	)
}

func FormatWelcomeBack() string {
	return "✅ Your Mekong account is linked.\n\nUse /services to check active tunnels or /help to see all commands."
}

func FormatHelp() string {
	return truncate(`*Mekong Tunnel Bot*

Quick checks from Telegram:

` + "`/link`" + ` connect your Mekong account
` + "`/me`" + ` account summary
` + "`/services`" + ` active tunnels
` + "`/logs <id>`" + ` recent logs
` + "`/subdomains`" + ` reserved subdomains
` + "`/domains`" + ` custom domains
` + "`/domain <host>`" + ` inspect one domain
` + "`/unlink`" + ` disconnect Telegram
` + "`/help`" + ` show this message`)
}

func FormatLinkRequest(approveURL string) string {
	return fmt.Sprintf(
		"Open the link below to connect your Mekong account:\n\n%s\n\nThis link expires in 10 minutes.",
		approveURL,
	)
}

func FormatAlreadyLinked() string {
	return "✅ Your Telegram account is already linked.\n\nUse /unlink first if you want to connect a different Mekong account."
}

func FormatNotLinked() string {
	return "Your Telegram account is not linked to a Mekong account.\n\nUse /link to connect your account."
}

func FormatSuspended() string {
	return "Your Mekong account is suspended.\n\nManage your account in the dashboard to restore Telegram access."
}

func FormatLinkApproved(display string) string {
	display = strings.TrimSpace(display)
	if display == "" {
		display = "your Mekong account"
	}
	return fmt.Sprintf(
		"✅ Your Telegram account is now linked to %s.\n\nUse /services to check active tunnels or /help to see all commands.",
		display,
	)
}

func FormatLinkCancelled() string {
	return "The pending Mekong link request was cancelled."
}

func FormatUnlinked() string {
	return "Your Telegram account has been unlinked from Mekong."
}

func FormatUnknownCommand() string {
	return "Unknown command.\n\nUse /help to see what I can do."
}

// FormatUser formats a user's account summary.
func FormatUser(u *models.User) string {
	verified := "✅ verified"
	if !u.EmailVerified {
		verified = "⚠ not verified"
	}

	var b strings.Builder
	b.WriteString("*Your Mekong Account*\n\n")
	if name := strings.TrimSpace(u.Name); name != "" {
		b.WriteString(fmt.Sprintf("Name: %s\n", escMD(name)))
	}
	b.WriteString(fmt.Sprintf("Email: %s\n", escMD(u.Email)))
	b.WriteString(fmt.Sprintf("Status: %s\n", verified))
	b.WriteString(fmt.Sprintf("Plan: %s\n", escMD(upperOrDash(u.Plan))))
	b.WriteString(fmt.Sprintf("Account: %s\n", escMD(upperOrDash(u.AccountType))))
	b.WriteString("\nNext: `/services`")
	return truncate(b.String())
}

// FormatTunnels formats a slice of tunnel records.
func FormatTunnels(tunnels []*models.Tunnel) string {
	if len(tunnels) == 0 {
		return "🟡 No active tunnels found."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("*Active Tunnels* (%d)\n\n", len(tunnels)))
	for i, t := range tunnels {
		if i > 0 {
			b.WriteString("\n")
		}
		label := t.Subdomain
		if strings.TrimSpace(label) == "" {
			label = t.ID
		}
		b.WriteString(fmt.Sprintf("%s `%s`\n", tunnelStatusIcon(t.Status), escMD(label)))
		b.WriteString(fmt.Sprintf("Port: `%d` | Requests: `%s`\n", t.LocalPort, formatCount(t.TotalRequests)))
	}
	if len(tunnels) == 1 {
		label := tunnels[0].Subdomain
		if strings.TrimSpace(label) == "" {
			label = tunnels[0].ID
		}
		b.WriteString(fmt.Sprintf("\nNext: `/logs %s`", escMD(label)))
	} else {
		b.WriteString("\nTip: Use `/logs <subdomain>` to inspect one tunnel.")
	}
	return truncate(b.String())
}

// FormatSubdomains formats reserved subdomain records.
func FormatSubdomains(subs []*models.ReservedSubdomain) string {
	if len(subs) == 0 {
		return "🟡 No reserved subdomains found."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("*Reserved Subdomains* (%d)\n\n", len(subs)))
	for _, s := range subs {
		b.WriteString(fmt.Sprintf("• `%s`\n", escMD(s.Subdomain)))
	}
	return truncate(strings.TrimRight(b.String(), "\n"))
}

// FormatDomains formats custom domain records.
func FormatDomains(domains []*models.CustomDomain) string {
	if len(domains) == 0 {
		return "🟡 No custom domains found."
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("*Custom Domains* (%d)\n\n", len(domains)))
	for _, d := range domains {
		b.WriteString(fmt.Sprintf("%s `%s`", domainStatusIcon(d.Status), escMD(d.Domain)))
		if d.TargetSubdomain != nil && strings.TrimSpace(*d.TargetSubdomain) != "" {
			b.WriteString(fmt.Sprintf(" -> `%s`", escMD(*d.TargetSubdomain)))
		}
		b.WriteString(fmt.Sprintf(" (%s)\n", escMD(strings.ToLower(d.Status))))
	}
	b.WriteString("\nTip: Use `/domain <host>` for details.")
	return truncate(strings.TrimRight(b.String(), "\n"))
}

// FormatDomain formats one custom domain in detail.
func FormatDomain(d *models.CustomDomain) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%s *Domain Check*\n\n", domainStatusIcon(d.Status)))
	b.WriteString(fmt.Sprintf("Host: `%s`\n", escMD(d.Domain)))
	b.WriteString(fmt.Sprintf("Status: %s\n", escMD(strings.ToLower(d.Status))))
	if d.TargetSubdomain != nil && strings.TrimSpace(*d.TargetSubdomain) != "" {
		b.WriteString(fmt.Sprintf("Target: `%s`\n", escMD(*d.TargetSubdomain)))
	}
	if d.LastCheckedAt != nil {
		b.WriteString(fmt.Sprintf("Last checked: %s\n", formatTime(*d.LastCheckedAt)))
	}
	if d.VerifiedAt != nil {
		b.WriteString(fmt.Sprintf("Verified: %s\n", formatTime(*d.VerifiedAt)))
	}
	b.WriteString(fmt.Sprintf("Added: %s", formatTime(d.CreatedAt)))
	return truncate(b.String())
}

// FormatLogs formats recent log lines for Telegram.
func FormatLogs(lines []string, label string) string {
	redacted := RedactLines(lines)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("*Recent Logs* `%s`\n", escMD(label)))
	b.WriteString("Last 20 lines. Secrets are redacted.\n\n```\n")
	for _, l := range redacted {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	b.WriteString("```")
	return truncate(b.String())
}

// FormatLogsPlain formats recent log lines without Markdown parsing.
func FormatLogsPlain(lines []string, label string) string {
	redacted := RedactLines(lines)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Recent logs: %s\n", label))
	b.WriteString("Last 20 lines. Secrets are redacted.\n\n")
	for _, l := range redacted {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return strings.TrimRight(truncate(b.String()), "\n")
}

// Future proactive alert templates.

func FormatTunnelDownAlert(service string, port int) string {
	var b strings.Builder
	b.WriteString("🔴 Tunnel Down\n\n")
	b.WriteString(fmt.Sprintf("Service: %s\n", nonEmpty(service, "unknown")))
	if port > 0 {
		b.WriteString(fmt.Sprintf("Last known port: %d\n", port))
	}
	b.WriteString("Issue: tunnel is no longer active\n\n")
	b.WriteString("Check: /services\n")
	if strings.TrimSpace(service) != "" {
		b.WriteString(fmt.Sprintf("Then: /logs %s", service))
	}
	return truncate(strings.TrimRight(b.String(), "\n"))
}

func FormatTunnelIssueAlert(service, symptom string) string {
	var b strings.Builder
	b.WriteString("🟡 Tunnel Issue\n\n")
	b.WriteString(fmt.Sprintf("Service: %s\n", nonEmpty(service, "unknown")))
	if strings.TrimSpace(symptom) != "" {
		b.WriteString(fmt.Sprintf("Recent symptom: %s\n", symptom))
	}
	b.WriteString("\nCheck: /services")
	if strings.TrimSpace(service) != "" {
		b.WriteString(fmt.Sprintf("\nThen: /logs %s", service))
	}
	return truncate(strings.TrimRight(b.String(), "\n"))
}

func FormatDomainPendingAlert(host string) string {
	return truncate(fmt.Sprintf(
		"🟡 Domain Pending\n\nDomain: %s\nStatus: pending\nReason: DNS or HTTPS setup is not complete yet\n\nCheck: /domain %s",
		nonEmpty(host, "unknown"),
		nonEmpty(host, "<host>"),
	))
}

func FormatDomainFailedAlert(host, reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "verification did not pass"
	}
	return truncate(fmt.Sprintf(
		"🔴 Domain Failed\n\nDomain: %s\nStatus: failed\nReason: %s\n\nCheck: /domain %s",
		nonEmpty(host, "unknown"),
		reason,
		nonEmpty(host, "<host>"),
	))
}

func FormatDomainReadyAlert(host, target string) string {
	var b strings.Builder
	b.WriteString("✅ Domain Ready\n\n")
	b.WriteString(fmt.Sprintf("Domain: %s\n", nonEmpty(host, "unknown")))
	if strings.TrimSpace(target) != "" {
		b.WriteString(fmt.Sprintf("Target: %s\n", target))
	}
	b.WriteString("Status: verified and HTTPS is ready\n\n")
	b.WriteString(fmt.Sprintf("Check: /domain %s", nonEmpty(host, "<host>")))
	return truncate(strings.TrimRight(b.String(), "\n"))
}

func FormatDomainUpdatedAlert(host, target string) string {
	var b strings.Builder
	b.WriteString("🟡 Domain Updated\n\n")
	b.WriteString(fmt.Sprintf("Domain: %s\n", nonEmpty(host, "unknown")))
	if strings.TrimSpace(target) != "" {
		b.WriteString(fmt.Sprintf("Target: %s\n", target))
	}
	b.WriteString("Status: route updated\n\n")
	b.WriteString(fmt.Sprintf("Check: /domain %s", nonEmpty(host, "<host>")))
	return truncate(strings.TrimRight(b.String(), "\n"))
}

func FormatTunnelRecoveredAlert(service string) string {
	var b strings.Builder
	b.WriteString("🟢 Tunnel Recovered\n\n")
	b.WriteString(fmt.Sprintf("Service: %s\n", nonEmpty(service, "unknown")))
	b.WriteString("Status: active again\n\n")
	b.WriteString("Check: /services")
	return truncate(b.String())
}

func domainStatusIcon(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
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

func tunnelStatusIcon(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "active":
		return "🟢"
	case "pending", "starting":
		return "🟡"
	case "failed", "error", "stopped", "inactive":
		return "🔴"
	default:
		return "🟢"
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

func upperOrDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return strings.ToUpper(s)
}

func formatTime(t time.Time) string {
	return t.Format(shortTimeLayout)
}

func formatCount(v int64) string {
	sign := ""
	if v < 0 {
		sign = "-"
		v = -v
	}
	raw := strconv.FormatInt(v, 10)
	if len(raw) <= 3 {
		return sign + raw
	}

	var parts []string
	for len(raw) > 3 {
		parts = append([]string{raw[len(raw)-3:]}, parts...)
		raw = raw[:len(raw)-3]
	}
	parts = append([]string{raw}, parts...)
	return sign + strings.Join(parts, ",")
}

func nonEmpty(s, fallback string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	return s
}
