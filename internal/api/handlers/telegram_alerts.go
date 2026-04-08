package handlers

import (
	"context"
	"strings"

	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/models"
)

type TelegramAlerter interface {
	NotifyTunnelDown(ctx context.Context, userID, service string, port int)
	NotifyTunnelIssue(ctx context.Context, userID, service, symptom string)
	NotifyTunnelRecovered(ctx context.Context, userID, service string)
	NotifyDomainPending(ctx context.Context, userIDs []string, host string)
	NotifyDomainFailed(ctx context.Context, userIDs []string, host, reason string)
	NotifyDomainReady(ctx context.Context, userIDs []string, host, target string)
	NotifyDomainUpdated(ctx context.Context, userIDs []string, host, target string)
}

func notifyTunnelTransition(ctx context.Context, bot TelegramAlerter, before *models.Tunnel, afterStatus string) {
	if bot == nil || before == nil || before.UserID == nil || strings.TrimSpace(*before.UserID) == "" {
		return
	}

	prevStatus := normalizeTunnelStatus(before.Status)
	nextStatus := normalizeTunnelStatus(afterStatus)
	if nextStatus == "" || prevStatus == nextStatus {
		return
	}

	userID := strings.TrimSpace(*before.UserID)
	service := strings.TrimSpace(before.Subdomain)
	if service == "" {
		service = strings.TrimSpace(before.ID)
	}

	switch nextStatus {
	case "active":
		bot.NotifyTunnelRecovered(ctx, userID, service)
	case "failed", "error":
		bot.NotifyTunnelIssue(ctx, userID, service, "status changed to "+nextStatus)
	case "stopped", "inactive":
		if prevStatus == "active" || prevStatus == "starting" || prevStatus == "pending" || prevStatus == "failed" || prevStatus == "error" {
			bot.NotifyTunnelDown(ctx, userID, service, before.LocalPort)
		}
	}
}

func notifyDomainCreated(ctx context.Context, bot TelegramAlerter, recipientUserIDs []string, d *models.CustomDomain) {
	if bot == nil || d == nil {
		return
	}
	bot.NotifyDomainPending(ctx, recipientUserIDs, d.Domain)
}

func notifyDomainTargetUpdated(ctx context.Context, bot TelegramAlerter, recipientUserIDs []string, d *models.CustomDomain) {
	if bot == nil || d == nil {
		return
	}
	target := ""
	if d.TargetSubdomain != nil {
		target = strings.TrimSpace(*d.TargetSubdomain)
	}
	bot.NotifyDomainUpdated(ctx, recipientUserIDs, d.Domain, target)
}

func notifyDomainVerificationResult(ctx context.Context, bot TelegramAlerter, recipientUserIDs []string, d *models.CustomDomain, verified, ready bool, reason string) {
	if bot == nil || d == nil {
		return
	}
	target := ""
	if d.TargetSubdomain != nil {
		target = strings.TrimSpace(*d.TargetSubdomain)
	}

	if verified {
		if ready {
			bot.NotifyDomainReady(ctx, recipientUserIDs, d.Domain, target)
			return
		}
		bot.NotifyDomainPending(ctx, recipientUserIDs, d.Domain)
		return
	}
	bot.NotifyDomainFailed(ctx, recipientUserIDs, d.Domain, reason)
}

func domainAlertRecipients(ctx context.Context, database *db.DB, d *models.CustomDomain) []string {
	if database == nil || d == nil {
		return nil
	}
	if strings.TrimSpace(d.UserID) != "" {
		return []string{strings.TrimSpace(d.UserID)}
	}
	if d.TeamID == nil || strings.TrimSpace(*d.TeamID) == "" {
		return nil
	}

	teamID := strings.TrimSpace(*d.TeamID)
	recipients := make(map[string]struct{})

	if team, err := database.GetTeamByID(ctx, teamID); err == nil && strings.TrimSpace(team.OwnerID) != "" {
		recipients[strings.TrimSpace(team.OwnerID)] = struct{}{}
	}

	if members, err := database.ListTeamMembers(ctx, teamID); err == nil {
		for _, member := range members {
			if member == nil || !canInvite(member.Role) {
				continue
			}
			userID := strings.TrimSpace(member.UserID)
			if userID == "" {
				continue
			}
			recipients[userID] = struct{}{}
		}
	}

	out := make([]string, 0, len(recipients))
	for userID := range recipients {
		out = append(out, userID)
	}
	return out
}

func normalizeTunnelStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}
