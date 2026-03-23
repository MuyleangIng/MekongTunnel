// Package notify provides a service for creating and pushing real-time notifications.
package notify

import (
	"context"
	"encoding/json"
	"log"

	"github.com/MuyleangIng/MekongTunnel/internal/db"
	"github.com/MuyleangIng/MekongTunnel/internal/hub"
)

// Service creates DB notifications and pushes them to live SSE connections.
type Service struct {
	DB  *db.DB
	Hub *hub.Hub
}

// Send creates a notification for a specific user and pushes it via SSE.
func (s *Service) Send(ctx context.Context, userID, notifType, title, body, link string) {
	n, err := s.DB.CreateNotification(ctx, userID, notifType, title, body, link)
	if err != nil {
		log.Printf("[notify] create: %v", err)
		return
	}
	data, _ := json.Marshal(n)
	s.Hub.Push(userID, data)
}

// SendToAdmins sends a notification to every admin user.
func (s *Service) SendToAdmins(ctx context.Context, notifType, title, body, link string) {
	adminIDs, err := s.DB.GetAdminIDs(ctx)
	if err != nil {
		log.Printf("[notify] get admins: %v", err)
		return
	}
	for _, id := range adminIDs {
		s.Send(ctx, id, notifType, title, body, link)
	}
}
