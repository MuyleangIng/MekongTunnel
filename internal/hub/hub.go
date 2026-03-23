// Package hub manages Server-Sent Events connections per user.
package hub

import "sync"

// Hub keeps track of SSE client channels keyed by user ID.
type Hub struct {
	mu      sync.RWMutex
	clients map[string]map[chan []byte]struct{}
}

func New() *Hub {
	return &Hub{clients: make(map[string]map[chan []byte]struct{})}
}

// Subscribe registers a new SSE channel for a user.
// Call the returned cleanup func when the connection closes.
func (h *Hub) Subscribe(userID string) (chan []byte, func()) {
	ch := make(chan []byte, 16)
	h.mu.Lock()
	if h.clients[userID] == nil {
		h.clients[userID] = make(map[chan []byte]struct{})
	}
	h.clients[userID][ch] = struct{}{}
	h.mu.Unlock()

	return ch, func() {
		h.mu.Lock()
		delete(h.clients[userID], ch)
		if len(h.clients[userID]) == 0 {
			delete(h.clients, userID)
		}
		h.mu.Unlock()
		close(ch)
	}
}

// Push sends a JSON payload to all active SSE connections for a user.
func (h *Hub) Push(userID string, data []byte) {
	h.mu.RLock()
	channels := make([]chan []byte, 0, len(h.clients[userID]))
	for ch := range h.clients[userID] {
		channels = append(channels, ch)
	}
	h.mu.RUnlock()

	for _, ch := range channels {
		select {
		case ch <- data:
		default: // drop if buffer full
		}
	}
}
