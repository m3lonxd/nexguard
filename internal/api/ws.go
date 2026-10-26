package api

import (
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"

	"nexguard/internal/transport"
)

type wsMessage struct {
	Kind    string               `json:"kind"`
	Finding *transport.Finding   `json:"finding,omitempty"`
	Action  *transport.ActionLog `json:"action,omitempty"`
}

var upgrader = websocket.Upgrader{
	// The dashboard is served from this same origin in Phase 1 (no
	// multi-host panel yet), so any origin is accepted here.
	CheckOrigin: func(r *http.Request) bool { return true },
}

type hub struct {
	mu      sync.Mutex
	clients map[*websocket.Conn]chan wsMessage
}

func newHub() *hub {
	return &hub{clients: make(map[*websocket.Conn]chan wsMessage)}
}

func (h *hub) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("api: websocket upgrade: %v", err)
		return
	}

	send := make(chan wsMessage, 16)
	h.mu.Lock()
	h.clients[conn] = send
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, conn)
		h.mu.Unlock()
		conn.Close()
	}()

	// Drain and discard client reads so the connection's read deadline logic
	// (and close detection) keeps working; the dashboard never sends us
	// anything over this socket.
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				conn.Close()
				return
			}
		}
	}()

	for msg := range send {
		if err := conn.WriteJSON(msg); err != nil {
			return
		}
	}
}

func (h *hub) broadcast(msg wsMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for conn, ch := range h.clients {
		select {
		case ch <- msg:
		default:
			log.Printf("api: websocket client %s too slow, dropping message", conn.RemoteAddr())
		}
	}
}
