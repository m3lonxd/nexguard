package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"nexguard/internal/store"
	"nexguard/internal/transport"
)

// Panelin ajanlara gönderebildiği komutlar.
const (
	CmdBlockIP    = "block_ip"
	CmdUnblockIP  = "unblock_ip"
	CmdAllowIP    = "allow_ip"
	CmdDisallowIP = "disallow_ip"
	CmdHoneypot   = "honeypot"
)

const (
	minBlockTTL = time.Minute
	maxBlockTTL = 7 * 24 * time.Hour
	maxTCPPorts = 16
)

// validateCommand parametreleri ajanın beklediği tek biçime indirger.
func validateCommand(typ string, in map[string]any) (map[string]any, error) {
	ipParam := func() (string, error) {
		s, _ := in["ip"].(string)
		a, err := netip.ParseAddr(s)
		if err != nil {
			return "", errors.New("geçerli bir ip gerekli")
		}
		return a.Unmap().String(), nil
	}
	switch typ {
	case CmdBlockIP:
		ip, err := ipParam()
		if err != nil {
			return nil, err
		}
		ttl := time.Hour
		if s, ok := in["ttl"].(string); ok && s != "" {
			d, err := time.ParseDuration(s)
			if err != nil || d < minBlockTTL || d > maxBlockTTL {
				return nil, fmt.Errorf("ttl %s ile %s arasında olmalı", minBlockTTL, maxBlockTTL)
			}
			ttl = d
		}
		return map[string]any{"ip": ip, "ttl": ttl.String()}, nil
	case CmdUnblockIP, CmdAllowIP, CmdDisallowIP:
		ip, err := ipParam()
		if err != nil {
			return nil, err
		}
		return map[string]any{"ip": ip}, nil
	case CmdHoneypot:
		enabled, _ := in["enabled"].(bool)
		autoBlock, _ := in["auto_block"].(bool)
		port := func(v any) (int, bool) {
			f, ok := v.(float64)
			if !ok || f != float64(int(f)) || f < 1 || f > 65535 {
				return 0, false
			}
			return int(f), true
		}
		sshPort := 0
		if v, ok := in["ssh_port"]; ok && v != nil {
			p, ok := port(v)
			if !ok {
				return nil, errors.New("ssh_port 1-65535 arasında olmalı")
			}
			sshPort = p
		}
		var tcp []int
		if raw, ok := in["tcp_ports"].([]any); ok {
			if len(raw) > maxTCPPorts {
				return nil, fmt.Errorf("en fazla %d tcp portu", maxTCPPorts)
			}
			seen := map[int]bool{}
			for _, v := range raw {
				p, ok := port(v)
				if !ok {
					return nil, errors.New("tcp_ports 1-65535 arası tam sayılar olmalı")
				}
				if p == sshPort {
					return nil, fmt.Errorf("%d hem ssh hem tcp tuzağı olamaz", p)
				}
				if !seen[p] {
					seen[p] = true
					tcp = append(tcp, p)
				}
			}
		}
		if enabled && sshPort == 0 && len(tcp) == 0 {
			return nil, errors.New("açık honeypot için en az bir port gerekli")
		}
		if tcp == nil {
			tcp = []int{}
		}
		return map[string]any{"enabled": enabled, "ssh_port": sshPort, "tcp_ports": tcp, "auto_block": autoBlock}, nil
	}
	return nil, fmt.Errorf("bilinmeyen komut: %q", typ)
}

// ---------- ajan bağlantıları ----------

type agentConn struct {
	send chan transport.AgentMessage
	done chan struct{}
	once sync.Once
}

func (c *agentConn) stop() { c.once.Do(func() { close(c.done) }) }

type agentState struct {
	Online   bool                   `json:"online"`
	LastSeen *time.Time             `json:"last_seen,omitempty"`
	Status   *transport.AgentStatus `json:"status,omitempty"`
}

type agents struct {
	mu    sync.Mutex
	conns map[string]*agentConn
	state map[string]agentState
}

func newAgents() *agents {
	return &agents{conns: map[string]*agentConn{}, state: map[string]agentState{}}
}

func (a *agents) get(serverID string) agentState {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state[serverID]
}

// deliver bağlı ajana komutu yollar; ajan bağlı değilse false döner ve komut
// kuyrukta kalır (ajan bağlanınca gönderilir).
func (a *agents) deliver(serverID string, cmd transport.Command) bool {
	a.mu.Lock()
	c := a.conns[serverID]
	a.mu.Unlock()
	if c == nil {
		return false
	}
	select {
	case c.send <- transport.AgentMessage{Kind: "command", Command: &cmd}:
		return true
	case <-c.done:
		return false
	default:
		return false
	}
}

func toTransport(c store.Command) transport.Command {
	return transport.Command{ID: c.ID, Type: c.Type, Params: c.Params, CreatedAt: c.CreatedAt}
}

const (
	agentPingEvery = 25 * time.Second
	agentReadWait  = 60 * time.Second
)

// handleAgent ajanın kalıcı komut soketidir (bearer token ile).
func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	serverID, _ := r.Context().Value(serverIDKey).(string)
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("api: agent websocket upgrade: %v", err)
		return
	}
	if err := s.store.SetServerIP(serverID, clientIP(r)); err != nil {
		log.Printf("api: set server ip: %v", err)
	}
	ac := &agentConn{send: make(chan transport.AgentMessage, 64), done: make(chan struct{})}

	s.agents.mu.Lock()
	if old := s.agents.conns[serverID]; old != nil {
		old.stop() // aynı ajandan yeni bağlantı eskisinin yerini alır
	}
	s.agents.conns[serverID] = ac
	now := time.Now().UTC()
	st := s.agents.state[serverID]
	st.Online, st.LastSeen = true, &now
	s.agents.state[serverID] = st
	s.agents.mu.Unlock()
	s.broadcastAgent(serverID)

	defer func() {
		s.agents.mu.Lock()
		if s.agents.conns[serverID] == ac {
			delete(s.agents.conns, serverID)
			st := s.agents.state[serverID]
			st.Online = false
			s.agents.state[serverID] = st
		}
		s.agents.mu.Unlock()
		conn.Close()
		s.broadcastAgent(serverID)
	}()

	// bekleyen komutlar
	open, err := s.store.OpenCommands(serverID)
	if err != nil {
		log.Printf("api: open commands: %v", err)
	}
queue:
	for _, c := range open {
		select {
		case ac.send <- transport.AgentMessage{Kind: "command", Command: ptr(toTransport(c))}:
		default:
			break queue // kalanlar bir sonraki bağlantıda gönderilir
		}
	}

	go func() {
		defer conn.Close()
		conn.SetReadLimit(1 << 20)
		_ = conn.SetReadDeadline(time.Now().Add(agentReadWait))
		conn.SetPongHandler(func(string) error { return conn.SetReadDeadline(time.Now().Add(agentReadWait)) })
		for {
			var msg transport.AgentMessage
			if err := conn.ReadJSON(&msg); err != nil {
				ac.stop()
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(agentReadWait))
			s.onAgentMessage(serverID, msg)
		}
	}()

	ping := time.NewTicker(agentPingEvery)
	defer ping.Stop()
	for {
		select {
		case <-ac.done:
			return
		case msg := <-ac.send:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteJSON(msg); err != nil {
				return
			}
			if msg.Kind == "command" && msg.Command != nil {
				if err := s.store.MarkCommandSent(msg.Command.ID); err != nil {
					log.Printf("api: mark command sent: %v", err)
				}
			}
		case <-ping.C:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func ptr[T any](v T) *T { return &v }

func (s *Server) onAgentMessage(serverID string, msg transport.AgentMessage) {
	now := time.Now().UTC()
	switch msg.Kind {
	case "status":
		if msg.Status == nil {
			return
		}
		s.agents.mu.Lock()
		st := s.agents.state[serverID]
		st.Status, st.LastSeen = msg.Status, &now
		s.agents.state[serverID] = st
		s.agents.mu.Unlock()
		s.broadcastAgent(serverID)
	case "result":
		res := msg.Result
		if res == nil || res.ID == "" {
			return
		}
		ok, err := s.store.CompleteCommand(serverID, res.ID, res.OK, res.Result, res.Error)
		if err != nil {
			log.Printf("api: complete command: %v", err)
			return
		}
		if !ok {
			return
		}
		if c, found, err := s.store.GetCommand(res.ID); err == nil && found {
			s.hub.broadcast(wsMessage{Kind: "command", Command: &c})
		}
	}
}

func (s *Server) broadcastAgent(serverID string) {
	st := s.agents.get(serverID)
	s.hub.broadcast(wsMessage{Kind: "agent", ServerID: serverID, Agent: &st})
}

// ---------- panel uçları ----------

func (s *Server) handleCreateCommand(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	exists, err := s.store.ServerExists(serverID)
	if err != nil {
		log.Printf("api: server exists: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}
	var req struct {
		Type   string         `json:"type"`
		Params map[string]any `json:"params"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	params, err := validateCommand(req.Type, req.Params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := store.Command{
		ID:        transport.NewID(),
		ServerID:  serverID,
		Type:      req.Type,
		Params:    params,
		Status:    store.CommandPending,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.store.InsertCommand(c); err != nil {
		log.Printf("api: insert command: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if s.agents.deliver(serverID, toTransport(c)) {
		c.Status = store.CommandSent
	}
	s.hub.broadcast(wsMessage{Kind: "command", Command: &c})
	writeJSON(w, http.StatusAccepted, c)
}

func (s *Server) handleListCommands(w http.ResponseWriter, r *http.Request) {
	cmds, err := s.store.ListCommands(r.PathValue("id"), 100)
	if err != nil {
		log.Printf("api: list commands: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, cmds)
}
