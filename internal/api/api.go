package api

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"nexguard/internal/geo"
	"nexguard/internal/store"
	"nexguard/internal/transport"
)

type ctxKey int

const serverIDKey ctxKey = 0

type Server struct {
	store  *store.Store
	hub    *hub
	mux    *http.ServeMux
	geo    *geo.Resolver
	home   *geo.Country // sunucu adresi çözülemediğinde kullanılan konum
	agents *agents
}

func New(st *store.Store) *Server {
	s := &Server{store: st, hub: newHub(), agents: newAgents()}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/enroll", s.handleEnroll)
	mux.HandleFunc("POST /api/v1/events", s.requireAuth(s.handleEvents))
	mux.HandleFunc("POST /api/v1/actions", s.requireAuth(s.handleActions))
	mux.HandleFunc("GET /api/v1/stream", s.handleStream)
	mux.HandleFunc("GET /api/v1/servers", s.handleListServers)
	mux.HandleFunc("GET /api/v1/findings", s.handleListFindings)
	mux.HandleFunc("GET /api/v1/actions", s.handleListActions)
	mux.HandleFunc("GET /api/v1/geo", s.handleGeo)
	mux.HandleFunc("GET /api/v1/agent", s.requireAuth(s.handleAgent))
	// Panel komut uçları Faz 1'deki diğer panel uçları gibi kimlik doğrulamasızdır;
	// paneli yalnızca güvenilir ağa (VPN / güvenlik duvarı arkası) açın.
	mux.HandleFunc("POST /api/v1/servers/{id}/commands", s.handleCreateCommand)
	mux.HandleFunc("GET /api/v1/servers/{id}/commands", s.handleListCommands)
	s.mux = mux
	return s
}

// SetGeo haritanın konum kaynağını bağlar. home, adresi genel internette
// çözülemeyen (yerel ağ, NAT arkası) sunucular için gösterilecek konumdur; nil olabilir.
func (s *Server) SetGeo(r *geo.Resolver, home *geo.Country) {
	s.geo = r
	s.home = home
}

// clientIP isteğin geldiği adresi döner. Panel aynı makinedeki bir ters
// vekilin (nginx) arkasındaysa vekilin bildirdiği adres kullanılır; başka
// yerden gelen isteklerde bu başlıklara güvenilmez.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if a.Unmap().IsLoopback() {
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
			if b, err := netip.ParseAddr(v); err == nil {
				return b.Unmap().String()
			}
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			first := strings.TrimSpace(strings.Split(v, ",")[0])
			if b, err := netip.ParseAddr(first); err == nil {
				return b.Unmap().String()
			}
		}
	}
	return a.Unmap().String()
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(auth, "Bearer ")
		if !ok || token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		serverID, ok, err := s.store.VerifyToken(token)
		if err != nil {
			log.Printf("api: verify token: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), serverIDKey, serverID)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req transport.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Hostname == "" {
		http.Error(w, "hostname is required", http.StatusBadRequest)
		return
	}

	id := store.NewID()
	token := store.NewToken()
	// Enrollment is intentionally open in Phase 1 (no install key required);
	// anyone who can reach this endpoint can register a server. Put it
	// behind a network boundary (VPN/firewall) or add an install key before
	// exposing the panel to the public internet.
	if err := s.store.CreateServer(id, req.Hostname, req.OS, store.HashToken(token)); err != nil {
		log.Printf("api: create server: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.SetServerIP(id, clientIP(r)); err != nil {
		log.Printf("api: set server ip: %v", err)
	}

	writeJSON(w, http.StatusOK, transport.EnrollResponse{ServerID: id, Token: token})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	serverID, _ := r.Context().Value(serverIDKey).(string)
	findings, err := decodeFindings(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.SetServerIP(serverID, clientIP(r)); err != nil {
		log.Printf("api: set server ip: %v", err)
	}
	for _, f := range findings {
		f.ServerID = serverID
		if err := s.store.InsertFinding(f); err != nil {
			log.Printf("api: insert finding: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.hub.broadcast(wsMessage{Kind: "finding", Finding: &f})
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	var a transport.ActionLog
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := s.store.InsertAction(a); err != nil {
		log.Printf("api: insert action: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.hub.broadcast(wsMessage{Kind: "action", Action: &a})
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	s.hub.serveWS(w, r)
}

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	servers, err := s.store.ListServers()
	if err != nil {
		log.Printf("api: list servers: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	type serverOut struct {
		store.Server
		Geo   *geo.Country `json:"geo,omitempty"`
		Agent agentState   `json:"agent"`
	}
	out := make([]serverOut, 0, len(servers))
	for _, srv := range servers {
		o := serverOut{Server: srv, Agent: s.agents.get(srv.ID)}
		if c, ok := s.geo.Lookup(srv.IP); ok {
			o.Geo = &c
		} else if s.home != nil {
			h := *s.home
			o.Geo = &h
		}
		out = append(out, o)
	}
	writeJSON(w, http.StatusOK, out)
}

const maxGeoIPs = 512

// handleGeo saldırgan adreslerini ülke noktalarına çevirir:
// GET /api/v1/geo?ip=a&ip=b -> {"enabled":true,"ips":{"a":{...}}}
// Çözülemeyen adresler yanıtta yer almaz.
func (s *Server) handleGeo(w http.ResponseWriter, r *http.Request) {
	ips := r.URL.Query()["ip"]
	if len(ips) > maxGeoIPs {
		http.Error(w, "too many ip parameters", http.StatusBadRequest)
		return
	}
	res := struct {
		Enabled bool                   `json:"enabled"`
		IPs     map[string]geo.Country `json:"ips"`
	}{Enabled: s.geo.Enabled(), IPs: map[string]geo.Country{}}
	for _, ip := range ips {
		if c, ok := s.geo.Lookup(ip); ok {
			res.IPs[ip] = c
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	findings, err := s.store.ListFindings()
	if err != nil {
		log.Printf("api: list findings: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

func (s *Server) handleListActions(w http.ResponseWriter, r *http.Request) {
	actions, err := s.store.ListActions()
	if err != nil {
		log.Printf("api: list actions: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, actions)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
