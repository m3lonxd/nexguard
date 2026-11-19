package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"nexguard/internal/honeypot"
	"nexguard/internal/responder"
	"nexguard/internal/transport"
)

// commander panelden gelen komutları çalıştırır ve sonucu döndürür.
type commander struct {
	resp  *responder.BlockIP
	hp    *honeypot.Manager
	state *stateStore

	mu      sync.Mutex
	results map[string]transport.CommandResult // tekrar gelen komut yeniden çalışmaz
	order   []string
}

const resultCache = 256

func (c *commander) status() transport.AgentStatus {
	st := c.state.get()
	hs := c.hp.Status()
	allow := st.Allow
	if allow == nil {
		allow = []string{}
	}
	return transport.AgentStatus{Version: version, Honeypot: &hs, Allow: allow, Blocked: c.resp.Active()}
}

func (c *commander) run(cmd transport.Command) transport.CommandResult {
	c.mu.Lock()
	if r, ok := c.results[cmd.ID]; ok {
		c.mu.Unlock()
		return r
	}
	c.mu.Unlock()

	res := transport.CommandResult{ID: cmd.ID}
	out, err := c.exec(cmd)
	if err != nil {
		res.Error = err.Error()
	} else {
		res.OK = true
		res.Result = out
	}
	log.Printf("agent: command %s %s -> ok=%v %s", cmd.Type, cmd.ID, res.OK, res.Error)

	c.mu.Lock()
	if c.results == nil {
		c.results = map[string]transport.CommandResult{}
	}
	c.results[cmd.ID] = res
	c.order = append(c.order, cmd.ID)
	if len(c.order) > resultCache {
		delete(c.results, c.order[0])
		c.order = c.order[1:]
	}
	c.mu.Unlock()
	return res
}

func paramIP(p map[string]any) (string, error) {
	s, _ := p["ip"].(string)
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", errors.New("geçersiz ip")
	}
	return a.Unmap().String(), nil
}

func (c *commander) exec(cmd transport.Command) (map[string]any, error) {
	switch cmd.Type {
	case "block_ip":
		ip, err := paramIP(cmd.Params)
		if err != nil {
			return nil, err
		}
		ttl, _ := time.ParseDuration(fmt.Sprint(cmd.Params["ttl"]))
		a, err := c.resp.Manual(ip, ttl, cmd.ID)
		if err != nil {
			return nil, err
		}
		if st := a.Params["status"]; st != "applied" {
			return nil, fmt.Errorf("%v: %v", st, a.Params["reason"])
		}
		return map[string]any{"action_id": a.ID, "backend": a.Params["backend"], "ttl": a.Params["ttl"]}, nil
	case "unblock_ip":
		ip, err := paramIP(cmd.Params)
		if err != nil {
			return nil, err
		}
		a, err := c.resp.Unblock(ip)
		if err != nil {
			return nil, err
		}
		return map[string]any{"action_id": a.ID}, nil
	case "allow_ip", "disallow_ip":
		ip, err := paramIP(cmd.Params)
		if err != nil {
			return nil, err
		}
		add := cmd.Type == "allow_ip"
		st, err := c.state.update(func(s *agentState) {
			out := s.Allow[:0]
			for _, x := range s.Allow {
				if x != ip {
					out = append(out, x)
				}
			}
			if add {
				out = append(out, ip)
			}
			s.Allow = out
		})
		if err != nil {
			return nil, err
		}
		c.resp.SetAllow(st.Allow)
		res := map[string]any{"allow": st.Allow}
		// izin listesine alınan adresin etkin engeli kaldırılır
		if add {
			if _, err := c.resp.Unblock(ip); err == nil {
				res["unblocked"] = true
			}
		}
		return res, nil
	case "honeypot":
		cfg := honeypot.Config{}
		cfg.Enabled, _ = cmd.Params["enabled"].(bool)
		cfg.AutoBlock, _ = cmd.Params["auto_block"].(bool)
		if f, ok := cmd.Params["ssh_port"].(float64); ok {
			cfg.SSHPort = int(f)
		}
		if raw, ok := cmd.Params["tcp_ports"].([]any); ok {
			for _, v := range raw {
				if f, ok := v.(float64); ok {
					cfg.TCPPorts = append(cfg.TCPPorts, int(f))
				}
			}
		}
		if _, err := c.state.update(func(s *agentState) { s.Honeypot = cfg }); err != nil {
			return nil, err
		}
		applyAutoBlock(c.resp, cfg)
		hs := c.hp.Apply(cfg)
		res := map[string]any{"listening": hs.Listening}
		if len(hs.Errors) > 0 {
			msgs := make([]string, 0, len(hs.Errors))
			for _, e := range hs.Errors {
				msgs = append(msgs, e)
			}
			res["errors"] = hs.Errors
			if len(hs.Listening) == 0 && cfg.Enabled {
				return nil, errors.New(strings.Join(msgs, "; "))
			}
		}
		return res, nil
	}
	return nil, fmt.Errorf("bilinmeyen komut %q", cmd.Type)
}

func applyAutoBlock(resp *responder.BlockIP, cfg honeypot.Config) {
	on := cfg.Enabled && cfg.AutoBlock
	resp.SetAutoBlock("honeypot_ssh", on)
	resp.SetAutoBlock("honeypot_tcp", on)
}

// commandLoop panele kalıcı soketle bağlanır; koparsa artan beklemeyle
// yeniden bağlanır. statusCh'e gelen her sinyal panele güncel durumu yollar.
func commandLoop(ctx context.Context, cfg Config, c *commander, statusCh <-chan struct{}) {
	wsURL := "ws" + strings.TrimPrefix(cfg.ServerURL, "http") + transport.AgentPath
	backoff := time.Second
	for ctx.Err() == nil {
		h := http.Header{}
		h.Set("Authorization", "Bearer "+cfg.Token)
		d := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
		conn, resp, err := d.DialContext(ctx, wsURL, h)
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if err != nil {
			log.Printf("agent: command channel: %v (retry in %s)", err, backoff)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < time.Minute {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		log.Printf("agent: command channel connected")
		serveConn(ctx, conn, c, statusCh)
		conn.Close()
	}
}

func serveConn(ctx context.Context, conn *websocket.Conn, c *commander, statusCh <-chan struct{}) {
	out := make(chan transport.AgentMessage, 32)
	done := make(chan struct{})
	conn.SetReadLimit(1 << 20)
	_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
	conn.SetPingHandler(func(data string) error {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		return conn.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(5*time.Second))
	})
	go func() {
		defer close(done)
		for {
			var msg transport.AgentMessage
			if err := conn.ReadJSON(&msg); err != nil {
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
			if msg.Kind != "command" || msg.Command == nil {
				continue
			}
			res := c.run(*msg.Command)
			select {
			case out <- transport.AgentMessage{Kind: "result", Result: &res}:
			case <-done:
				return
			}
			st := c.status()
			select {
			case out <- transport.AgentMessage{Kind: "status", Status: &st}:
			default:
			}
		}
	}()
	st := c.status()
	out <- transport.AgentMessage{Kind: "status", Status: &st}
	for {
		select {
		case <-ctx.Done():
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
			return
		case <-done:
			return
		case <-statusCh:
			st := c.status()
			select {
			case out <- transport.AgentMessage{Kind: "status", Status: &st}:
			default:
			}
		case msg := <-out:
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteJSON(msg); err != nil {
				return
			}
		}
	}
}
