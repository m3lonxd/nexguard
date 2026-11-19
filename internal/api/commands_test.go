package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"nexguard/internal/store"
	"nexguard/internal/transport"
)

func TestValidateCommand(t *testing.T) {
	ok := []struct {
		typ string
		in  map[string]any
	}{
		{CmdBlockIP, map[string]any{"ip": "198.51.100.4"}},
		{CmdBlockIP, map[string]any{"ip": "198.51.100.4", "ttl": "24h"}},
		{CmdUnblockIP, map[string]any{"ip": "2001:db8::1"}},
		{CmdAllowIP, map[string]any{"ip": "::ffff:10.0.0.1"}},
		{CmdHoneypot, map[string]any{"enabled": true, "ssh_port": float64(2222), "tcp_ports": []any{float64(23), float64(3389)}, "auto_block": true}},
		{CmdHoneypot, map[string]any{"enabled": false}},
	}
	for _, c := range ok {
		if _, err := validateCommand(c.typ, c.in); err != nil {
			t.Errorf("%s %v: beklenmeyen hata %v", c.typ, c.in, err)
		}
	}
	bad := []struct {
		typ string
		in  map[string]any
	}{
		{"rm_rf", map[string]any{}},
		{CmdBlockIP, map[string]any{"ip": "1.2.3.4; reboot"}},
		{CmdBlockIP, map[string]any{"ip": "198.51.100.4", "ttl": "5s"}},
		{CmdBlockIP, map[string]any{"ip": "198.51.100.4", "ttl": "720h"}},
		{CmdHoneypot, map[string]any{"enabled": true}},
		{CmdHoneypot, map[string]any{"enabled": true, "ssh_port": float64(70000)}},
		{CmdHoneypot, map[string]any{"enabled": true, "ssh_port": float64(2222), "tcp_ports": []any{float64(2222)}}},
		{CmdHoneypot, map[string]any{"enabled": true, "tcp_ports": []any{"23"}}},
	}
	for _, c := range bad {
		if _, err := validateCommand(c.typ, c.in); err == nil {
			t.Errorf("%s %v: hata bekleniyordu", c.typ, c.in)
		}
	}
	p, _ := validateCommand(CmdAllowIP, map[string]any{"ip": "::ffff:10.0.0.1"})
	if p["ip"] != "10.0.0.1" {
		t.Errorf("ip normalize edilmedi: %v", p["ip"])
	}
}

func postCommand(t *testing.T, base, serverID string, body string) (int, store.Command) {
	t.Helper()
	resp, err := http.Post(base+"/api/v1/servers/"+serverID+"/commands", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var c store.Command
	if resp.StatusCode == http.StatusAccepted {
		_ = json.NewDecoder(resp.Body).Decode(&c)
	}
	return resp.StatusCode, c
}

func listCommands(t *testing.T, base, serverID string) []store.Command {
	t.Helper()
	resp, err := http.Get(base + "/api/v1/servers/" + serverID + "/commands")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []store.Command
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func dialAgent(t *testing.T, base, token string) *websocket.Conn {
	t.Helper()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(base, "http")+"/api/v1/agent", h)
	if err != nil {
		t.Fatalf("dial agent: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func readCommand(t *testing.T, conn *websocket.Conn) transport.Command {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var msg transport.AgentMessage
	if err := conn.ReadJSON(&msg); err != nil {
		t.Fatalf("read command: %v", err)
	}
	if msg.Kind != "command" || msg.Command == nil {
		t.Fatalf("beklenmeyen mesaj: %+v", msg)
	}
	return *msg.Command
}

func waitStatus(t *testing.T, base, serverID, id, want string) store.Command {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, c := range listCommands(t, base, serverID) {
			if c.ID == id && c.Status == want {
				return c
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("komut %s %s durumuna geçmedi", id, want)
	return store.Command{}
}

func TestCommandChannel(t *testing.T) {
	srv, _ := newTestServer(t)
	enrolled := enrollAgent(t, srv)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if code, _ := postCommand(t, ts.URL, "yok", `{"type":"block_ip","params":{"ip":"198.51.100.4"}}`); code != http.StatusNotFound {
		t.Fatalf("bilinmeyen sunucu: %d", code)
	}
	if code, _ := postCommand(t, ts.URL, enrolled.ServerID, `{"type":"block_ip","params":{"ip":"bozuk"}}`); code != http.StatusBadRequest {
		t.Fatalf("bozuk ip: %d", code)
	}

	// ajan bağlı değilken verilen komut kuyrukta bekler, bağlanınca gelir
	code, queued := postCommand(t, ts.URL, enrolled.ServerID, `{"type":"block_ip","params":{"ip":"198.51.100.4","ttl":"2h"}}`)
	if code != http.StatusAccepted || queued.Status != store.CommandPending {
		t.Fatalf("kuyruk: %d %+v", code, queued)
	}

	// geçersiz token reddedilir
	h := http.Header{}
	h.Set("Authorization", "Bearer yanlis")
	if _, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(ts.URL, "http")+"/api/v1/agent", h); err == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("yanlış token kabul edildi")
	}

	conn := dialAgent(t, ts.URL, enrolled.Token)
	got := readCommand(t, conn)
	if got.ID != queued.ID || got.Type != CmdBlockIP || got.Params["ttl"] != "2h0m0s" {
		t.Fatalf("kuyruktaki komut: %+v", got)
	}
	waitStatus(t, ts.URL, enrolled.ServerID, got.ID, store.CommandSent)

	if err := conn.WriteJSON(transport.AgentMessage{Kind: "result", Result: &transport.CommandResult{ID: got.ID, OK: true, Result: map[string]any{"backend": "nft"}}}); err != nil {
		t.Fatal(err)
	}
	done := waitStatus(t, ts.URL, enrolled.ServerID, got.ID, store.CommandDone)
	if done.Result["backend"] != "nft" || done.DoneAt == nil {
		t.Fatalf("sonuç kaydedilmedi: %+v", done)
	}

	// bağlıyken verilen komut anında gelir; başarısız sonuç hata metniyle saklanır
	_, live := postCommand(t, ts.URL, enrolled.ServerID, `{"type":"unblock_ip","params":{"ip":"198.51.100.4"}}`)
	got = readCommand(t, conn)
	if got.ID != live.ID {
		t.Fatalf("canlı komut: %+v", got)
	}
	_ = conn.WriteJSON(transport.AgentMessage{Kind: "result", Result: &transport.CommandResult{ID: got.ID, OK: false, Error: "kural yok"}})
	failed := waitStatus(t, ts.URL, enrolled.ServerID, got.ID, store.CommandFailed)
	if failed.Error != "kural yok" {
		t.Fatalf("hata metni: %+v", failed)
	}

	// durum mesajı sunucu listesine yansır
	_ = conn.WriteJSON(transport.AgentMessage{Kind: "status", Status: &transport.AgentStatus{Allow: []string{"203.0.113.9"}, Blocked: []string{}, Honeypot: &transport.HoneypotStatus{Enabled: true, SSHPort: 2222, Listening: []int{2222}}}})
	deadline := time.Now().Add(3 * time.Second)
	for {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil))
		var out []struct {
			Agent agentState `json:"agent"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) == 1 && out[0].Agent.Online && out[0].Agent.Status != nil && out[0].Agent.Status.Honeypot != nil && out[0].Agent.Status.Honeypot.SSHPort == 2222 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ajan durumu yansımadı: %s", rec.Body.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Başka bir sunucunun ajanı, ait olmadığı komutu kapatamaz.
func TestCommandResultScopedToServer(t *testing.T) {
	srv, st := newTestServer(t)
	a := enrollAgent(t, srv)
	b := enrollAgent(t, srv)
	c := store.Command{ID: transport.NewID(), ServerID: a.ServerID, Type: CmdAllowIP, Params: map[string]any{"ip": "198.51.100.8"}, Status: store.CommandPending, CreatedAt: time.Now()}
	if err := st.InsertCommand(c); err != nil {
		t.Fatal(err)
	}
	srv.onAgentMessage(b.ServerID, transport.AgentMessage{Kind: "result", Result: &transport.CommandResult{ID: c.ID, OK: true}})
	got, _, _ := st.GetCommand(c.ID)
	if got.Status != store.CommandPending {
		t.Fatalf("başka sunucunun sonucu kabul edildi: %+v", got)
	}
}
