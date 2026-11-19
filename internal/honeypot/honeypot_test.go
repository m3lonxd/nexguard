package honeypot

import (
	"net"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"nexguard/internal/transport"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type hitLog struct {
	mu   sync.Mutex
	hits []Hit
}

func (h *hitLog) add(x Hit) { h.mu.Lock(); h.hits = append(h.hits, x); h.mu.Unlock() }
func (h *hitLog) wait(t *testing.T, ok func([]Hit) bool) []Hit {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		cp := append([]Hit{}, h.hits...)
		h.mu.Unlock()
		if ok(cp) {
			return cp
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	t.Fatalf("beklenen dokunuşlar gelmedi: %+v", h.hits)
	return nil
}

func newManager(t *testing.T, log *hitLog) *Manager {
	t.Helper()
	m := &Manager{HostKeyPath: filepath.Join(t.TempDir(), "hp_ed25519"), Bind: "127.0.0.1", OnHit: log.add}
	t.Cleanup(m.Close)
	return m
}

func TestSSHHoneypotRecordsCredentialsAndRejects(t *testing.T) {
	log := &hitLog{}
	m := newManager(t, log)
	port := freePort(t)
	st := m.Apply(Config{Enabled: true, SSHPort: port})
	if len(st.Listening) != 1 || st.Listening[0] != port || len(st.Errors) != 0 {
		t.Fatalf("status = %+v", st)
	}

	var serverVersion string
	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("toor")},
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error { return nil },
		BannerCallback:  func(string) error { return nil },
		Timeout:         5 * time.Second,
	}
	c, err := ssh.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port), cfg)
	if err == nil {
		c.Close()
		t.Fatal("honeypot bir girişi kabul etti")
	}
	hits := log.wait(t, func(h []Hit) bool {
		for _, x := range h {
			if x.Method == "password" {
				return true
			}
		}
		return false
	})
	var pw Hit
	connects := 0
	for _, x := range hits {
		if x.Method == "password" {
			pw = x
		}
		if x.Method == "connect" {
			connects++
		}
	}
	if pw.User != "root" || pw.Password != "toor" || pw.IP != "127.0.0.1" || pw.Port != port || pw.Kind != "ssh" {
		t.Fatalf("password hit = %+v", pw)
	}
	if pw.Client == "" {
		t.Fatalf("istemci sürümü kaydedilmedi: %+v", pw)
	}
	if connects != 1 {
		t.Fatalf("bağlantı bir kez sayılmalı, %d kez sayıldı", connects)
	}

	// sunucu sürümü OpenSSH gibi görünür
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := conn.Read(buf)
	conn.Close()
	serverVersion = string(buf[:n])
	if serverVersion[:len(SSHBanner)] != SSHBanner {
		t.Fatalf("banner = %q", serverVersion)
	}
}

func TestHostKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	a, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := loadOrCreateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if ssh.FingerprintSHA256(a.PublicKey()) != ssh.FingerprintSHA256(b.PublicKey()) {
		t.Fatal("host anahtarı yeniden açılışta değişti")
	}
}

func TestTCPTrapAndDisable(t *testing.T) {
	log := &hitLog{}
	m := newManager(t, log)
	port := freePort(t)
	m.Apply(Config{Enabled: true, TCPPorts: []int{port}})
	addr := "127.0.0.1:" + strconv.Itoa(port)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\n\x00\xff"))
	_ = conn.SetReadDeadline(time.Now().Add(6 * time.Second))
	_, _ = conn.Read(make([]byte, 1)) // tuzak kapatana kadar
	conn.Close()
	hits := log.wait(t, func(h []Hit) bool { return len(h) > 0 })
	if hits[0].Kind != "tcp" || hits[0].Payload != `GET / HTTP/1.0\r\n\x00\xff` {
		t.Fatalf("tcp hit = %+v", hits[0])
	}

	st := m.Apply(Config{Enabled: false, TCPPorts: []int{port}})
	if len(st.Listening) != 0 {
		t.Fatalf("kapatınca dinleme sürüyor: %+v", st)
	}
	if c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("kapatılan tuzak hâlâ bağlantı kabul ediyor")
	}
}

func TestPortConflictReported(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	busy := ln.Addr().(*net.TCPAddr).Port
	free := freePort(t)
	m := newManager(t, &hitLog{})
	st := m.Apply(Config{Enabled: true, TCPPorts: []int{busy, free}})
	if len(st.Listening) != 1 || st.Listening[0] != free {
		t.Fatalf("boş port açılmalıydı: %+v", st)
	}
	if st.Errors[strconv.Itoa(busy)] == "" {
		t.Fatalf("dolu port hatası raporlanmadı: %+v", st)
	}
}

func TestEscape(t *testing.T) {
	if got := Escape([]byte("a\\b\x01\n"), 100); got != `a\\b\x01\n` {
		t.Fatalf("Escape = %q", got)
	}
	if got := Escape([]byte("abcdef"), 3); got != "abc…" {
		t.Fatalf("Escape limit = %q", got)
	}
}

func TestReporterAggregates(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	var got []transport.Finding
	r := NewReporter(func(f transport.Finding) { got = append(got, f) })
	r.Now = func() time.Time { return now }

	r.Add(Hit{Kind: "ssh", IP: "198.51.100.4", Port: 2222, Method: "connect", Client: "SSH-2.0-libssh"})
	r.Add(Hit{Kind: "ssh", IP: "198.51.100.4", Port: 2222, Method: "password", User: "root", Password: "123456"})
	r.Add(Hit{Kind: "ssh", IP: "198.51.100.4", Port: 2222, Method: "password", User: "admin", Password: "admin"})
	r.Flush()
	if len(got) != 0 {
		t.Fatal("ilk gecikme dolmadan bulgu üretildi")
	}
	now = now.Add(3 * time.Second)
	r.Flush()
	if len(got) != 1 {
		t.Fatalf("ilk bulgu bekleniyordu, %d", len(got))
	}
	f := got[0]
	creds := f.Evidence["credentials"].([]map[string]any)
	if f.Type != "honeypot_ssh" || f.Severity != "high" || f.Evidence["attempts"] != 2 || len(creds) != 2 || f.Evidence["client"] != "SSH-2.0-libssh" {
		t.Fatalf("bulgu = %+v", f)
	}

	// bir dakika dolmadan gelenler birikir
	r.Add(Hit{Kind: "tcp", IP: "198.51.100.4", Port: 23, Method: "connect", Payload: "root"})
	now = now.Add(30 * time.Second)
	r.Flush()
	if len(got) != 1 {
		t.Fatal("aralık dolmadan ikinci bulgu üretildi")
	}
	now = now.Add(31 * time.Second)
	r.Flush()
	if len(got) != 2 || got[1].Type != "honeypot_tcp" || got[1].Evidence["payload"] != "root" {
		t.Fatalf("ikinci bulgu = %+v", got)
	}
}
