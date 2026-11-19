// Package honeypot, ajanın açabildiği iki düşük etkileşimli tuzağı içerir:
//
//   - Sahte SSH: gerçek bir OpenSSH gibi el sıkışır, her kimlik doğrulama
//     denemesini (kullanıcı, şifre, anahtar türü) kaydeder ve hiçbirini kabul
//     etmez. Kabuk, komut ya da kanal açılmaz.
//   - TCP tuzağı: seçilen portları dinler, istemcinin ilk baytlarını kısa bir
//     süre okuyup kaydeder ve bağlantıyı kapatır.
//
// Tuzaklara meşru bir istemcinin bağlanması için sebep yoktur; bu yüzden her
// dokunuş yüksek önemli bulgudur. Kaynak tüketimi sınırlıdır: eşzamanlı
// bağlantı sayısı, IP başına bağlantı ve bağlantı başına süre kısıtlıdır.
package honeypot

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"nexguard/internal/transport"
)

// Config panelden gelen honeypot ayarıdır; ajan durum dosyasında saklanır.
type Config struct {
	Enabled   bool  `yaml:"enabled" json:"enabled"`
	SSHPort   int   `yaml:"ssh_port" json:"ssh_port"`
	TCPPorts  []int `yaml:"tcp_ports" json:"tcp_ports"`
	AutoBlock bool  `yaml:"auto_block" json:"auto_block"`
}

// Hit tuzağa tek bir dokunuştur.
type Hit struct {
	Kind     string // "ssh" ya da "tcp"
	IP       string
	Port     int
	Method   string // ssh: connect, password, publickey, keyboard-interactive
	User     string
	Password string
	Client   string // ssh istemci sürümü
	Payload  string // tcp: ilk baytlar, kaçışlanmış
	At       time.Time
}

const (
	// SSHBanner Debian 12'nin varsayılan OpenSSH sürümüdür; tarayıcılar
	// genelde sürüme bakarak hedef seçer.
	SSHBanner     = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
	maxConns      = 64
	maxPerIP      = 4
	sshDeadline   = 30 * time.Second
	tcpReadWait   = 5 * time.Second
	maxPayload    = 512
	maxFieldBytes = 64
)

type Manager struct {
	// HostKeyPath sahte SSH'nin kalıcı ed25519 anahtarıdır; yoksa üretilir.
	// Anahtar her açılışta değişseydi tarayıcılar bunu tuzak işareti sayardı.
	HostKeyPath string
	// Bind dinlenecek adres (boş: tüm arayüzler). Testlerde 127.0.0.1.
	Bind  string
	OnHit func(Hit)

	mu        sync.Mutex
	cfg       Config
	listeners map[int]net.Listener
	kinds     map[int]string
	errs      map[int]string
	sshConf   *ssh.ServerConfig
	sem       chan struct{}
	perIP     map[string]int
	hits      atomic.Int64
}

func (m *Manager) init() {
	if m.listeners == nil {
		m.listeners = map[int]net.Listener{}
		m.kinds = map[int]string{}
		m.errs = map[int]string{}
		m.perIP = map[string]int{}
		m.sem = make(chan struct{}, maxConns)
	}
}

// Apply ayarı uygular: gereksiz dinleyicileri kapatır, yenilerini açar.
// Açılamayan portlar (izin yok, kullanımda) hata olarak durumda raporlanır;
// diğer portlar çalışmaya devam eder.
func (m *Manager) Apply(cfg Config) transport.HoneypotStatus {
	m.mu.Lock()
	m.init()
	m.cfg = cfg
	want := map[int]string{}
	if cfg.Enabled {
		if cfg.SSHPort > 0 {
			want[cfg.SSHPort] = "ssh"
		}
		for _, p := range cfg.TCPPorts {
			if p > 0 && want[p] == "" {
				want[p] = "tcp"
			}
		}
	}
	for p, ln := range m.listeners {
		if want[p] != m.kinds[p] {
			ln.Close()
			delete(m.listeners, p)
			delete(m.kinds, p)
		}
	}
	m.errs = map[int]string{}
	for p, kind := range want {
		if _, ok := m.listeners[p]; ok {
			continue
		}
		if kind == "ssh" && m.sshConf == nil {
			conf, err := m.newSSHConfig()
			if err != nil {
				m.errs[p] = err.Error()
				continue
			}
			m.sshConf = conf
		}
		ln, err := net.Listen("tcp", net.JoinHostPort(m.Bind, strconv.Itoa(p)))
		if err != nil {
			m.errs[p] = friendlyListenErr(err, p)
			continue
		}
		m.listeners[p] = ln
		m.kinds[p] = kind
		go m.serve(ln, p, kind)
	}
	m.mu.Unlock()
	return m.Status()
}

func friendlyListenErr(err error, port int) string {
	switch {
	case errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "permission denied"):
		return fmt.Sprintf("%d portu için yetki yok (1024 altı portlar CAP_NET_BIND_SERVICE ister)", port)
	case strings.Contains(err.Error(), "address already in use"):
		return fmt.Sprintf("%d portu başka bir servis tarafından kullanılıyor", port)
	}
	return err.Error()
}

func (m *Manager) Status() transport.HoneypotStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.init()
	st := transport.HoneypotStatus{
		Enabled:   m.cfg.Enabled,
		SSHPort:   m.cfg.SSHPort,
		TCPPorts:  append([]int{}, m.cfg.TCPPorts...),
		AutoBlock: m.cfg.AutoBlock,
		Listening: []int{},
		Hits:      int(m.hits.Load()),
	}
	for p := range m.listeners {
		st.Listening = append(st.Listening, p)
	}
	sort.Ints(st.Listening)
	if len(m.errs) > 0 {
		st.Errors = map[string]string{}
		for p, e := range m.errs {
			st.Errors[strconv.Itoa(p)] = e
		}
	}
	return st
}

func (m *Manager) Close() {
	m.Apply(Config{})
}

func (m *Manager) emit(h Hit) {
	m.hits.Add(1)
	if m.OnHit != nil {
		m.OnHit(h)
	}
}

// acquire eşzamanlı bağlantı sınırlarını uygular.
func (m *Manager) acquire(ip string) bool {
	select {
	case m.sem <- struct{}{}:
	default:
		return false
	}
	m.mu.Lock()
	if m.perIP[ip] >= maxPerIP {
		m.mu.Unlock()
		<-m.sem
		return false
	}
	m.perIP[ip]++
	m.mu.Unlock()
	return true
}

func (m *Manager) release(ip string) {
	m.mu.Lock()
	if m.perIP[ip]--; m.perIP[ip] <= 0 {
		delete(m.perIP, ip)
	}
	m.mu.Unlock()
	<-m.sem
}

func (m *Manager) serve(ln net.Listener, port int, kind string) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return // dinleyici kapatıldı
		}
		ip := remoteIP(conn.RemoteAddr())
		if !m.acquire(ip) {
			conn.Close()
			continue
		}
		go func() {
			defer m.release(ip)
			defer conn.Close()
			if kind == "ssh" {
				m.handleSSH(conn, ip, port)
			} else {
				m.handleTCP(conn, ip, port)
			}
		}()
	}
}

func remoteIP(a net.Addr) string {
	if ta, ok := a.(*net.TCPAddr); ok {
		if v4 := ta.IP.To4(); v4 != nil {
			return v4.String()
		}
		return ta.IP.String()
	}
	host, _, _ := net.SplitHostPort(a.String())
	return host
}

func (m *Manager) handleTCP(conn net.Conn, ip string, port int) {
	_ = conn.SetDeadline(time.Now().Add(tcpReadWait))
	buf := make([]byte, maxPayload)
	n, _ := conn.Read(buf)
	m.emit(Hit{Kind: "tcp", IP: ip, Port: port, Method: "connect", Payload: Escape(buf[:n], 160), At: time.Now().UTC()})
}

func (m *Manager) handleSSH(conn net.Conn, ip string, port int) {
	_ = conn.SetDeadline(time.Now().Add(sshDeadline))
	m.mu.Lock()
	base := m.sshConf
	m.mu.Unlock()
	if base == nil {
		return
	}
	var once sync.Once
	connected := func(client string) {
		once.Do(func() {
			m.emit(Hit{Kind: "ssh", IP: ip, Port: port, Method: "connect", Client: client, At: time.Now().UTC()})
		})
	}
	ver := func(meta ssh.ConnMetadata) string { v := clip(string(meta.ClientVersion())); connected(v); return v }
	conf := *base
	conf.PasswordCallback = func(meta ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		v := ver(meta)
		m.emit(Hit{Kind: "ssh", IP: ip, Port: port, Method: "password", User: clip(meta.User()), Password: clip(string(pw)), Client: v, At: time.Now().UTC()})
		time.Sleep(400 * time.Millisecond) // gerçek sshd gibi yavaş ret
		return nil, errors.New("permission denied")
	}
	conf.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		v := ver(meta)
		m.emit(Hit{Kind: "ssh", IP: ip, Port: port, Method: "publickey", User: clip(meta.User()), Password: key.Type() + " " + ssh.FingerprintSHA256(key), Client: v, At: time.Now().UTC()})
		return nil, errors.New("permission denied")
	}
	conf.KeyboardInteractiveCallback = func(meta ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
		v := ver(meta)
		ans, err := ch("", "", []string{"Password: "}, []bool{false})
		if err == nil && len(ans) == 1 {
			m.emit(Hit{Kind: "ssh", IP: ip, Port: port, Method: "keyboard-interactive", User: clip(meta.User()), Password: clip(ans[0]), Client: v, At: time.Now().UTC()})
		}
		time.Sleep(400 * time.Millisecond)
		return nil, errors.New("permission denied")
	}
	conf.AuthLogCallback = func(meta ssh.ConnMetadata, method string, err error) { ver(meta) }
	sc, chans, reqs, err := ssh.NewServerConn(conn, &conf)
	if err != nil {
		// el sıkışma kimlik doğrulamaya varmadan bittiyse (yalnız banner okuyan
		// tarayıcılar) bağlantı yine de bir kez sayılır
		connected("")
		return
	}
	// Buraya ulaşılamaz (hiçbir doğrulama kabul edilmez); yine de güvenli kapat.
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		_ = nc.Reject(ssh.Prohibited, "denied")
	}
	sc.Close()
}

func (m *Manager) newSSHConfig() (*ssh.ServerConfig, error) {
	signer, err := loadOrCreateHostKey(m.HostKeyPath)
	if err != nil {
		return nil, err
	}
	conf := &ssh.ServerConfig{ServerVersion: SSHBanner, MaxAuthTries: 6}
	conf.AddHostKey(signer)
	return conf, nil
}

func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			s, err := ssh.ParsePrivateKey(b)
			if err != nil {
				return nil, fmt.Errorf("honeypot host key %s: %w", path, err)
			}
			return s, nil
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if path != "" {
		blk, err := ssh.MarshalPrivateKey(priv, "nexguard-honeypot")
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("honeypot host key dir: %w", err)
		}
		if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
			return nil, fmt.Errorf("honeypot host key write: %w", err)
		}
	}
	return ssh.NewSignerFromKey(priv)
}

func clip(s string) string {
	if len(s) > maxFieldBytes {
		s = s[:maxFieldBytes]
	}
	return Escape([]byte(s), maxFieldBytes*4)
}

// Escape yazdırılamayan baytları \xNN olarak kaçışlar ve uzunluğu sınırlar;
// saldırganın yolladığı veri panele ham haliyle gitmez.
func Escape(b []byte, max int) string {
	var sb strings.Builder
	for _, c := range b {
		if sb.Len() >= max {
			sb.WriteString("…")
			break
		}
		switch {
		case c == '\\':
			sb.WriteString(`\\`)
		case c >= 0x20 && c < 0x7f:
			sb.WriteByte(c)
		case c == '\n':
			sb.WriteString(`\n`)
		case c == '\r':
			sb.WriteString(`\r`)
		default:
			fmt.Fprintf(&sb, `\x%02x`, c)
		}
	}
	return sb.String()
}
