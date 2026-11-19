package honeypot

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"nexguard/internal/transport"
)

// Reporter tuzak dokunuşlarını IP başına toplayıp bulguya çevirir. Bir IP'nin
// ilk dokunuşu FirstDelay sonra (aynı bağlantının denemeleri birikene kadar),
// sonraki dokunuşları en fazla Every aralıkla tek bulgu olarak raporlanır.
type Reporter struct {
	FirstDelay time.Duration
	Every      time.Duration
	Emit       func(transport.Finding)
	Now        func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type cred struct{ User, Password, Method string }

type bucket struct {
	first, last, lastEmit time.Time
	count                 int // bu raporda toplam dokunuş (bağlantı + deneme)
	conns, tries          int
	ssh                   bool
	ports                 map[int]bool
	creds                 []cred
	client, payload       string
}

const maxCreds = 20

func NewReporter(emit func(transport.Finding)) *Reporter {
	return &Reporter{FirstDelay: 2 * time.Second, Every: time.Minute, Emit: emit, buckets: map[string]*bucket{}}
}

func (r *Reporter) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Add bir dokunuşu kaydeder; eşzamanlı çağrılabilir.
func (r *Reporter) Add(h Hit) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buckets == nil {
		r.buckets = map[string]*bucket{}
	}
	b := r.buckets[h.IP]
	if b == nil {
		b = &bucket{ports: map[int]bool{}}
		r.buckets[h.IP] = b
	}
	now := r.now()
	if b.count == 0 {
		b.first = now
	}
	b.last = now
	b.ports[h.Port] = true
	if h.Kind == "ssh" {
		b.ssh = true
	}
	if h.Client != "" {
		b.client = h.Client
	}
	if h.Payload != "" && b.payload == "" {
		b.payload = h.Payload
	}
	b.count++
	if h.Method == "connect" {
		b.conns++
		return
	}
	b.tries++
	if len(b.creds) < maxCreds {
		c := cred{h.User, h.Password, h.Method}
		for _, x := range b.creds {
			if x == c {
				return
			}
		}
		b.creds = append(b.creds, c)
	}
}

// Flush zamanı gelen kovaları bulguya çevirir. Ajan bunu saniyede bir çağırır.
func (r *Reporter) Flush() {
	now := r.now()
	var out []transport.Finding
	r.mu.Lock()
	for ip, b := range r.buckets {
		if b.count == 0 {
			if now.Sub(b.lastEmit) > time.Hour {
				delete(r.buckets, ip)
			}
			continue
		}
		due := (b.lastEmit.IsZero() && now.Sub(b.first) >= r.FirstDelay) ||
			(!b.lastEmit.IsZero() && now.Sub(b.lastEmit) >= r.Every && now.Sub(b.first) >= r.FirstDelay)
		if !due {
			continue
		}
		out = append(out, b.finding(ip, now))
		b.lastEmit = now
		b.count, b.conns, b.tries, b.creds, b.payload = 0, 0, 0, nil, ""
		b.ports = map[int]bool{}
		b.ssh = false
	}
	r.mu.Unlock()
	for _, f := range out {
		if r.Emit != nil {
			r.Emit(f)
		}
	}
}

func (b *bucket) finding(ip string, now time.Time) transport.Finding {
	ports := make([]int, 0, len(b.ports))
	for p := range b.ports {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	typ, kind := "honeypot_tcp", "TCP"
	if b.ssh {
		typ, kind = "honeypot_ssh", "SSH"
	}
	users := []string{}
	creds := make([]map[string]any, 0, len(b.creds))
	seen := map[string]bool{}
	for _, c := range b.creds {
		creds = append(creds, map[string]any{"user": c.User, "password": c.Password, "method": c.Method})
		if c.User != "" && !seen[c.User] {
			seen[c.User] = true
			users = append(users, c.User)
		}
	}
	ps := make([]string, len(ports))
	for i, p := range ports {
		ps[i] = fmt.Sprint(p)
	}
	// deneme: giriş denemesi varsa onların sayısı, yoksa bağlantı sayısı
	attempts := b.tries
	if attempts == 0 {
		attempts = b.conns
	}
	summary := fmt.Sprintf("Honeypot: %s, %s tuzağına (%s) %d bağlantı, %d giriş denemesi", ip, kind, strings.Join(ps, ", "), b.conns, b.tries)
	ev := map[string]any{
		"ip":          ip,
		"attempts":    attempts,
		"connections": b.conns,
		"honeypot":    strings.ToLower(kind),
		"ports":       ports,
		"credentials": creds,
		"users_tried": users,
		"first_seen":  b.first.UTC().Format(time.RFC3339),
	}
	if b.client != "" {
		ev["client"] = b.client
	}
	if b.payload != "" {
		ev["payload"] = b.payload
	}
	return transport.Finding{
		ID:        transport.NewID(),
		Type:      typ,
		Severity:  "high",
		Summary:   summary,
		Evidence:  ev,
		CreatedAt: now.UTC(),
	}
}
