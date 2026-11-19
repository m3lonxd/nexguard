package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"nexguard/internal/geo"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		remote, real, xff, want string
	}{
		{"198.51.100.9:5000", "", "", "198.51.100.9"},
		// başka bir makineden gelen başlığa güvenilmez
		{"198.51.100.9:5000", "8.8.8.8", "1.1.1.1", "198.51.100.9"},
		// aynı makinedeki nginx bildirirse gerçek adres alınır
		{"127.0.0.1:41000", "8.8.8.8", "", "8.8.8.8"},
		{"127.0.0.1:41000", "", "1.1.1.1, 10.0.0.2", "1.1.1.1"},
		{"127.0.0.1:41000", "bozuk", "", "127.0.0.1"},
		{"[::1]:41000", "", "", "::1"},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		if c.real != "" {
			r.Header.Set("X-Real-IP", c.real)
		}
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r); got != c.want {
			t.Errorf("clientIP(%s, real=%q, xff=%q) = %s, want %s", c.remote, c.real, c.xff, got, c.want)
		}
	}
}

type geoResp struct {
	Enabled bool                   `json:"enabled"`
	IPs     map[string]geo.Country `json:"ips"`
}

func getGeo(t *testing.T, srv *Server, q string) (int, geoResp) {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/geo"+q, nil))
	var g geoResp
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil {
			t.Fatalf("decode geo: %v", err)
		}
	}
	return rec.Code, g
}

func TestGeoDisabled(t *testing.T) {
	srv, _ := newTestServer(t)
	code, g := getGeo(t, srv, "?ip=8.8.8.8")
	if code != http.StatusOK || g.Enabled || len(g.IPs) != 0 {
		t.Fatalf("konum verisi yokken boş yanıt bekleniyordu: %d %+v", code, g)
	}
}

func TestGeoTooMany(t *testing.T) {
	srv, _ := newTestServer(t)
	q := "?"
	for i := 0; i <= maxGeoIPs; i++ {
		q += "ip=1.1.1.1&"
	}
	if code, _ := getGeo(t, srv, q); code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", code)
	}
}

func TestServersGeoHomeFallback(t *testing.T) {
	srv, _ := newTestServer(t)
	tr, _ := geo.ByCode("TR")
	srv.SetGeo(nil, &tr)
	enrollAgent(t, srv) // httptest adresi 192.0.2.1: çözülemez, merkez konuma düşer

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/servers", nil))
	var out []struct {
		IP  string       `json:"ip"`
		Geo *geo.Country `json:"geo"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 || out[0].IP != "192.0.2.1" || out[0].Geo == nil || out[0].Geo.Code != "TR" {
		t.Fatalf("beklenmeyen sunucu listesi: %s", rec.Body.String())
	}
}

func TestGeoWithDB(t *testing.T) {
	path := "../../data/dbip-country-lite.mmdb"
	if _, err := os.Stat(path); err != nil {
		t.Skip("data/dbip-country-lite.mmdb yok")
	}
	r, err := geo.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	srv, _ := newTestServer(t)
	srv.SetGeo(r, nil)
	code, g := getGeo(t, srv, "?ip=8.8.8.8&ip=192.0.2.14&ip=bozuk")
	if code != http.StatusOK || !g.Enabled || len(g.IPs) != 1 || g.IPs["8.8.8.8"].Code != "US" {
		t.Fatalf("beklenmeyen yanıt: %d %+v", code, g)
	}
}
