package geo

import (
	"net/netip"
	"os"
	"testing"
)

func TestPublic(t *testing.T) {
	cases := map[string]bool{
		"8.8.8.8":         true,
		"1.1.1.1":         true,
		"127.0.0.1":       false,
		"10.1.2.3":        false,
		"192.168.1.10":    false,
		"172.16.4.4":      false,
		"100.64.0.1":      false,
		"192.0.2.14":      false,
		"203.0.113.7":     false,
		"::1":             false,
		"fe80::1":         false,
		"2001:db8::1":     false,
		"2606:4700::1":    true,
		"::ffff:10.0.0.1": false,
	}
	for ip, want := range cases {
		if got := Public(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Public(%s) = %v, want %v", ip, got, want)
		}
	}
}

func TestByCode(t *testing.T) {
	c, ok := ByCode("TR")
	if !ok || c.Name != "Türkiye" || c.Lat < 36 || c.Lat > 42 || c.Lon < 26 || c.Lon > 45 {
		t.Fatalf("ByCode(TR) = %+v, %v", c, ok)
	}
	for _, code := range []string{"SG", "HK", "US", "CN", "RU", "DE", "NL", "BR", "IN"} {
		if _, ok := ByCode(code); !ok {
			t.Errorf("ByCode(%s) bulunamadı", code)
		}
	}
	if _, ok := ByCode("ZZ"); ok {
		t.Error("ByCode(ZZ) bulunmamalı")
	}
}

func TestDisabledResolver(t *testing.T) {
	r, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	if r.Enabled() {
		t.Fatal("boş yol ile Enabled olmamalı")
	}
	if _, ok := r.Lookup("8.8.8.8"); ok {
		t.Fatal("kapalı resolver çözmemeli")
	}
	if _, err := Open("/yok/boyle/dosya.mmdb"); err == nil {
		t.Fatal("olmayan dosya hata vermeli")
	}
}

// Gerçek veritabanıyla uçtan uca deneme; dosya yoksa atlanır.
func TestLookupWithDB(t *testing.T) {
	path := "../../data/dbip-country-lite.mmdb"
	if _, err := os.Stat(path); err != nil {
		t.Skip("data/dbip-country-lite.mmdb yok")
	}
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	c, ok := r.Lookup("8.8.8.8")
	if !ok || c.Code != "US" {
		t.Fatalf("8.8.8.8 = %+v, %v; US bekleniyordu", c, ok)
	}
	if _, ok := r.Lookup("192.0.2.14"); ok {
		t.Fatal("belgelendirme adresi çözülmemeli")
	}
	if _, ok := r.Lookup("bozuk"); ok {
		t.Fatal("bozuk adres çözülmemeli")
	}
}
