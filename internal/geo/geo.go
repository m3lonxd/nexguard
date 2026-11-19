// Package geo, IP adreslerini ülke düzeyinde konumlandırır. Ülke kodu DB-IP
// "IP to Country Lite" mmdb dosyasından (CC BY 4.0, https://db-ip.com) okunur;
// koordinat olarak Natural Earth ülke etiket noktası kullanılır.
//
// Dosya verilmezse ya da açılamazsa Resolver hiçbir adresi çözmez; panel
// haritayı konumsuz gösterir. Özel, yerel ve belgelendirme aralıkları her
// zaman çözülmez.
package geo

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/oschwald/maxminddb-golang"
)

// Country bir ülkenin harita üzerindeki temsil noktasıdır.
type Country struct {
	Code string  `json:"cc"`
	Name string  `json:"name"`
	Lat  float64 `json:"lat"`
	Lon  float64 `json:"lon"`
}

// Resolver eşzamanlı kullanıma uygundur.
type Resolver struct {
	db *maxminddb.Reader
}

// Open mmdb dosyasını belleğe eşler. path boşsa nil hata ve çözmeyen bir
// Resolver döner.
func Open(path string) (*Resolver, error) {
	if path == "" {
		return &Resolver{}, nil
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return &Resolver{}, fmt.Errorf("geo: open %s: %w", path, err)
	}
	return &Resolver{db: db}, nil
}

// Enabled konum verisi yüklüyse true döner.
func (r *Resolver) Enabled() bool { return r != nil && r.db != nil }

func (r *Resolver) Close() error {
	if r == nil || r.db == nil {
		return nil
	}
	return r.db.Close()
}

// Lookup adresin ülkesini döner. Ayrıştırılamayan, genel internette
// yönlendirilmeyen ya da veritabanında bulunmayan adresler için false döner.
func (r *Resolver) Lookup(ip string) (Country, bool) {
	if !r.Enabled() {
		return Country{}, false
	}
	a, err := netip.ParseAddr(ip)
	if err != nil || !Public(a) {
		return Country{}, false
	}
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := r.db.Lookup(net.IP(a.AsSlice()), &rec); err != nil || rec.Country.ISOCode == "" {
		return Country{}, false
	}
	return ByCode(rec.Country.ISOCode)
}

// ByCode ISO 3166-1 alfa-2 koduna göre ülke noktasını döner.
func ByCode(code string) (Country, bool) {
	c, ok := centroids[code]
	return c, ok
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protokol atamaları
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // kıyaslama
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), // IPv6 belgelendirme
}

// Public adres genel internette yönlendirilebilir bir tekil adresse true döner.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
