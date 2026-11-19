// geogen, Natural Earth 1:110m ülke sınırlarından (public domain) panelin
// kullandığı iki gömülü veriyi üretir:
//
//   - internal/geo/centroids_gen.go: ISO 3166-1 alfa-2 kodu -> etiket noktası ve Türkçe ad
//   - web/dunya.js: 2B harita ızgarası ve 3B küre için kara noktaları
//   - web/sinirlar.js: ülke sınırı ve kıyı halkaları (SINIRLAR ve UYDU stilleri)
//
// Kaynak dosya depoya girmez; yeniden üretmek için:
//
//	curl -fsSLO https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_110m_admin_0_countries.geojson
//	go run ./tools/geogen -src ne_110m_admin_0_countries.geojson
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/format"
	"log"
	"math"
	"os"
	"sort"
	"strings"
)

type feature struct {
	Properties struct {
		ISO    string  `json:"ISO_A2_EH"`
		Name   string  `json:"NAME"`
		NameTR string  `json:"NAME_TR"`
		LX     float64 `json:"LABEL_X"`
		LY     float64 `json:"LABEL_Y"`
	} `json:"properties"`
	Geometry struct {
		Type        string          `json:"type"`
		Coordinates json.RawMessage `json:"coordinates"`
	} `json:"geometry"`
}

// ring: [lon, lat] köşe listesi
type ring [][2]float64

type poly struct {
	rings                  []ring // ilk halka dış sınır, kalanlar delik
	minX, minY, maxX, maxY float64
}

func (p *poly) contains(x, y float64) bool {
	if x < p.minX || x > p.maxX || y < p.minY || y > p.maxY {
		return false
	}
	in := false
	for _, r := range p.rings {
		for i, j := 0, len(r)-1; i < len(r); j, i = i, i+1 {
			xi, yi, xj, yj := r[i][0], r[i][1], r[j][0], r[j][1]
			if (yi > y) != (yj > y) && x < (xj-xi)*(y-yi)/(yj-yi)+xi {
				in = !in
			}
		}
	}
	return in
}

func newPoly(rs []ring) poly {
	p := poly{rings: rs, minX: 999, minY: 999, maxX: -999, maxY: -999}
	for _, c := range rs[0] {
		p.minX, p.maxX = math.Min(p.minX, c[0]), math.Max(p.maxX, c[0])
		p.minY, p.maxY = math.Min(p.minY, c[1]), math.Max(p.maxY, c[1])
	}
	return p
}

// 110m ölçekte bulunmayan, saldırı kaynağı olarak sık görülen küçük ülkeler.
var extra = map[string][3]any{
	"SG": {1.352, 103.82, "Singapur"},
	"HK": {22.32, 114.17, "Hong Kong"},
	"MO": {22.20, 113.55, "Makao"},
	"BH": {26.07, 50.55, "Bahreyn"},
	"MT": {35.90, 14.45, "Malta"},
	"MU": {-20.25, 57.55, "Mauritius"},
	"MV": {3.20, 73.22, "Maldivler"},
	"AD": {42.55, 1.58, "Andorra"},
	"MC": {43.74, 7.42, "Monako"},
	"LI": {47.16, 9.55, "Lihtenştayn"},
	"SM": {43.94, 12.46, "San Marino"},
	"SC": {-4.68, 55.49, "Seyşeller"},
	"BB": {13.19, -59.54, "Barbados"},
	"GI": {36.14, -5.35, "Cebelitarık"},
	"JE": {49.21, -2.13, "Jersey"},
	"GG": {49.45, -2.58, "Guernsey"},
	"IM": {54.24, -4.55, "Man Adası"},
}

func main() {
	src := flag.String("src", "ne_110m_admin_0_countries.geojson", "Natural Earth 110m ülkeler GeoJSON dosyası")
	goOut := flag.String("go", "internal/geo/centroids_gen.go", "ülke merkezleri Go çıktısı")
	jsOut := flag.String("js", "web/dunya.js", "kara noktaları JS çıktısı")
	bordersOut := flag.String("borders", "web/sinirlar.js", "ülke sınırları JS çıktısı")
	flag.Parse()

	b, err := os.ReadFile(*src)
	if err != nil {
		log.Fatal(err)
	}
	var fc struct {
		Features []feature `json:"features"`
	}
	if err := json.Unmarshal(b, &fc); err != nil {
		log.Fatal(err)
	}

	var polys []poly
	var rings []ring // tüm halkalar (Antarktika dahil, sınır çizimi için)
	type cen struct {
		lat, lon float64
		name     string
	}
	cens := map[string]cen{}
	for _, f := range fc.Features {
		var groups [][]ring
		switch f.Geometry.Type {
		case "Polygon":
			var rs []ring
			if err := json.Unmarshal(f.Geometry.Coordinates, &rs); err != nil {
				log.Fatal(err)
			}
			groups = append(groups, rs)
		case "MultiPolygon":
			if err := json.Unmarshal(f.Geometry.Coordinates, &groups); err != nil {
				log.Fatal(err)
			}
		}
		for _, g := range groups {
			rings = append(rings, g...)
		}
		iso := f.Properties.ISO
		if iso == "AQ" { // Antarktika haritada yer kaplar, saldırı kaynağı değildir
			continue
		}
		for _, g := range groups {
			polys = append(polys, newPoly(g))
		}
		if len(iso) == 2 && iso != "-9" {
			name := f.Properties.NameTR
			if name == "" {
				name = f.Properties.Name
			}
			cens[iso] = cen{f.Properties.LY, f.Properties.LX, name}
		}
	}
	for k, v := range extra {
		if _, ok := cens[k]; !ok {
			cens[k] = cen{v[0].(float64), v[1].(float64), v[2].(string)}
		}
	}
	land := func(lat, lon float64) bool {
		for i := range polys {
			if polys[i].contains(lon, lat) {
				return true
			}
		}
		return false
	}

	// 2B: eşit aralıklı ızgara (equirectangular), 1.5 derece
	var flat []int
	const step = 1.5
	for lat := 82.5; lat >= -56; lat -= step {
		for lon := -180 + step/2; lon < 180; lon += step {
			if land(lat, lon) {
				flat = append(flat, int(math.Round(lat*10)), int(math.Round(lon*10)))
			}
		}
	}
	// 3B: Fibonacci küresi, yüzeye eşit dağılır
	var globe []int
	const nf = 26000
	ga := math.Pi * (3 - math.Sqrt(5))
	for i := 0; i < nf; i++ {
		y := 1 - (float64(i)+0.5)/nf*2
		lat := math.Asin(y) * 180 / math.Pi
		lon := math.Mod(float64(i)*ga*180/math.Pi, 360) - 180
		if lat < -60 {
			continue
		}
		if land(lat, lon) {
			globe = append(globe, int(math.Round(lat*10)), int(math.Round(lon*10)))
		}
	}

	var js bytes.Buffer
	js.WriteString("/* Üretildi: go run ./tools/geogen. Kaynak: Natural Earth 1:110m (public domain).\n")
	js.WriteString("   Değerler derece x 10, [enlem, boylam] çiftleri halinde. */\n")
	fmt.Fprintf(&js, "window.NEXGEO={flatStep:%g,flat:%s,globe:%s};\n", step, ints(flat), ints(globe))
	if err := os.WriteFile(*jsOut, js.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}

	// sınırlar: her halka [boylam, enlem] x 100 tam sayı dizisi
	var bj bytes.Buffer
	bj.WriteString("/* Üretildi: go run ./tools/geogen. Kaynak: Natural Earth 1:110m (public domain).\n")
	bj.WriteString("   Her halka [boylam, enlem] x 100 çiftleri; ülke sınırları ve kıyılar. */\n")
	bj.WriteString("window.NEXBORDERS=[")
	nv := 0
	for i, r := range rings {
		if i > 0 {
			bj.WriteByte(',')
		}
		v := make([]int, 0, len(r)*2)
		for _, c := range r {
			v = append(v, int(math.Round(c[0]*100)), int(math.Round(c[1]*100)))
		}
		nv += len(r)
		bj.WriteString(ints(v))
	}
	bj.WriteString("];\n")
	if err := os.WriteFile(*bordersOut, bj.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("geogen: %d halka, %d köşe", len(rings), nv)

	keys := make([]string, 0, len(cens))
	for k := range cens {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var g bytes.Buffer
	g.WriteString("// Code generated by tools/geogen; DO NOT EDIT.\n// Kaynak: Natural Earth 1:110m ülke etiket noktaları (public domain).\n\npackage geo\n\n")
	g.WriteString("var centroids = map[string]Country{\n")
	for _, k := range keys {
		c := cens[k]
		fmt.Fprintf(&g, "\t%q: {Code: %q, Name: %q, Lat: %.3f, Lon: %.3f},\n", k, k, c.name, c.lat, c.lon)
	}
	g.WriteString("}\n")
	src2, err := format.Source(g.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*goOut, src2, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("geogen: %d ülke, 2B %d nokta, 3B %d nokta", len(cens), len(flat)/2, len(globe)/2)
}

func ints(v []int) string {
	var sb strings.Builder
	sb.WriteByte('[')
	for i, n := range v {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "%d", n)
	}
	sb.WriteByte(']')
	return sb.String()
}
