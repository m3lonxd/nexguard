package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nexguard/internal/api"
	"nexguard/internal/geo"
	"nexguard/internal/store"
	"nexguard/web"
)

func main() {
	addr := flag.String("addr", ":8842", "listen address")
	dbPath := flag.String("db", "./nexguard.db", "path to the SQLite database file")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (enables HTTPS together with -tls-key)")
	tlsKey := flag.String("tls-key", "", "TLS key file (enables HTTPS together with -tls-cert)")
	geoPath := flag.String("geoip", "", "DB-IP IP to Country Lite mmdb dosyası (saldırı haritası için; boşsa konum gösterilmez)")
	home := flag.String("home", "", "adresi çözülemeyen sunucuların harita konumu: \"enlem,boylam\" ya da ülke kodu (ör. TR)")
	flag.Parse()

	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("-tls-cert and -tls-key must be set together")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	gr, err := geo.Open(*geoPath)
	if err != nil {
		log.Printf("geo: %v; harita konumsuz çalışacak", err)
	}
	defer gr.Close()
	homeLoc, err := parseHome(*home)
	if err != nil {
		log.Fatalf("-home: %v", err)
	}

	apiSrv := api.New(st)
	apiSrv.SetGeo(gr, homeLoc)
	mux := http.NewServeMux()
	mux.Handle("/api/v1/", apiSrv.Handler())
	mux.Handle("/", http.FileServer(http.FS(web.FS)))

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if *tlsCert != "" {
			log.Printf("nexguard-serverd listening on %s (TLS)", *addr)
			errCh <- httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
			return
		}
		log.Printf("nexguard-serverd listening on %s", *addr)
		errCh <- httpSrv.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}
}

// parseHome "41.01,28.97" ya da "TR" biçimini çözer.
func parseHome(v string) (*geo.Country, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	if lat, lon, ok := strings.Cut(v, ","); ok {
		la, err1 := strconv.ParseFloat(strings.TrimSpace(lat), 64)
		lo, err2 := strconv.ParseFloat(strings.TrimSpace(lon), 64)
		if err1 != nil || err2 != nil || la < -90 || la > 90 || lo < -180 || lo > 180 {
			return nil, errInvalidHome(v)
		}
		return &geo.Country{Name: "Merkez", Lat: la, Lon: lo}, nil
	}
	c, ok := geo.ByCode(strings.ToUpper(v))
	if !ok {
		return nil, errInvalidHome(v)
	}
	return &c, nil
}

type errInvalidHome string

func (e errInvalidHome) Error() string {
	return "geçersiz konum " + strconv.Quote(string(e)) + "; \"enlem,boylam\" ya da ülke kodu bekleniyor"
}
