package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nexguard/internal/api"
	"nexguard/internal/store"
	"nexguard/web"
)

func main() {
	addr := flag.String("addr", ":8842", "listen address")
	dbPath := flag.String("db", "./nexguard.db", "path to the SQLite database file")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file (enables HTTPS together with -tls-key)")
	tlsKey := flag.String("tls-key", "", "TLS key file (enables HTTPS together with -tls-cert)")
	flag.Parse()

	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("-tls-cert and -tls-key must be set together")
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	apiSrv := api.New(st)
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
