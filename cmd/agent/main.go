package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"nexguard/internal/collectors"
	"nexguard/internal/detectors"
	"nexguard/internal/honeypot"
	"nexguard/internal/responder"
	"nexguard/internal/transport"
)

const version = "0.2.0"

func main() {
	defaultConfigPath := ""
	if home, err := os.UserHomeDir(); err == nil {
		defaultConfigPath = filepath.Join(home, ".config", "nexguard", "agent.yaml")
	}

	enrollURL := flag.String("enroll", "", "panel URL to enroll with (e.g. http://localhost:8842); enrolls and exits")
	configPath := flag.String("config", defaultConfigPath, "path to agent config file")
	authlogPath := flag.String("authlog", "", "override path to tail instead of auto-detecting journalctl/auth.log (mainly for testing)")
	auditPath := flag.String("audit-log", "/var/log/nexguard/actions.jsonl", "path to the local JSON Lines action audit log")
	window := flag.Duration("window", detectors.DefaultWindow, "ssh bruteforce detection window")
	threshold := flag.Int("threshold", detectors.DefaultThreshold, "failed attempts within window to trigger a finding")
	ttl := flag.Duration("block-ttl", responder.DefaultTTL, "how long an automatic ip block stays in place")
	stateDir := flag.String("state-dir", "", "allowlist, honeypot ayarı ve honeypot host anahtarının dizini (varsayılan: config dizini)")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("agent: could not determine a default config path (no $HOME); pass -config explicitly")
	}

	if *enrollURL != "" {
		if err := runEnroll(*enrollURL, *configPath); err != nil {
			log.Fatalf("agent: enroll failed: %v", err)
		}
		log.Printf("agent: enrolled with %s, config written to %s", *enrollURL, *configPath)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("agent: load config (%s): %v -- run with -enroll <panel-url> first", *configPath, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	collector := &collectors.AuthLogCollector{FilePath: *authlogPath}
	events, err := collector.Start(ctx)
	if err != nil {
		log.Fatalf("agent: start collector: %v", err)
	}

	det := detectors.NewSSHBruteForce(*window, *threshold)
	resp := responder.NewBlockIP(responder.ExecRunner{}, *auditPath, *ttl)

	pending := newPusher()
	go pending.retryLoop(ctx, 30*time.Second)
	resp.Publish = func(a transport.ActionLog) {
		pending.push(func() error { return transport.PushAction(cfg.ServerURL, cfg.Token, a) })
	}

	dir := *stateDir
	if dir == "" {
		dir = filepath.Dir(*configPath)
	}
	state, err := openState(filepath.Join(dir, "state.yaml"))
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	statusCh := make(chan struct{}, 1)
	notify := func() {
		select {
		case statusCh <- struct{}{}:
		default:
		}
	}
	handle := func(f transport.Finding) {
		f.ServerID = cfg.ServerID
		log.Printf("agent: finding detected: %s (%s)", f.Summary, f.Severity)
		pending.push(func() error { return transport.PushFinding(cfg.ServerURL, cfg.Token, f) })
		if a, err := resp.Respond(f); err != nil {
			log.Printf("agent: responder error (finding %s): %v", f.ID, err)
		} else if a != nil {
			notify()
		}
	}
	prevPublish := resp.Publish
	resp.Publish = func(a transport.ActionLog) { prevPublish(a); notify() }

	reporter := honeypot.NewReporter(handle)
	hp := &honeypot.Manager{HostKeyPath: filepath.Join(dir, "honeypot_ed25519"), OnHit: reporter.Add}
	defer hp.Close()
	st := state.get()
	resp.SetAllow(st.Allow)
	applyAutoBlock(resp, st.Honeypot)
	if hs := hp.Apply(st.Honeypot); st.Honeypot.Enabled {
		log.Printf("agent: honeypot listening on %v errors=%v", hs.Listening, hs.Errors)
	}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				reporter.Flush()
			}
		}
	}()
	cmdr := &commander{resp: resp, hp: hp, state: state}
	go commandLoop(ctx, cfg, cmdr, statusCh)

	log.Printf("agent: running, server=%s window=%s threshold=%d", cfg.ServerURL, *window, *threshold)
	for ev := range events {
		if finding := det.Feed(ev); finding != nil {
			handle(*finding)
		}
	}
}

func runEnroll(panelURL, configPath string) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}
	serverID, token, err := transport.Enroll(panelURL, hostname, runtime.GOOS)
	if err != nil {
		return err
	}
	return saveConfig(configPath, Config{
		ServerURL: panelURL,
		ServerID:  serverID,
		Token:     token,
		Hostname:  hostname,
	})
}
