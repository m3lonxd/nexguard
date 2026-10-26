package main

import (
	"context"
	"log"
	"sync"
	"time"
)

// pusher buffers failed panel pushes (findings/actions) in memory and
// retries them on a timer, since transport.PushFinding/PushAction already
// give up after a few quick retries and the panel may be down for longer
// than that (restart, deploy, network blip).
type pusher struct {
	mu      sync.Mutex
	pending []func() error
}

func newPusher() *pusher {
	return &pusher{}
}

func (p *pusher) push(fn func() error) {
	err := fn()
	if err == nil {
		return
	}
	log.Printf("agent: panel push failed, buffering for retry: %v", err)
	p.mu.Lock()
	p.pending = append(p.pending, fn)
	p.mu.Unlock()
}

func (p *pusher) retryLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.flush()
		}
	}
}

func (p *pusher) flush() {
	p.mu.Lock()
	items := p.pending
	p.pending = nil
	p.mu.Unlock()
	if len(items) == 0 {
		return
	}

	var stillPending []func() error
	for _, fn := range items {
		if err := fn(); err != nil {
			stillPending = append(stillPending, fn)
		}
	}
	if len(stillPending) == 0 {
		return
	}
	p.mu.Lock()
	p.pending = append(stillPending, p.pending...)
	p.mu.Unlock()
}
